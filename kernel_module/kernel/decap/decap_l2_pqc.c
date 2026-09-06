#include "../mwan_steer.h"
#include "../mwan_state.h"
#include "../mwan_proto.h"
#include "../mwan_multicore.h"
#include "../mwan_mtu.h"

#include <linux/cpu.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/ktime.h>
#include <linux/netdevice.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <crypto/aead.h>
#include <net/ip.h>

static struct workqueue_struct *mwan_l2_wq;
static struct dentry *mwan_debugfs_dir;
#define MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS       10U
#define MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS     1000U

static DEFINE_SPINLOCK(mwan_l2_rx_diag_lock);
static u32 mwan_l2_rx_diag_flows[MWAN_L2_DIAG_MAX_FLOWS];
static unsigned int mwan_l2_rx_diag_count;
static u32 mwan_l2_rx_diag_bucket_flow[MWAN_FLOW_HASH_SIZE];
static bool mwan_l2_rx_diag_bucket_valid[MWAN_FLOW_HASH_SIZE];

static DEFINE_SPINLOCK(mwan_l2_work_diag_lock);
static u32 mwan_l2_work_diag_flows[MWAN_L2_DIAG_MAX_FLOWS];
static unsigned int mwan_l2_work_diag_count;
static atomic_t mwan_l2_diag_generation = ATOMIC_INIT(0);
static atomic64_t mwan_l2_rx_diag_flows_count;
static atomic64_t mwan_l2_rx_diag_zero;
static atomic64_t mwan_l2_rx_diag_collisions;
static atomic64_t mwan_l2_rx_diag_fid_mismatch;
static atomic64_t mwan_l2_rx_diag_seq_mismatch;
static atomic64_t mwan_l2_rx_diag_nonce_mismatch;
static atomic64_t mwan_l2_rx_diag_cb_corrupt;
static atomic64_t mwan_l2_rx_diag_decrypt_fail;
static atomic64_t mwan_l2_rx_diag_auth_fail;
static atomic64_t mwan_l2_rx_diag_cpu_flows[NR_CPUS];
static atomic64_t mwan_l2_diag_cookie;
u32 mwan_l2_diag_generation_get(void)
{
    return (u32)atomic_read(&mwan_l2_diag_generation);
}

void mwan_l2_diag_reset_all(void)
{
    struct mwan_config *cfg;
    int cpu;
    u32 generation;

    mwan_l2_tx_diag_reset();
    mwan_multicore_diag_reset();
    mwan_mtu_stats_reset(MWAN_MTU_PROFILE_BYPASS);
    mwan_mtu_stats_reset(MWAN_MTU_PROFILE_L2_PQC);

    spin_lock_bh(&mwan_l2_rx_diag_lock);
    memset(mwan_l2_rx_diag_flows, 0, sizeof(mwan_l2_rx_diag_flows));
    memset(mwan_l2_rx_diag_bucket_flow, 0,
           sizeof(mwan_l2_rx_diag_bucket_flow));
    memset(mwan_l2_rx_diag_bucket_valid, 0,
           sizeof(mwan_l2_rx_diag_bucket_valid));
    mwan_l2_rx_diag_count = 0;
    spin_unlock_bh(&mwan_l2_rx_diag_lock);

    spin_lock_bh(&mwan_l2_work_diag_lock);
    memset(mwan_l2_work_diag_flows, 0,
           sizeof(mwan_l2_work_diag_flows));
    mwan_l2_work_diag_count = 0;
    spin_unlock_bh(&mwan_l2_work_diag_lock);

    atomic64_set(&mwan_l2_rx_diag_flows_count, 0);
    atomic64_set(&mwan_l2_rx_diag_zero, 0);
    atomic64_set(&mwan_l2_rx_diag_collisions, 0);
    atomic64_set(&mwan_l2_rx_diag_fid_mismatch, 0);
    atomic64_set(&mwan_l2_rx_diag_seq_mismatch, 0);
    atomic64_set(&mwan_l2_rx_diag_nonce_mismatch, 0);
    atomic64_set(&mwan_l2_rx_diag_cb_corrupt, 0);
    atomic64_set(&mwan_l2_rx_diag_decrypt_fail, 0);
    atomic64_set(&mwan_l2_rx_diag_auth_fail, 0);
    atomic64_set(&mwan_l2_diag_cookie, 0);
    for (cpu = 0; cpu < NR_CPUS; cpu++)
        atomic64_set(&mwan_l2_rx_diag_cpu_flows[cpu], 0);

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg)
        mwan_rekey_diag_reset(cfg);
    rcu_read_unlock();

    generation = (u32)atomic_inc_return(&mwan_l2_diag_generation);
    pr_info("mwan_kmod: L2D RESET g=%u\n", generation);
}

static bool mwan_l2_diag_first_flow(u32 flow_id, u32 *flows,
                                    unsigned int *flow_count,
                                    spinlock_t *lock)
{
    unsigned int count;
    unsigned int limit;
    unsigned int i;
    bool first = false;

    if (!READ_ONCE(mwan_l2_diag_enabled))
        return false;

    limit = min_t(unsigned int, READ_ONCE(mwan_l2_diag_limit),
                  MWAN_L2_DIAG_MAX_FLOWS);
    spin_lock_bh(lock);
    count = *flow_count;
    for (i = 0; i < count; i++) {
        if (flows[i] == flow_id)
            goto out;
    }
    if (count < limit) {
        flows[count] = flow_id;
        *flow_count = count + 1;
        first = true;
    }
out:
    spin_unlock_bh(lock);
    return first;
}

static void mwan_atomic64_update_max(atomic64_t *maximum, u64 value)
{
    s64 old = atomic64_read(maximum);

    while (value > (u64)old) {
        s64 observed = atomic64_cmpxchg(maximum, old, (s64)value);

        if (observed == old)
            break;
        old = observed;
    }
}

static void mwan_l2_update_ewma(struct mwan_l2_worker *worker, u64 sample_ns)
{
    s64 old;
    s64 next;

    do {
        old = atomic64_read(&worker->processing_ewma_ns);
        next = old ? old - (old >> 3) + ((s64)sample_ns >> 3) : sample_ns;
    } while (atomic64_cmpxchg(&worker->processing_ewma_ns, old, next) != old);
}

static bool mwan_l2_schedule_rx_worker(struct mwan_l2_worker *worker)
{
    if (!mwan_l2_wq)
        return false;
    if (queue_work_on(worker->cpu, mwan_l2_wq, &worker->work))
        return true;
    if (work_busy(&worker->work))
        return true;
    return queue_work(mwan_l2_wq, &worker->work);
}

static int mwan_l2_enqueue_skb(struct mwan_config *cfg, struct sk_buff *skb,
                               struct mwan_l2_rx_flow *flow, u64 flow_token,
                               u32 flow_seq, u64 packet_nonce,
                               u32 rx_headlen, bool rx_nonlinear,
                               int ingress_cpu)
{
    struct mwan_l2_worker *worker;
    unsigned int accounted_bytes = skb->truesize;
    u32 diag_id = lower_32_bits(flow_token);
    int owner = flow->owner_worker;
    int was_scheduled;
    bool new_diag_flow;
    u32 generation = mwan_l2_diag_generation_get();
    u64 diag_cookie = 0;
    unsigned int queued_after;

    if (READ_ONCE(mwan_l2_diag_enabled))
        diag_cookie = (u64)atomic64_inc_return(&mwan_l2_diag_cookie);

    new_diag_flow = mwan_l2_diag_first_flow(diag_id, mwan_l2_rx_diag_flows,
                                            &mwan_l2_rx_diag_count,
                                            &mwan_l2_rx_diag_lock);
    if (READ_ONCE(mwan_l2_diag_enabled) && unlikely(diag_id == 0)) {
        atomic64_inc(&mwan_l2_rx_diag_zero);
        pr_info_ratelimited("mwan_kmod: L2D RX_ZERO_IN g=%u c=%llu token=%016llx/%u/%016llx head=%u nl=%u in=%d\n",
                            generation, diag_cookie, flow_token, flow_seq,
                            packet_nonce, rx_headlen, rx_nonlinear,
                            ingress_cpu);
    }
    if (new_diag_flow)
        atomic64_inc(&mwan_l2_rx_diag_flows_count);
    if (owner < 0 || owner >= cfg->num_workers ||
        !cpu_online(cfg->l2_workers[owner].cpu))
        return -ENODEV;

    worker = &cfg->l2_workers[owner];
    spin_lock(&worker->rx_queue.lock);
    if (worker->rx_queue.qlen >= MWAN_L2_QUEUE_MAX_PACKETS ||
        atomic64_read(&worker->queued_bytes) + accounted_bytes >
            MWAN_L2_QUEUE_MAX_BYTES) {
        spin_unlock(&worker->rx_queue.lock);
        atomic64_inc(&worker->dropped_packets);
        mwan_rekey_diag_count_drop(cfg, MWAN_REKEY_DROP_RX_QUEUE, 0);
        return -ENOSPC;
    }

    BUILD_BUG_ON(sizeof(struct mwan_l2_rx_cb) > sizeof(skb->cb));
    MWAN_L2_RX_CB(skb)->flow_ptr = (uintptr_t)flow;
    MWAN_L2_RX_CB(skb)->dispatch_flow_token = flow_token;
    MWAN_L2_RX_CB(skb)->accounted_bytes = accounted_bytes;
    MWAN_L2_RX_CB(skb)->dispatch_flow_seq = flow_seq;
    MWAN_L2_RX_CB(skb)->dispatch_nonce = packet_nonce;
    MWAN_L2_RX_CB(skb)->diag_cookie = diag_cookie;
    MWAN_L2_RX_CB(skb)->dispatch_headlen =
        min_t(u32, rx_headlen, U16_MAX);
    MWAN_L2_RX_CB(skb)->dispatch_flags =
        rx_nonlinear ? MWAN_L2_RX_CB_NONLINEAR : 0;
    MWAN_L2_RX_CB(skb)->diag_magic = MWAN_L2_RX_CB_MAGIC;
    MWAN_L2_RX_CB(skb)->diag_check =
        mwan_l2_rx_cb_checksum(MWAN_L2_RX_CB(skb));
    atomic_inc(&worker->crypto_key_pending[
        (u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT)]);
    __skb_queue_tail(&worker->rx_queue, skb);
    queued_after = worker->rx_queue.qlen;
    atomic64_inc(&worker->queued_packets);
    atomic64_add(accounted_bytes, &worker->queued_bytes);
    atomic64_inc(&worker->enqueued_packets);
    atomic_inc(&flow->pending_crypto);
    /* Change 0 -> 1 while holding the same queue lock used by the worker's
     * empty-queue handoff.  This makes queue ownership and scheduled state a
     * single transition instead of two independently visible operations. */
    was_scheduled = atomic_cmpxchg(&worker->scheduled, 0, 1);
    mwan_atomic64_update_max(&worker->max_queued_packets,
                             worker->rx_queue.qlen);
    mwan_atomic64_update_max(&worker->max_queued_bytes,
                             atomic64_read(&worker->queued_bytes));
    spin_unlock(&worker->rx_queue.lock);

    if (new_diag_flow) {
        if (worker->cpu >= 0 && worker->cpu < NR_CPUS)
            atomic64_inc(&mwan_l2_rx_diag_cpu_flows[worker->cpu]);
        pr_info("mwan_kmod: L2D RX g=%u c=%llu token=%016llx/%u/%016llx head=%u nl=%u in=%d owner=%d/%d q=%u\n",
                generation, diag_cookie, flow_token, flow_seq, packet_nonce,
                rx_headlen, rx_nonlinear, ingress_cpu, owner, worker->cpu,
                queued_after);
    }

    if (was_scheduled == 0 &&
        unlikely(!mwan_l2_schedule_rx_worker(worker)))
        atomic64_inc(&worker->schedule_failures);
    return 0;
}

static int l2_pqc_decrypt_skb(struct sk_buff *skb,
                              struct mwan_l2_worker *worker,
                              u64 *out_flow_token, u32 *out_flow_seq,
                              u64 *out_packet_nonce)
{
    u8 iv_buf[MWAN_RFC4106_IV_LEN];
    u64 packet_nonce;
    u64 flow_token;
    u32 flow_seq;
    __be64 flow_token_be, nonce_be;
    __be32 flow_seq_be;
    struct aead_request *req;
    struct crypto_aead *tfm;
    struct mwan_l2_pqc_hdr *l2_hdr;
    int ciphertext_len;
    int err;

    if (skb_is_nonlinear(skb) && unlikely(skb_linearize(skb)))
        return -ENOMEM;
    if (skb_cow(skb, 0))
        return -ENOMEM;
    if (skb->len < MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN)
        return -EINVAL;
    l2_hdr = (struct mwan_l2_pqc_hdr *)skb->data;
    memcpy(&flow_token_be, &l2_hdr->flow_token, sizeof(flow_token_be));
    memcpy(&flow_seq_be, &l2_hdr->flow_seq, sizeof(flow_seq_be));
    memcpy(&nonce_be, &l2_hdr->packet_nonce, sizeof(nonce_be));
    flow_token = be64_to_cpu(flow_token_be);
    flow_seq = be32_to_cpu(flow_seq_be);
    packet_nonce = be64_to_cpu(nonce_be);
    if (unlikely(packet_nonce == 0))
        return -EINVAL;

    if (out_flow_token)
        *out_flow_token = flow_token;
    if (out_flow_seq)
        *out_flow_seq = flow_seq;
    if (out_packet_nonce)
        *out_packet_nonce = packet_nonce;
    memcpy(iv_buf, &nonce_be, sizeof(nonce_be));

    ciphertext_len = skb->len - MWAN_L2_HDR_LEN;
    {
        struct scatterlist sg[MAX_SKB_FRAGS + 3];
        int nents;

        sg_init_table(sg, ARRAY_SIZE(sg));
        sg_set_buf(&sg[0], skb->data, MWAN_L2_HDR_LEN);
        nents = skb_to_sgvec(skb, &sg[1], MWAN_L2_HDR_LEN,
                             ciphertext_len);
        if (unlikely(nents < 0))
            return -EINVAL;

        err = mwan_l2_worker_rx_crypto_lock(
            worker, (u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT),
            &tfm, &req);
        if (unlikely(err))
            return err;

        aead_request_set_crypt(req, sg, sg, ciphertext_len, iv_buf);
        aead_request_set_ad(req, MWAN_L2_HDR_LEN);
        err = crypto_aead_decrypt(req);
        mwan_l2_worker_crypto_unlock(worker);
    }

    if (err) {
        pr_warn_ratelimited("mwan_kmod: L2 PQC RX decrypt FAILED (err=%d)\n",
                            err);
        return err;
    }

    if (unlikely(skb_cow(skb, ETH_HLEN)))
        return -ENOMEM;

    memmove(skb->data + MWAN_L2_HDR_LEN - ETH_HLEN,
            skb->data - ETH_HLEN, ETH_HLEN);
    skb_pull(skb, MWAN_L2_HDR_LEN);
    skb_trim(skb, skb->len - MWAN_GCM_TAG_LEN);

    skb_set_mac_header(skb, -ETH_HLEN);
    eth_hdr(skb)->h_proto = htons(ETH_P_IP);
    skb->protocol = htons(ETH_P_IP);
    skb_reset_network_header(skb);
    skb->ip_summed = CHECKSUM_NONE;
    skb->encapsulation = 0;

    /* The old hash describes the encrypted/outer frame.  Recompute it from
     * the restored inner tuple before reinjection. */
    skb_clear_hash(skb);
    skb_get_hash(skb);
    return 0;
}

static bool mwan_l2_decrypted_tcp_closing(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    int offset;

    if (!pskb_may_pull(skb, sizeof(*iph)))
        return false;
    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->ihl < 5 ||
        iph->protocol != IPPROTO_TCP)
        return false;
    offset = iph->ihl * 4;
    if (!pskb_may_pull(skb, offset + sizeof(*tcph)))
        return false;
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)iph + offset);
    return tcph->fin || tcph->rst;
}

/*
 * A successful enqueue transfers one RX-flow reference to the worker and
 * increments pending_crypto.  Normally both are recovered from skb->cb.  If
 * another layer corrupts cb, however, treating flow_ptr as a pointer would be
 * unsafe and simply dropping the skb would leak that queue-owned reference.
 *
 * The fixed L2-PQC prefix is not modified while the skb is private to this
 * queue and contains the same flow token used by the RX handler.  Resolve the
 * already-existing flow under its bucket lock and release the queue ownership
 * there, without ever dereferencing data obtained from the corrupt cb.
 */
static bool mwan_l2_release_corrupt_cb_flow(struct mwan_l2_worker *worker,
                                            const struct sk_buff *skb,
                                            u8 *accounted_key_id)
{
    struct mwan_l2_pqc_hdr l2_hdr_buf;
    const struct mwan_l2_pqc_hdr *l2_hdr;
    struct mwan_config *cfg = worker->cfg;
    __be64 flow_token_be;
    u64 flow_token;
    int owner;

    if (unlikely(!cfg || !cfg->l2_workers ||
                 skb->len < sizeof(l2_hdr_buf)))
        return false;

    l2_hdr = skb_header_pointer(skb, 0, sizeof(l2_hdr_buf), &l2_hdr_buf);
    if (unlikely(!l2_hdr))
        return false;
    memcpy(&flow_token_be, &l2_hdr->flow_token, sizeof(flow_token_be));
    flow_token = be64_to_cpu(flow_token_be);
    if (unlikely(!flow_token))
        return false;
    if (accounted_key_id)
        *accounted_key_id = (u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT);

    owner = (int)(worker - cfg->l2_workers);
    if (unlikely(owner < 0 || owner >= cfg->num_workers))
        return false;
    return mwan_l2_rx_flow_release_queued(cfg, flow_token, owner);
}

void mwan_l2_rx_worker_fn(struct work_struct *work)
{
    struct mwan_l2_worker *worker = container_of(work, struct mwan_l2_worker,
                                                 work);
    struct sk_buff *skb;
    unsigned int batch = 0;

    atomic64_inc(&worker->work_runs);
    atomic_set(&worker->busy, 1);
    for (;;) {
        while ((skb = skb_dequeue(&worker->rx_queue)) != NULL) {
            struct mwan_l2_rx_cb cb;
            struct mwan_l2_rx_flow *flow;
            unsigned int accounted_bytes = skb->truesize;
            u64 dispatch_flow_token;
            u32 dispatch_flow_seq;
            u64 dispatch_nonce;
            u64 diag_cookie;
            u32 dispatch_headlen;
            bool dispatch_nonlinear;
            bool cb_ok;
            u64 flow_token = 0;
            u32 flow_seq = 0;
            u64 packet_nonce = 0;
            u64 start_ns = ktime_get_ns();
            int ret;

            memcpy(&cb, MWAN_L2_RX_CB(skb), sizeof(cb));
            cb_ok = cb.diag_magic == MWAN_L2_RX_CB_MAGIC &&
                    cb.diag_check == mwan_l2_rx_cb_checksum(&cb) &&
                    cb.flow_ptr && cb.accounted_bytes == accounted_bytes &&
                    !(cb.dispatch_flags & ~MWAN_L2_RX_CB_NONLINEAR);

            /* skb->truesize is the value charged at enqueue and is outside
             * skb->cb.  It therefore remains safe accounting input even when
             * every byte of cb must be treated as untrusted. */
            atomic64_dec(&worker->queued_packets);
            atomic64_sub(accounted_bytes, &worker->queued_bytes);
            if (unlikely(!cb_ok)) {
                bool flow_released;
                u8 accounted_key_id = 0;

                flow_released = mwan_l2_release_corrupt_cb_flow(
                    worker, skb, &accounted_key_id);
                if (accounted_key_id)
                    atomic_dec(&worker->crypto_key_pending[
                        accounted_key_id]);
                atomic64_inc(&mwan_l2_rx_diag_cb_corrupt);
                atomic64_inc(&worker->processed_packets);
                atomic64_inc(&worker->dropped_packets);
                mwan_l2_update_ewma(worker, ktime_get_ns() - start_ns);
                pr_warn_ratelimited("mwan_kmod: L2 RX corrupt skb->cb; packet hard-dropped cpu=%d/%u flow_ref_released=%u\n",
                                    worker->cpu, raw_smp_processor_id(),
                                    flow_released);
                memset(skb->cb, 0, sizeof(skb->cb));
                kfree_skb(skb);
                if (++batch == 64) {
                    batch = 0;
                    cond_resched();
                }
                continue;
            }

            flow = (struct mwan_l2_rx_flow *)cb.flow_ptr;
            dispatch_flow_token = cb.dispatch_flow_token;
            dispatch_flow_seq = cb.dispatch_flow_seq;
            dispatch_nonce = cb.dispatch_nonce;
            diag_cookie = cb.diag_cookie;
            dispatch_headlen = cb.dispatch_headlen;
            dispatch_nonlinear =
                cb.dispatch_flags & MWAN_L2_RX_CB_NONLINEAR;
            ret = l2_pqc_decrypt_skb(skb, worker, &flow_token, &flow_seq,
                                     &packet_nonce);
            atomic_dec(&worker->crypto_key_pending[
                (u8)(dispatch_flow_token >> MWAN_FLOW_KEY_ID_SHIFT)]);
            mwan_l2_update_ewma(worker, ktime_get_ns() - start_ns);
            atomic64_inc(&worker->processed_packets);

            if (READ_ONCE(mwan_l2_diag_enabled)) {
                bool fid_ok = dispatch_flow_token == flow_token;
                bool seq_ok = dispatch_flow_seq == flow_seq;
                bool nonce_ok = dispatch_nonce == packet_nonce;
                bool first_work;
                u32 generation = mwan_l2_diag_generation_get();

                if (!fid_ok)
                    atomic64_inc(&mwan_l2_rx_diag_fid_mismatch);
                if (!seq_ok)
                    atomic64_inc(&mwan_l2_rx_diag_seq_mismatch);
                if (!nonce_ok)
                    atomic64_inc(&mwan_l2_rx_diag_nonce_mismatch);
                if (ret) {
                    atomic64_inc(&mwan_l2_rx_diag_decrypt_fail);
                    if (ret == -EBADMSG)
                        atomic64_inc(&mwan_l2_rx_diag_auth_fail);
                }

                first_work = mwan_l2_diag_first_flow(
                    lower_32_bits(dispatch_flow_token),
                    mwan_l2_work_diag_flows,
                    &mwan_l2_work_diag_count, &mwan_l2_work_diag_lock);
                if (unlikely(ret || !fid_ok || !seq_ok || !nonce_ok))
                    pr_info_ratelimited("mwan_kmod: L2D WORK_BAD g=%u c=%llu cb_ok=%u cb=%016llx/%u/%016llx hdr=%016llx/%u/%016llx rx_head=%u rx_nl=%u cpu=%d/%u token_ok=%u seq_ok=%u nonce_ok=%u decrypt_status=%s auth=%s err=%d\n",
                                        generation, diag_cookie,
                                        cb_ok,
                                        dispatch_flow_token,
                                        dispatch_flow_seq,
                                        dispatch_nonce, flow_token, flow_seq,
                                        packet_nonce, dispatch_headlen,
                                        dispatch_nonlinear,
                                        worker->cpu, raw_smp_processor_id(),
                                        fid_ok, seq_ok, nonce_ok,
                                        ret ? "fail" : "ok",
                                        ret == -EBADMSG ? "fail" :
                                        (ret ? "na" : "ok"), ret);
                else if (first_work)
                    pr_info("mwan_kmod: L2D WORK g=%u c=%llu hdr=%016llx/%u/%016llx cpu=%d/%u token_ok=1 seq_ok=1 auth=ok\n",
                            generation, diag_cookie, flow_token, flow_seq,
                            packet_nonce, worker->cpu,
                            raw_smp_processor_id());
            }

            memset(skb->cb, 0, sizeof(skb->cb));
            if (unlikely(ret < 0)) {
                u8 packet_key_id =
                    (u8)(dispatch_flow_token >> MWAN_FLOW_KEY_ID_SHIFT);

                if (ret == -ENOKEY)
                    mwan_rekey_diag_count_drop(
                        worker->cfg, MWAN_REKEY_DROP_RX_CRYPTO_NO_KEY,
                        packet_key_id);
                else if (ret == -EBADMSG)
                    mwan_rekey_diag_count_drop(
                        worker->cfg, MWAN_REKEY_DROP_RX_AUTH,
                        packet_key_id);
                else
                    mwan_rekey_diag_count_drop(
                        worker->cfg, MWAN_REKEY_DROP_RX_CRYPTO_OTHER,
                        packet_key_id);
                atomic64_inc(&worker->decrypt_failures);
                kfree_skb(skb);
            } else {
                /* At an RX bottleneck the inner TCP header is visible only
                 * after authentication.  Mark CE here; never guess packet
                 * class from unauthenticated ciphertext. */
                mwan_multicore_rx_congestion_feedback(worker, skb);
                mwan_l2_rx_flow_touch(flow,
                    mwan_l2_decrypted_tcp_closing(skb));
                mwan_l2_rx_flow_deliver(flow, skb, flow_seq);
            }

            if (flow) {
                atomic_dec(&flow->pending_crypto);
                mwan_l2_rx_flow_put(flow);
            }
            if (++batch == 64) {
                batch = 0;
                cond_resched();
            }
        }

        spin_lock_bh(&worker->rx_queue.lock);
        if (!skb_queue_empty(&worker->rx_queue)) {
            spin_unlock_bh(&worker->rx_queue.lock);
            continue;
        }
        atomic_set(&worker->scheduled, 0);
        spin_unlock_bh(&worker->rx_queue.lock);
        break;
    }
    atomic_set(&worker->busy, 0);
}

static int mwan_l2_stats_show(struct seq_file *m, void *unused)
{
    struct mwan_config *cfg;
    int i;

    (void)unused;
    seq_puts(m, "cpu rx_q_pkts rx_q_bytes rx_max_pkts rx_max_bytes rx_enqueued rx_processed rx_drops rx_decrypt_fail rx_owned rx_ewma_ns rx_runs rx_schedule_fail rx_busy tx_q_pkts tx_q_bytes tx_max_pkts tx_max_bytes tx_enqueued tx_processed tx_drops tx_xmit_fail tx_owned tx_ewma_ns tx_runs tx_schedule_fail tx_busy score sys_raw_bp sys_ewma_bp soft_raw_bp soft_ewma_bp idle_raw_bp idle_ewma_bp busy_raw_bp busy_ewma_bp blocked emergency tx_ecn_marked rx_ecn_marked overload_drop control_preserved emergency_hot emergency_cool emergency_enters emergency_last_ns overload_last_ns busy_peak_bp idle_min_bp\n");
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->l2_workers) {
        seq_puts(m, "L2-PQC workers are not active\n");
        rcu_read_unlock();
        return 0;
    }

    for (i = 0; i < cfg->num_workers; i++) {
        struct mwan_l2_worker *w = &cfg->l2_workers[i];

        seq_printf(m, "%d %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %d ",
                   w->cpu,
                   atomic64_read(&w->queued_packets),
                   atomic64_read(&w->queued_bytes),
                   atomic64_read(&w->max_queued_packets),
                   atomic64_read(&w->max_queued_bytes),
                   atomic64_read(&w->enqueued_packets),
                   atomic64_read(&w->processed_packets),
                   atomic64_read(&w->dropped_packets),
                   atomic64_read(&w->decrypt_failures),
                   atomic64_read(&w->assigned_flows),
                   atomic64_read(&w->processing_ewma_ns),
                   atomic64_read(&w->work_runs),
                   atomic64_read(&w->schedule_failures),
                   atomic_read(&w->busy));
        seq_printf(m, "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %d ",
                   atomic64_read(&w->tx_queued_packets),
                   atomic64_read(&w->tx_queued_bytes),
                   atomic64_read(&w->tx_max_queued_packets),
                   atomic64_read(&w->tx_max_queued_bytes),
                   atomic64_read(&w->tx_enqueued_packets),
                   atomic64_read(&w->tx_processed_packets),
                   atomic64_read(&w->tx_dropped_packets),
                   atomic64_read(&w->tx_xmit_failures),
                   atomic64_read(&w->tx_assigned_flows),
                   atomic64_read(&w->tx_processing_ewma_ns),
                   atomic64_read(&w->tx_work_runs),
                   atomic64_read(&w->tx_schedule_failures),
                   atomic_read(&w->tx_busy));
        seq_printf(m, "%llu %d %d %d %d %d %d %d %d %d %d %lld %lld %lld %lld ",
                   mwan_multicore_worker_score(w),
                   atomic_read(&w->system_raw_bp),
                   atomic_read(&w->system_ewma_bp),
                   atomic_read(&w->softirq_raw_bp),
                   atomic_read(&w->softirq_ewma_bp),
                   atomic_read(&w->idle_raw_bp),
                   atomic_read(&w->idle_ewma_bp),
                   atomic_read(&w->busy_raw_bp),
                   atomic_read(&w->busy_ewma_bp),
                   atomic_read(&w->admission_blocked),
                   atomic_read(&w->emergency_shed),
                   atomic64_read(&w->tx_ecn_marked),
                   atomic64_read(&w->rx_ecn_marked),
                   atomic64_read(&w->tx_overload_dropped),
                   atomic64_read(&w->tx_control_preserved));
        seq_printf(m, "%u %u %lld %lld %lld %d %d\n",
                   READ_ONCE(w->emergency_hot_samples),
                   READ_ONCE(w->emergency_cool_samples),
                   atomic64_read(&w->emergency_enter_count),
                   atomic64_read(&w->emergency_last_enter_ns),
                   atomic64_read(&w->overload_last_drop_ns),
                   atomic_read(&w->busy_peak_bp),
                   atomic_read(&w->idle_min_bp));
    }
    rcu_read_unlock();
    return 0;
}

static int mwan_l2_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, mwan_l2_stats_show, inode->i_private);
}

static const struct file_operations mwan_l2_stats_fops = {
    .owner = THIS_MODULE,
    .open = mwan_l2_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int mwan_l2_diag_show(struct seq_file *m, void *unused)
{
    struct mwan_mtu_stats_snapshot bypass_mtu;
    struct mwan_mtu_stats_snapshot l2_mtu;
    struct mwan_config *cfg;
    u64 pending_current = 0;
    u64 pending_previous = 0;
    u64 pending_next = 0;
    int phase;
    int reason;
    int cpu;

    (void)unused;
    seq_printf(m, "generation=%u enabled=%u limit=%u\n",
               mwan_l2_diag_generation_get(),
               READ_ONCE(mwan_l2_diag_enabled),
               min_t(unsigned int, READ_ONCE(mwan_l2_diag_limit),
                     MWAN_L2_DIAG_MAX_FLOWS));
    seq_printf(m, "tx_flows=%llu tx_zero_packets=%llu\n",
               mwan_l2_tx_diag_flows_get(), mwan_l2_tx_diag_zero_get());
    seq_printf(m, "rx_flows=%lld rx_zero_packets=%lld collisions=%lld\n",
               atomic64_read(&mwan_l2_rx_diag_flows_count),
               atomic64_read(&mwan_l2_rx_diag_zero),
               atomic64_read(&mwan_l2_rx_diag_collisions));
    seq_printf(m, "fid_mismatch=%lld seq_mismatch=%lld nonce_mismatch=%lld cb_corrupt=%lld\n",
               atomic64_read(&mwan_l2_rx_diag_fid_mismatch),
               atomic64_read(&mwan_l2_rx_diag_seq_mismatch),
               atomic64_read(&mwan_l2_rx_diag_nonce_mismatch),
               atomic64_read(&mwan_l2_rx_diag_cb_corrupt));
    seq_printf(m, "decrypt_fail=%lld auth_fail=%lld\n",
               atomic64_read(&mwan_l2_rx_diag_decrypt_fail),
               atomic64_read(&mwan_l2_rx_diag_auth_fail));
    mwan_mtu_stats_get(MWAN_MTU_PROFILE_BYPASS, &bypass_mtu);
    mwan_mtu_stats_get(MWAN_MTU_PROFILE_L2_PQC, &l2_mtu);
    seq_printf(m, "mtu_bypass fits=%llu gso=%llu oversize=%llu invalid=%llu icmp_attempted=%llu\n",
               bypass_mtu.fits, bypass_mtu.needs_segment,
               bypass_mtu.oversize, bypass_mtu.invalid,
               bypass_mtu.frag_needed_attempted);
    seq_printf(m, "mtu_l2_pqc fits=%llu gso=%llu oversize=%llu invalid=%llu icmp_attempted=%llu\n",
               l2_mtu.fits, l2_mtu.needs_segment, l2_mtu.oversize,
               l2_mtu.invalid, l2_mtu.frag_needed_attempted);
    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg) {
        seq_printf(m, "flow_table key_id=%u prev_key_id=%u prev_valid=%u tx_active=%d rx_active=%d tx_created=%lld tx_expired=%lld rx_created=%lld rx_expired=%lld full=%lld\n",
                   cfg->key_id, cfg->prev_key_id, cfg->prev_key_valid,
                   atomic_read(&cfg->flows.tx_count),
                   atomic_read(&cfg->flows.rx_count),
                   atomic64_read(&cfg->flows.tx_created),
                   atomic64_read(&cfg->flows.tx_expired),
                   atomic64_read(&cfg->flows.rx_created),
                   atomic64_read(&cfg->flows.rx_expired),
                   atomic64_read(&cfg->flows.table_full));
        seq_printf(m, "reorder late=%lld duplicate=%lld too_far=%lld skipped_on_timeout=%lld resync=%lld resync_skipped=%lld resync_flushed=%lld\n",
                   atomic64_read(&cfg->flows.reorder_late),
                   atomic64_read(&cfg->flows.reorder_duplicate),
                   atomic64_read(&cfg->flows.reorder_too_far),
                   atomic64_read(&cfg->flows.reorder_timeouts),
                   atomic64_read(&cfg->flows.reorder_resync),
                   atomic64_read(&cfg->flows.reorder_resync_skipped),
                   atomic64_read(&cfg->flows.reorder_resync_flushed));
        if (cfg->l2_workers) {
            int i;

            for (i = 0; i < cfg->num_workers; i++) {
                struct mwan_l2_worker *worker = &cfg->l2_workers[i];

                if (cfg->key_id)
                    pending_current += (u64)max_t(
                        int, atomic_read(&worker->crypto_key_pending[
                            cfg->key_id]), 0);
                if (cfg->prev_key_id)
                    pending_previous += (u64)max_t(
                        int, atomic_read(&worker->crypto_key_pending[
                            cfg->prev_key_id]), 0);
                if (cfg->next_key_id)
                    pending_next += (u64)max_t(
                        int, atomic_read(&worker->crypto_key_pending[
                            cfg->next_key_id]), 0);
            }
        }
        phase = atomic_read(&cfg->rekey_diag.phase);
        seq_printf(m, "rekey_diag event_seq=%lld epoch=%llu phase=%s key_state=%u keys=%u/%u/%u valid=%u/%u pending=%llu/%llu/%llu prev_reject_retire=%lld\n",
                   atomic64_read(&cfg->rekey_diag.event_seq),
                   cfg->rekey_epoch,
                   mwan_rekey_diag_phase_name(phase), cfg->key_state,
                   cfg->key_id, cfg->prev_key_id, cfg->next_key_id,
                   cfg->prev_key_valid, cfg->next_key_valid,
                   pending_current, pending_previous, pending_next,
                   atomic64_read(
                       &cfg->rekey_diag.prev_rejected_while_retiring));
        seq_puts(m, "rekey_drop_phase:");
        for (phase = 0; phase < MWAN_REKEY_DIAG_PHASE_MAX; phase++)
            seq_printf(m, " %s=%lld",
                       mwan_rekey_diag_phase_name(phase),
                       atomic64_read(
                           &cfg->rekey_diag.drop_by_phase[phase]));
        seq_putc(m, '\n');
        seq_puts(m, "rekey_drop_reason:");
        for (reason = 0; reason < MWAN_REKEY_DROP_REASON_MAX; reason++)
            seq_printf(m, " %s=%lld",
                       mwan_rekey_drop_reason_name(reason),
                       atomic64_read(
                           &cfg->rekey_diag.drop_by_reason[reason]));
        seq_putc(m, '\n');
    }
    rcu_read_unlock();
    seq_printf(m, "cpu_high=%u recover_load=%u idle_unblock=%u emergency=%u max_shed=%u sample_ms=%u admitted=%llu no_eligible=%llu\n",
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_high_pct), 1U, 100U),
               min_t(unsigned int, READ_ONCE(mwan_l2_softirq_low_pct),
                     clamp_t(unsigned int,
                             READ_ONCE(mwan_l2_softirq_high_pct),
                             1U, 100U) - 1U),
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_idle_unblock_pct), 1U, 99U),
               clamp_t(unsigned int, READ_ONCE(mwan_l2_emergency_pct),
                       clamp_t(unsigned int,
                               READ_ONCE(mwan_l2_softirq_high_pct),
                               1U, 100U), 100U),
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_max_shed_pct), 1U, 100U),
               clamp_t(unsigned int,
                       READ_ONCE(mwan_l2_softirq_sample_ms),
                       MWAN_L2_SOFTIRQ_MIN_SAMPLE_MS,
                       MWAN_L2_SOFTIRQ_MAX_SAMPLE_MS),
               mwan_multicore_admitted_get(),
               mwan_multicore_no_eligible_get());
    seq_puts(m, "cpu_flows:");
    cpus_read_lock();
    for_each_online_cpu(cpu)
        seq_printf(m, " %d=%lld", cpu,
                   atomic64_read(&mwan_l2_rx_diag_cpu_flows[cpu]));
    cpus_read_unlock();
    seq_putc(m, '\n');
    return 0;
}

static int mwan_l2_diag_open(struct inode *inode, struct file *file)
{
    return single_open(file, mwan_l2_diag_show, inode->i_private);
}

static const struct file_operations mwan_l2_diag_fops = {
    .owner = THIS_MODULE,
    .open = mwan_l2_diag_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int l2_pqc_rx_handler(struct sk_buff *skb, struct net_device *dev,
                             struct packet_type *pt,
                             struct net_device *orig_dev)
{
    struct mwan_l2_pqc_hdr l2_hdr_buf;
    const struct mwan_l2_pqc_hdr *l2_hdr;
    struct mwan_config *cfg;
    struct mwan_l2_rx_flow *flow;
    __be64 flow_token_be, nonce_be;
    __be32 flow_seq_be;
    u64 flow_token;
    u32 flow_seq;
    u64 packet_nonce;
    u8 packet_key_id;
    u32 rx_headlen;
    bool rx_nonlinear;
    int ingress_cpu;
    int ret;

    (void)dev;
    (void)pt;
    (void)orig_dev;
    if (!skb)
        return NET_RX_DROP;
    if (skb->len < MWAN_L2_HDR_LEN + MWAN_GCM_TAG_LEN) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    /* A packet_type handler may receive a fully non-linear skb with
     * skb_headlen(skb) == 0. Read only the authenticated 20-byte prefix here;
     * skb_header_pointer() returns skb->data on the linear fast path and
     * copies just the prefix into l2_hdr_buf otherwise. The selected worker
     * remains responsible for linearizing the encrypted payload. */
    l2_hdr = skb_header_pointer(skb, 0, sizeof(l2_hdr_buf), &l2_hdr_buf);
    if (unlikely(!l2_hdr)) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    memcpy(&flow_token_be, &l2_hdr->flow_token, sizeof(flow_token_be));
    memcpy(&flow_seq_be, &l2_hdr->flow_seq, sizeof(flow_seq_be));
    memcpy(&nonce_be, &l2_hdr->packet_nonce, sizeof(nonce_be));
    flow_token = be64_to_cpu(flow_token_be);
    packet_key_id = (u8)(flow_token >> MWAN_FLOW_KEY_ID_SHIFT);
    flow_seq = be32_to_cpu(flow_seq_be);
    packet_nonce = be64_to_cpu(nonce_be);
    rx_headlen = skb_headlen(skb);
    rx_nonlinear = skb_is_nonlinear(skb);
    ingress_cpu = raw_smp_processor_id();

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (!cfg || !cfg->encrypt_on || !cfg->l2_workers) {
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    if (packet_key_id != cfg->key_id &&
        (!cfg->prev_key_valid ||
         packet_key_id != cfg->prev_key_id) &&
        (!cfg->next_key_valid ||
         packet_key_id != cfg->next_key_id)) {
        mwan_rekey_diag_count_drop(cfg, MWAN_REKEY_DROP_RX_KEY_REJECT,
                                   packet_key_id);
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    flow = mwan_l2_rx_flow_get(cfg, flow_token, flow_seq);
    if (!flow) {
        mwan_rekey_diag_count_drop(cfg, MWAN_REKEY_DROP_RX_FLOW,
                                   packet_key_id);
        rcu_read_unlock();
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    ret = mwan_l2_enqueue_skb(cfg, skb, flow, flow_token, flow_seq,
                              packet_nonce,
                              rx_headlen, rx_nonlinear, ingress_cpu);
    rcu_read_unlock();
    if (unlikely(ret < 0)) {
        mwan_l2_rx_flow_put(flow);
        kfree_skb(skb);
        return NET_RX_DROP;
    }
    return NET_RX_SUCCESS;
}

static struct packet_type l2_pqc_packet_type __read_mostly = {
    .type = cpu_to_be16(MWAN_L2_PQC_ETHERTYPE),
    .func = l2_pqc_rx_handler,
};

int mwan_decap_l2_pqc_init(void)
{
    mwan_l2_diag_reset_all();
    mwan_l2_wq = alloc_workqueue("mwan_l2rx",
                                 WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1);
    if (!mwan_l2_wq)
        return -ENOMEM;
    if (mwan_multicore_init()) {
        destroy_workqueue(mwan_l2_wq);
        mwan_l2_wq = NULL;
        return -ENOMEM;
    }

    mwan_debugfs_dir = debugfs_create_dir("mwan_kmod", NULL);
    if (IS_ERR_OR_NULL(mwan_debugfs_dir)) {
        pr_warn("mwan_kmod: debugfs is unavailable; L2 stats disabled\n");
        mwan_debugfs_dir = NULL;
    } else {
        debugfs_create_file("l2_workers", 0444, mwan_debugfs_dir, NULL,
                            &mwan_l2_stats_fops);
        debugfs_create_file("l2_diag", 0444, mwan_debugfs_dir, NULL,
                            &mwan_l2_diag_fops);
    }
    dev_add_pack(&l2_pqc_packet_type);
    pr_info("mwan_kmod: registered L2-PQC RX and shared multicore TX (0x%04x)\n",
            MWAN_L2_PQC_ETHERTYPE);
    return 0;
}

void mwan_decap_l2_pqc_cleanup(void)
{
    dev_remove_pack(&l2_pqc_packet_type);
    debugfs_remove_recursive(mwan_debugfs_dir);
    mwan_debugfs_dir = NULL;
    if (mwan_l2_wq) {
        destroy_workqueue(mwan_l2_wq);
        mwan_l2_wq = NULL;
    }
    mwan_multicore_cleanup();
    pr_info("mwan_kmod: unregistered L2-PQC packet handler\n");
}
