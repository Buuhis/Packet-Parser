#include "../../inc/interface.h"
#include <poll.h>
#include <sched.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if.h>

static int config_map_fds[MAX_INTERFACES]; 
static int config_map_fd_count = 0;

void interface_reset_redirect_maps(void) {
    config_map_fd_count = 0;
}

static void register_config_map_fd(int fd) {
    if (fd < 0)
        return;
    for (int i = 0; i < config_map_fd_count; i++) {
        if (config_map_fds[i] == fd)
            return;
    }
    if (config_map_fd_count < MAX_INTERFACES)
        config_map_fds[config_map_fd_count++] = fd;
}


static void interface_xdp_try_detach(int ifindex, const char *ifname) {
    static const int modes[] = {
        XDP_FLAGS_SKB_MODE,
        XDP_FLAGS_DRV_MODE,
        XDP_FLAGS_HW_MODE,
    };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        int r = bpf_xdp_detach(ifindex, modes[i], NULL);
        if (r < 0) {
            int e = -r;
            if (e != EINVAL && e != EOPNOTSUPP && e != ENODEV && e != ENOENT && ifname)
                fprintf(stderr, "[XDP] %s: detach flags=0x%x ret=%d (%s)\n",
                        ifname, (unsigned)modes[i], r, strerror(e));
        }
    }
}

int interface_push_redirect_cfg(const struct redirect_cfg *rcfg)
{
    if (!rcfg || config_map_fd_count <= 0)
        return -1;
    __u32 key = 0;
    int ok = 0;
    for (int i = 0; i < config_map_fd_count; i++) {
        if (bpf_map_update_elem(config_map_fds[i], &key, rcfg, 0) == 0)
            ok = 1;
    }
    return ok ? 0 : -1;
}

static int get_rx_queue_count(const char *ifname) {
    struct ethtool_channels channels = {0};
    struct ifreq ifr = {0};
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 1;

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);
    channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void *)&channels;

    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    close(fd);

    if (ret < 0)
        return 1;

    int count = channels.combined_count;
    if (count == 0)
        count = channels.rx_count;
    if (count == 0)
        count = 1;

    return count > MAX_QUEUES ? MAX_QUEUES : count;
}

int interface_get_queue_count(const char *ifname) {
    return get_rx_queue_count(ifname);
}


static int effective_xsk_queue_count(const char *ifname, int cfg_q) {
    int hw = get_rx_queue_count(ifname);
    if (hw < 1)
        hw = 1;
    if (cfg_q <= 0)
        return hw > MAX_QUEUES ? MAX_QUEUES : hw;
    if (cfg_q > MAX_QUEUES)
        cfg_q = MAX_QUEUES;
    return cfg_q < hw ? cfg_q : hw;
}

int interface_set_queue_count(const char *ifname, int desired_count) {
    struct ethtool_channels channels = {0};
    struct ifreq ifr = {0};
    int fd, ret;

    if (desired_count < 1)
        desired_count = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);
    channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void *)&channels;

    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret < 0) {
        close(fd);
        fprintf(stderr, "[QUEUE] %s: cannot read channels (ethtool not supported)\n", ifname);
        return -1;
    }

    int max_combined = channels.max_combined;
    int max_rx = channels.max_rx;
    int current = channels.combined_count ? channels.combined_count : channels.rx_count;

    if (max_combined > 0) {
        int target = desired_count > max_combined ? max_combined : desired_count;
        if (target == (int)channels.combined_count) {
            close(fd);
            return target;
        }
        channels.cmd = ETHTOOL_SCHANNELS;
        channels.combined_count = target;
        channels.rx_count = 0;
        channels.tx_count = 0;
        ifr.ifr_data = (void *)&channels;
        ret = ioctl(fd, SIOCETHTOOL, &ifr);
        close(fd);
        if (ret < 0) {
            fprintf(stderr, "[QUEUE] %s: failed to set %d combined channels (max=%d, current=%d): %s\n",
                    ifname, target, max_combined, current, strerror(errno));
            return current > 0 ? current : 1;
        }
        return target;
    } 
    
    else if (max_rx > 0) {
        int target = desired_count > max_rx ? max_rx : desired_count;
        if (target == (int)channels.rx_count) {
            close(fd);
            return target;
        }
        channels.cmd = ETHTOOL_SCHANNELS;
        channels.rx_count = target;
        ifr.ifr_data = (void *)&channels;
        ret = ioctl(fd, SIOCETHTOOL, &ifr);
        close(fd);
        if (ret < 0) {
            fprintf(stderr, "[QUEUE] %s: failed to set %d rx channels (max=%d): %s\n",
                    ifname, target, max_rx, strerror(errno));
            return current > 0 ? current : 1;
        }
        return target;
    }

    close(fd);
    fprintf(stderr, "[QUEUE] %s: NIC does not support multi-queue\n", ifname);
    return 1;
}

int interface_init_local(struct xsk_interface *iface,
                         const struct local_config *local_cfg,
                         const char *bpf_file) {
    int ret;
    struct bpf_object *bpf_obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, xsk_map_fd = -1;

    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(local_cfg->ifname);
    strncpy(iface->ifname, local_cfg->ifname, IF_NAMESIZE - 1);
    iface->ifname[IF_NAMESIZE - 1] = '\0';
    memcpy(iface->src_mac, local_cfg->src_mac, MAC_LEN);
    memcpy(iface->dst_mac, local_cfg->dst_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", local_cfg->ifname);
        return -1;
    }

    int queue_count = effective_xsk_queue_count(local_cfg->ifname, local_cfg->queue_count);

    interface_xdp_try_detach(iface->ifindex, iface->ifname);

    if (access(bpf_file, F_OK) != 0) {
        fprintf(stderr, "XDP object not found: %s\n", bpf_file);
        return -1;
    }

    bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Failed to open %s\n", bpf_file);
        bpf_obj = NULL;
        return -1;
    }

    ret = bpf_object__load(bpf_obj);
    if (ret) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
        return -1;
    }

    prog = bpf_object__find_program_by_name(bpf_obj, "xdp_redirect_prog");
    if (!prog) {
        fprintf(stderr, "XDP program not found\n");
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    if (!map) {
        fprintf(stderr, "xsks_map not found\n");
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
        return -1;
    }
    xsk_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(bpf_obj, "config_map");
    if (map)
        register_config_map_fd(bpf_map__fd(map));

    size_t local_umem_size = (size_t)local_cfg->umem_mb * 1024 * 1024;
    iface->umem_size = local_umem_size;
    iface->ring_size = local_cfg->ring_size;
    iface->frame_size = local_cfg->frame_size;
    iface->batch_size = local_cfg->batch_size;

    struct xsk_umem_config umem_cfg = {
        .fill_size = local_cfg->ring_size,
        .comp_size = local_cfg->ring_size,
        .frame_size = local_cfg->frame_size,
        .frame_headroom = 0,
        .flags = 0
    };

    struct xsk_socket_config sock_cfg = {
        .rx_size = local_cfg->ring_size,
        .tx_size = local_cfg->ring_size,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    for (int q = 0; q < queue_count; q++) {
        struct xsk_queue *queue = &iface->queues[q];
        uint32_t idx;

        ret = posix_memalign(&queue->bufs, getpagesize(), local_umem_size);
        if (ret || !queue->bufs) {
            fprintf(stderr, "Queue %d: posix_memalign failed\n", q);
            goto err_queues;
        }
        mlock(queue->bufs, local_umem_size);

        ret = xsk_umem__create(&queue->umem, queue->bufs, local_umem_size,
                               &queue->fill, &queue->comp, &umem_cfg);
        if (ret) {
            fprintf(stderr, "Queue %d: xsk_umem__create failed: %d\n", q, ret);
            munlock(queue->bufs, local_umem_size);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        ret = xsk_socket__create(&queue->xsk, iface->ifname, q, queue->umem,
                                 &queue->rx, &queue->tx, &sock_cfg);
        if (ret) {
            fprintf(stderr, "Queue %d: xsk_socket__create failed: %d (%s)\n", q, ret,
                    ret < 0 ? strerror(-ret) : "non-negative error");
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, local_umem_size);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        int fd = xsk_socket__fd(queue->xsk);
        ret = bpf_map_update_elem(xsk_map_fd, &q, &fd, 0);
        if (ret) {
            fprintf(stderr, "Queue %d: bpf_map_update_elem failed\n", q);
            xsk_socket__delete(queue->xsk);
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, local_umem_size);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        ret = xsk_ring_prod__reserve(&queue->fill, local_cfg->ring_size, &idx);
        if (ret != (int)local_cfg->ring_size) {
            fprintf(stderr, "Queue %d: fill reserve got %d, expected %d\n", q, ret, local_cfg->ring_size);
        }
        for (int i = 0; i < ret; i++)
            *xsk_ring_prod__fill_addr(&queue->fill, idx++) = i * local_cfg->frame_size;
        xsk_ring_prod__submit(&queue->fill, ret);

        queue->tx_slot = 0;
        queue->pending_tx_count = 0;
        pthread_mutex_init(&queue->tx_lock, NULL);

        iface->queue_count++;
    }

    prog = bpf_object__find_program_by_name(bpf_obj, "xdp_redirect_prog");
    prog_fd = bpf_program__fd(prog);
    ret = bpf_xdp_attach(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (ret) {
        fprintf(stderr, "bpf_set_link_xdp_fd failed: %d (%s)\n", ret,
                ret < 0 ? strerror(-ret) : "non-negative");
        goto err_queues;
    }

    iface->pending_tx_count = 0;
    pthread_mutex_init(&iface->tx_lock, NULL);

    return 0;

err_queues:
    for (int j = 0; j < iface->queue_count; j++) {
        struct xsk_queue *queue = &iface->queues[j];
        if (queue->xsk) xsk_socket__delete(queue->xsk);
        if (queue->umem) xsk_umem__delete(queue->umem);
        if (queue->bufs) {
            munlock(queue->bufs, iface->umem_size);
            free(queue->bufs);
        }
    }
    interface_xdp_try_detach(iface->ifindex, iface->ifname);
    if (bpf_obj)
        bpf_object__close(bpf_obj);
    return -1;
}

int interface_init_wan(struct xsk_interface *iface,
                       const struct wan_config *wan_cfg) {
    int ret;
    uint32_t idx = 0;

    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(wan_cfg->ifname);
    strncpy(iface->ifname, wan_cfg->ifname, IF_NAMESIZE - 1);
    iface->ifname[IF_NAMESIZE - 1] = '\0';
    memcpy(iface->src_mac, wan_cfg->src_mac, MAC_LEN);
    memcpy(iface->dst_mac, wan_cfg->dst_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", wan_cfg->ifname);
        return -1;
    }

    size_t wan_umem_size = (size_t)wan_cfg->umem_mb * 1024 * 1024;
    iface->umem_size = wan_umem_size;
    iface->ring_size = wan_cfg->ring_size;
    iface->frame_size = wan_cfg->frame_size;
    iface->batch_size = wan_cfg->batch_size;

    ret = posix_memalign(&iface->bufs, getpagesize(), wan_umem_size);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    mlock(iface->bufs, wan_umem_size);

    ret = xsk_umem__create(&iface->umem, iface->bufs, wan_umem_size,
                           &iface->fill, &iface->comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    struct xsk_socket_config sock_cfg = {
        .rx_size = wan_cfg->ring_size,
        .tx_size = wan_cfg->ring_size,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&iface->xsk, iface->ifname, 0, iface->umem,
                             &iface->rx, &iface->tx, &sock_cfg);
    if (ret) {
        perror("xsk_socket__create WAN");
        xsk_umem__delete(iface->umem);
        free(iface->bufs);
        return -1;
    }

    ret = xsk_ring_prod__reserve(&iface->fill, wan_cfg->ring_size, &idx);
    if (ret != (int)wan_cfg->ring_size) {
        fprintf(stderr, "xsk_ring_prod__reserve WAN fill failed: ret=%d expected=%u\n",
                ret, wan_cfg->ring_size);
        xsk_socket__delete(iface->xsk);
        xsk_umem__delete(iface->umem);
        free(iface->bufs);
        return -1;
    }
    for (uint32_t i = 0; i < wan_cfg->ring_size; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx++) = i * wan_cfg->frame_size;
    xsk_ring_prod__submit(&iface->fill, wan_cfg->ring_size);

    iface->tx_slot = 0;

    return 0;
}

int interface_init_wan_rx(struct xsk_interface *iface,
                          const struct wan_config *wan_cfg,
                          const char *bpf_file,
                          uint16_t fake_ethertype_ipv4,
                          uint16_t fake_ethertype_ipv6) {
    int ret;
    struct bpf_object *wan_bpf_obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, wan_xsk_map_fd;

    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(wan_cfg->ifname);
    strncpy(iface->ifname, wan_cfg->ifname, IF_NAMESIZE - 1);
    iface->ifname[IF_NAMESIZE - 1] = '\0';
    memcpy(iface->src_mac, wan_cfg->src_mac, MAC_LEN);
    memcpy(iface->dst_mac, wan_cfg->dst_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "WAN Interface %s not found\n", wan_cfg->ifname);
        return -1;
    }

    int queue_count = effective_xsk_queue_count(wan_cfg->ifname, wan_cfg->queue_count);

    interface_xdp_try_detach(iface->ifindex, iface->ifname);

    if (access(bpf_file, F_OK) != 0) {
        fprintf(stderr, "WAN XDP object not found: %s\n", bpf_file);
        return -1;
    }

    wan_bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(wan_bpf_obj)) {
        fprintf(stderr, "Failed to open WAN BPF: %s\n", bpf_file);
        return -1;
    }

    ret = bpf_object__load(wan_bpf_obj);
    if (ret) {
        fprintf(stderr, "Failed to load WAN BPF object\n");
        bpf_object__close(wan_bpf_obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(wan_bpf_obj, "xdp_wan_redirect_prog");
    if (!prog) {
        fprintf(stderr, "WAN XDP program not found\n");
        bpf_object__close(wan_bpf_obj);
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    map = bpf_object__find_map_by_name(wan_bpf_obj, "wan_xsks_map");
    if (!map) {
        fprintf(stderr, "wan_xsks_map not found\n");
        bpf_object__close(wan_bpf_obj);
        return -1;
    }
    wan_xsk_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(wan_bpf_obj, "wan_config_map");
    if (map) {
        int cfg_fd = bpf_map__fd(map);
        int key0 = 0, key1 = 1;
        uint16_t fake4_net = htons(fake_ethertype_ipv4);
        uint16_t fake6_net = htons(fake_ethertype_ipv6);
        bpf_map_update_elem(cfg_fd, &key0, &fake4_net, 0);
        bpf_map_update_elem(cfg_fd, &key1, &fake6_net, 0);
    }

    size_t wan_umem_size = (size_t)wan_cfg->umem_mb * 1024 * 1024;
    iface->umem_size = wan_umem_size;
    iface->ring_size = wan_cfg->ring_size;
    iface->frame_size = wan_cfg->frame_size;
    iface->batch_size = wan_cfg->batch_size;

    struct xsk_umem_config umem_cfg = {
        .fill_size = wan_cfg->ring_size,
        .comp_size = wan_cfg->ring_size,
        .frame_size = wan_cfg->frame_size,
        .frame_headroom = 0,
        .flags = 0
    };

    struct xsk_socket_config sock_cfg = {
        .rx_size = wan_cfg->ring_size,
        .tx_size = wan_cfg->ring_size,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    for (int q = 0; q < queue_count; q++) {
        struct xsk_queue *queue = &iface->queues[q];
        uint32_t idx;

        ret = posix_memalign(&queue->bufs, getpagesize(), wan_umem_size);
        if (ret || !queue->bufs) {
            fprintf(stderr, "WAN Queue %d: posix_memalign failed\n", q);
            goto err_queues;
        }
        mlock(queue->bufs, wan_umem_size);

        ret = xsk_umem__create(&queue->umem, queue->bufs, wan_umem_size,
                               &queue->fill, &queue->comp, &umem_cfg);
        if (ret) {
            fprintf(stderr, "WAN Queue %d: xsk_umem__create failed: %d\n", q, ret);
            munlock(queue->bufs, wan_umem_size);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        ret = xsk_socket__create(&queue->xsk, iface->ifname, q, queue->umem,
                                 &queue->rx, &queue->tx, &sock_cfg);
        if (ret) {
            fprintf(stderr, "WAN Queue %d: xsk_socket__create failed: %d (%s)\n", q, ret,
                    ret < 0 ? strerror(-ret) : "non-negative error");
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, wan_umem_size);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        int fd = xsk_socket__fd(queue->xsk);
        ret = bpf_map_update_elem(wan_xsk_map_fd, &q, &fd, 0);
        if (ret) {
            fprintf(stderr, "WAN Queue %d: bpf_map_update_elem failed\n", q);
            xsk_socket__delete(queue->xsk);
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, wan_umem_size);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        ret = xsk_ring_prod__reserve(&queue->fill, wan_cfg->ring_size, &idx);
        if (ret != (int)wan_cfg->ring_size) {
            fprintf(stderr, "WAN Queue %d: fill reserve got %d\n", q, ret);
        }
        for (int i = 0; i < ret; i++)
            *xsk_ring_prod__fill_addr(&queue->fill, idx++) = i * wan_cfg->frame_size;
        xsk_ring_prod__submit(&queue->fill, ret);

        queue->tx_slot = 0;
        queue->pending_tx_count = 0;
        pthread_mutex_init(&queue->tx_lock, NULL);

        iface->queue_count++;
    }

    ret = bpf_xdp_attach(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (ret) {
        fprintf(stderr, "WAN bpf_set_link_xdp_fd failed: %d\n", ret);
        goto err_queues;
    }

    iface->xsk = iface->queues[0].xsk;
    iface->tx = iface->queues[0].tx;
    iface->comp = iface->queues[0].comp;
    iface->bufs = iface->queues[0].bufs;
    iface->tx_slot = 0;
    iface->pending_tx_count = 0;
    pthread_mutex_init(&iface->tx_lock, NULL);

    return 0;

err_queues:
    for (int j = 0; j < iface->queue_count; j++) {
        struct xsk_queue *queue = &iface->queues[j];
        if (queue->xsk) xsk_socket__delete(queue->xsk);
        if (queue->umem) xsk_umem__delete(queue->umem);
        if (queue->bufs) {
            munlock(queue->bufs, iface->umem_size);
            free(queue->bufs);
        }
    }
    interface_xdp_try_detach(iface->ifindex, iface->ifname);
    if (wan_bpf_obj) bpf_object__close(wan_bpf_obj);
    return -1;
}

void interface_cleanup(struct xsk_interface *iface) {
    pthread_mutex_destroy(&iface->tx_lock);

    if (iface->ifindex)
        interface_xdp_try_detach(iface->ifindex, iface->ifname);

    for (int q = 0; q < iface->queue_count; q++) {
        struct xsk_queue *queue = &iface->queues[q];
        pthread_mutex_destroy(&queue->tx_lock);
        if (queue->xsk)
            xsk_socket__delete(queue->xsk);
        if (queue->umem)
            xsk_umem__delete(queue->umem);
        if (queue->bufs) {
            munlock(queue->bufs, iface->umem_size);
            free(queue->bufs);
        }
    }

    if (iface->queue_count == 0) {
        if (iface->xsk)
            xsk_socket__delete(iface->xsk);

        if (iface->umem)
            xsk_umem__delete(iface->umem);

        if (iface->bufs) {
            munlock(iface->bufs, iface->umem_size);
            free(iface->bufs);
        }
    }

    memset(iface, 0, sizeof(*iface));
}

#define ADDR_ENCODE(q, addr) (((uint64_t)(q) << 56) | ((addr) & 0x00FFFFFFFFFFFFFF))
#define ADDR_QUEUE(encoded)  ((int)((encoded) >> 56))
#define ADDR_OFFSET(encoded) ((encoded) & 0x00FFFFFFFFFFFFFF)

int interface_recv(struct xsk_interface *iface,
                   void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts) {
    uint32_t idx_rx = 0;
    int total_rcvd = 0;

    if (iface->queue_count == 0)
        return 0;

    for (int i = 0; i < iface->queue_count && total_rcvd < max_pkts; i++) {
        int q = (iface->current_queue + i) % iface->queue_count;
        struct xsk_queue *queue = &iface->queues[q];

        int rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts - total_rcvd, &idx_rx);
        if (rcvd == 0)
            continue;

        for (int j = 0; j < rcvd; j++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queue->rx, idx_rx + j);
            addrs[total_rcvd + j] = ADDR_ENCODE(q, desc->addr);
            pkt_ptrs[total_rcvd + j] = (uint8_t *)queue->bufs + desc->addr;
            pkt_lens[total_rcvd + j] = desc->len;
        }

        xsk_ring_cons__release(&queue->rx, rcvd);
        total_rcvd += rcvd;
    }

    iface->current_queue = (iface->current_queue + 1) % iface->queue_count;

    if (total_rcvd == 0) {
        struct pollfd fds[MAX_QUEUES];
        for (int q = 0; q < iface->queue_count; q++) {
            fds[q].fd = xsk_socket__fd(iface->queues[q].xsk);
            fds[q].events = POLLIN;
        }
        if (poll(fds, iface->queue_count, 1) <= 0)
            return 0;

        for (int q = 0; q < iface->queue_count && total_rcvd < max_pkts; q++) {
            if (!(fds[q].revents & POLLIN))
                continue;

            struct xsk_queue *queue = &iface->queues[q];
            int rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts - total_rcvd, &idx_rx);
            if (rcvd == 0)
                continue;

            for (int j = 0; j < rcvd; j++) {
                const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queue->rx, idx_rx + j);
                addrs[total_rcvd + j] = ADDR_ENCODE(q, desc->addr);
                pkt_ptrs[total_rcvd + j] = (uint8_t *)queue->bufs + desc->addr;
                pkt_lens[total_rcvd + j] = desc->len;
            }

            xsk_ring_cons__release(&queue->rx, rcvd);
            total_rcvd += rcvd;
        }
    }

    iface->rx_packets += total_rcvd;
    return total_rcvd;
}

void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count) {
    if (iface->queue_count == 0)
        return;

    for (int i = 0; i < count; i++) {
        int q = ADDR_QUEUE(addrs[i]);
        uint64_t addr = ADDR_OFFSET(addrs[i]);

        if (q >= iface->queue_count)
            continue;

        struct xsk_queue *queue = &iface->queues[q];
        uint32_t idx_fill;

        int ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
        if (ret != 1) {
            uint32_t comp_idx;
            int comp = xsk_ring_cons__peek(&queue->comp, iface->batch_size, &comp_idx);
            if (comp > 0)
                xsk_ring_cons__release(&queue->comp, comp);

            ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
            if (ret != 1)
                continue;
        }

        *xsk_ring_prod__fill_addr(&queue->fill, idx_fill) = addr;
        xsk_ring_prod__submit(&queue->fill, 1);
    }
}

int interface_send(struct xsk_interface *iface,
                   void *pkt_data, uint32_t pkt_len) {
    uint32_t idx;
    struct ether_header *eth;

    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&iface->comp, iface->batch_size, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&iface->comp, completed);

    int reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
    if (reserved < 1) {
        sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        completed = xsk_ring_cons__peek(&iface->comp, iface->batch_size, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&iface->comp, completed);
        reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
        if (reserved < 1)
            return -1;
    }

    uint64_t addr = ((iface->tx_slot % iface->ring_size) + iface->ring_size) * iface->frame_size;
    iface->tx_slot++;

    void *tx_buf = (uint8_t *)iface->bufs + addr;
    memcpy(tx_buf, pkt_data, pkt_len);

    eth = (struct ether_header *)tx_buf;
    memcpy(eth->ether_dhost, iface->dst_mac, MAC_LEN);
    memcpy(eth->ether_shost, iface->src_mac, MAC_LEN);

    xsk_ring_prod__tx_desc(&iface->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&iface->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&iface->tx, 1);

    sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    iface->tx_packets++;
    iface->tx_bytes += pkt_len;

    return 0;
}

int interface_send_to_local(struct xsk_interface *iface,
                            const struct local_config *local_cfg,
                            void *pkt_data, uint32_t pkt_len) {
    uint32_t idx;
    struct ether_header *eth;

    if (iface->queue_count == 0)
        return -1;

    struct xsk_queue *queue = &iface->queues[0];

    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&queue->comp, iface->batch_size, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&queue->comp, completed);

    int reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
    if (reserved < 1) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        completed = xsk_ring_cons__peek(&queue->comp, iface->batch_size, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&queue->comp, completed);
        reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
        if (reserved < 1)
            return -1;
    }

    uint32_t frame_count = iface->umem_size / iface->frame_size;
    uint64_t addr = ((iface->tx_slot % (frame_count / 2)) + frame_count / 2) * iface->frame_size;
    iface->tx_slot++;

    void *tx_buf = (uint8_t *)queue->bufs + addr;
    memcpy(tx_buf, pkt_data, pkt_len);

    eth = (struct ether_header *)tx_buf;

    if (local_cfg->dst_mac[0] | local_cfg->dst_mac[1] | local_cfg->dst_mac[2] |
        local_cfg->dst_mac[3] | local_cfg->dst_mac[4] | local_cfg->dst_mac[5]) {
        memcpy(eth->ether_dhost, local_cfg->dst_mac, MAC_LEN);
    }
    if (local_cfg->src_mac[0] | local_cfg->src_mac[1] | local_cfg->src_mac[2] |
        local_cfg->src_mac[3] | local_cfg->src_mac[4] | local_cfg->src_mac[5]) {
        memcpy(eth->ether_shost, local_cfg->src_mac, MAC_LEN);
    }

    xsk_ring_prod__tx_desc(&queue->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&queue->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&queue->tx, 1);

    sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    iface->tx_packets++;
    iface->tx_bytes += pkt_len;

    return 0;
}

void interface_print_stats(struct xsk_interface *iface) {
    (void)iface;
}

int interface_send_batch(struct xsk_interface *iface,
                         void *pkt_data, uint32_t pkt_len) {
    uint32_t idx;
    struct ether_header *eth;
    int ret = 0;

    pthread_mutex_lock(&iface->tx_lock);

    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&iface->comp, iface->ring_size, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&iface->comp, completed);

    int reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
    if (reserved < 1) {
        if (iface->pending_tx_count > 0) {
            sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            iface->pending_tx_count = 0;
        }

        completed = xsk_ring_cons__peek(&iface->comp, iface->ring_size, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&iface->comp, completed);

        for (int retry = 0; retry < 3; retry++) {
            reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
            if (reserved >= 1)
                break;
            for (volatile int i = 0; i < 100; i++);
            completed = xsk_ring_cons__peek(&iface->comp, iface->ring_size, &comp_idx);
            if (completed > 0)
                xsk_ring_cons__release(&iface->comp, completed);
        }

        if (reserved < 1) {
            ret = -1;
            goto unlock;
        }
    }

    uint64_t addr = ((iface->tx_slot % iface->ring_size) + iface->ring_size) * iface->frame_size;
    iface->tx_slot++;

    void *tx_buf = (uint8_t *)iface->bufs + addr;
    memcpy(tx_buf, pkt_data, pkt_len);

    eth = (struct ether_header *)tx_buf;
    memcpy(eth->ether_dhost, iface->dst_mac, MAC_LEN);
    memcpy(eth->ether_shost, iface->src_mac, MAC_LEN);

    xsk_ring_prod__tx_desc(&iface->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&iface->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&iface->tx, 1);

    iface->pending_tx_count++;
    __sync_fetch_and_add(&iface->tx_packets, 1);
    __sync_fetch_and_add(&iface->tx_bytes, pkt_len);

    if (iface->pending_tx_count >= 64) {
        sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        iface->pending_tx_count = 0;
    }

unlock:
    pthread_mutex_unlock(&iface->tx_lock);
    return ret;
}

void interface_send_flush(struct xsk_interface *iface) {
    pthread_mutex_lock(&iface->tx_lock);
    if (iface->pending_tx_count > 0) {
        sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        iface->pending_tx_count = 0;
    }
    pthread_mutex_unlock(&iface->tx_lock);
}

int interface_send_to_local_batch(struct xsk_interface *iface,
                                  const struct local_config *local_cfg,
                                  void *pkt_data, uint32_t pkt_len,
                                  int tx_queue) {
    uint32_t idx;
    struct ether_header *eth;

    if (iface->queue_count == 0)
        return -1;

    int q = tx_queue % iface->queue_count;
    struct xsk_queue *queue = &iface->queues[q];

    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&queue->comp, iface->ring_size, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&queue->comp, completed);

    int reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
    if (reserved < 1) {
        if (queue->pending_tx_count > 0) {
            sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            queue->pending_tx_count = 0;
        }

        completed = xsk_ring_cons__peek(&queue->comp, iface->ring_size, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&queue->comp, completed);

        for (int retry = 0; retry < 8; retry++) {
            reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
            if (reserved >= 1)
                break;
            for (volatile int i = 0; i < 400; i++);
            completed = xsk_ring_cons__peek(&queue->comp, iface->ring_size, &comp_idx);
            if (completed > 0)
                xsk_ring_cons__release(&queue->comp, completed);
        }

        if (reserved < 1) {
            return -1;
        }
    }

    uint64_t addr = ((queue->tx_slot % iface->ring_size) + iface->ring_size) * iface->frame_size;
    queue->tx_slot++;

    void *tx_buf = (uint8_t *)queue->bufs + addr;
    memcpy(tx_buf, pkt_data, pkt_len);

    eth = (struct ether_header *)tx_buf;
    if (local_cfg->dst_mac[0] | local_cfg->dst_mac[1] | local_cfg->dst_mac[2] |
        local_cfg->dst_mac[3] | local_cfg->dst_mac[4] | local_cfg->dst_mac[5]) {
        memcpy(eth->ether_dhost, local_cfg->dst_mac, MAC_LEN);
    }
    if (local_cfg->src_mac[0] | local_cfg->src_mac[1] | local_cfg->src_mac[2] |
        local_cfg->src_mac[3] | local_cfg->src_mac[4] | local_cfg->src_mac[5]) {
        memcpy(eth->ether_shost, local_cfg->src_mac, MAC_LEN);
    }

    xsk_ring_prod__tx_desc(&queue->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&queue->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&queue->tx, 1);

    queue->pending_tx_count++;
    __sync_fetch_and_add(&iface->tx_packets, 1);
    __sync_fetch_and_add(&iface->tx_bytes, pkt_len);

    if (queue->pending_tx_count >= 16) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }

    return 0;
}

void interface_send_to_local_flush(struct xsk_interface *iface, int tx_queue) {
    if (iface->queue_count == 0)
        return;

    int q = tx_queue % iface->queue_count;
    struct xsk_queue *queue = &iface->queues[q];

    if (queue->pending_tx_count > 0) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }
}



int interface_recv_single_queue(struct xsk_interface *iface, int queue_idx,
                                void **pkt_ptrs, uint32_t *pkt_lens,
                                uint64_t *addrs, int max_pkts) {
    if (queue_idx >= iface->queue_count)
        return 0;

    struct xsk_queue *queue = &iface->queues[queue_idx];
    uint32_t idx_rx = 0;
    
    int rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts, &idx_rx);
    if (rcvd == 0) {
        struct pollfd pfd = {
            .fd = xsk_socket__fd(queue->xsk),
            .events = POLLIN
        };
        if (poll(&pfd, 1, 1) <= 0)
            return 0;

        rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts, &idx_rx);
        if (rcvd == 0)
            return 0;
    }

    for (int j = 0; j < rcvd; j++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queue->rx, idx_rx + j);
        addrs[j] = desc->addr;
        pkt_ptrs[j] = (uint8_t *)queue->bufs + desc->addr;
        pkt_lens[j] = desc->len;
    }
    xsk_ring_cons__release(&queue->rx, rcvd);
    iface->rx_packets += rcvd;
    return rcvd;
}

void interface_recv_release_single_queue(struct xsk_interface *iface,
                                          int queue_idx,
                                          uint64_t *addrs, int count) {
    if (queue_idx >= iface->queue_count)
        return;

    struct xsk_queue *queue = &iface->queues[queue_idx];

    for (int i = 0; i < count; i++) {
        uint32_t idx_fill;
        int ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
        if (ret != 1) {
            uint32_t comp_idx;
            int comp = xsk_ring_cons__peek(&queue->comp, 64, &comp_idx);
            if (comp > 0)
                xsk_ring_cons__release(&queue->comp, comp);

            ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
            if (ret != 1)
                continue;
        }
        *xsk_ring_prod__fill_addr(&queue->fill, idx_fill) = addrs[i];
        xsk_ring_prod__submit(&queue->fill, 1);
    }
}

int interface_send_batch_queue(struct xsk_interface *iface, int queue_idx,
                                void *pkt_data, uint32_t pkt_len) {
    if (queue_idx >= iface->queue_count)
        return -1;

    struct xsk_queue *queue = &iface->queues[queue_idx];
    uint32_t idx;
    struct ether_header *eth;
    int ret = 0;

    pthread_mutex_lock(&queue->tx_lock);

    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&queue->comp, iface->ring_size, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&queue->comp, completed);

    int reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
    if (reserved < 1) {
        if (queue->pending_tx_count > 0) {
            sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            queue->pending_tx_count = 0;
        }

        completed = xsk_ring_cons__peek(&queue->comp, iface->ring_size, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&queue->comp, completed);

        for (int retry = 0; retry < 8; retry++) {
            reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
            if (reserved >= 1)
                break;
            for (volatile int i = 0; i < 400; i++);
            completed = xsk_ring_cons__peek(&queue->comp, iface->ring_size, &comp_idx);
            if (completed > 0)
                xsk_ring_cons__release(&queue->comp, completed);
        }

        if (reserved < 1) {
            ret = -1;
            goto unlock;
        }
    }

    {
        uint32_t frame_count = iface->umem_size / iface->frame_size;
        uint64_t addr = ((queue->tx_slot % (frame_count / 2)) + frame_count / 2) * iface->frame_size;
        queue->tx_slot++;

        void *tx_buf = (uint8_t *)queue->bufs + addr;
        memcpy(tx_buf, pkt_data, pkt_len);

        eth = (struct ether_header *)tx_buf;
        int have_dst = (iface->dst_mac[0] | iface->dst_mac[1] | iface->dst_mac[2] |
                        iface->dst_mac[3] | iface->dst_mac[4] | iface->dst_mac[5]);
        int have_src = (iface->src_mac[0] | iface->src_mac[1] | iface->src_mac[2] |
                        iface->src_mac[3] | iface->src_mac[4] | iface->src_mac[5]);

        if (have_dst)
            memcpy(eth->ether_dhost, iface->dst_mac, MAC_LEN);
        if (have_src)
            memcpy(eth->ether_shost, iface->src_mac, MAC_LEN);

        xsk_ring_prod__tx_desc(&queue->tx, idx)->addr = addr;
        xsk_ring_prod__tx_desc(&queue->tx, idx)->len = pkt_len;
        xsk_ring_prod__submit(&queue->tx, 1);
    }

    queue->pending_tx_count++;
    __sync_fetch_and_add(&iface->tx_packets, 1);
    __sync_fetch_and_add(&iface->tx_bytes, pkt_len);

    if (queue->pending_tx_count >= 16) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }

unlock:
    pthread_mutex_unlock(&queue->tx_lock);
    return ret;
}

void interface_send_flush_queue(struct xsk_interface *iface, int queue_idx) {
    if (queue_idx >= iface->queue_count)
        return;

    struct xsk_queue *queue = &iface->queues[queue_idx];
    pthread_mutex_lock(&queue->tx_lock);
    if (queue->pending_tx_count > 0) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }
    pthread_mutex_unlock(&queue->tx_lock);
}

int interface_send_to_local_batch_queue(struct xsk_interface *iface,
                                         int queue_idx,
                                         const struct local_config *local_cfg,
                                         void *pkt_data, uint32_t pkt_len) {
    if (queue_idx >= iface->queue_count)
        return -1;

    struct xsk_queue *queue = &iface->queues[queue_idx];
    uint32_t idx;
    struct ether_header *eth;

#define LOCAL_TX_MAX_WAIT_LOOPS  10000

    pthread_mutex_lock(&queue->tx_lock);

    uint32_t comp_idx;
    int completed;
    int reserved = 0;
    unsigned int wait_loops = 0;
    unsigned int total_loops = 0;

    while (1) {
        completed = xsk_ring_cons__peek(&queue->comp, iface->ring_size, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&queue->comp, completed);

        reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
        if (reserved >= 1)
            break;

        __sync_fetch_and_add(&queue->tx_wait_loops, 1);
        if (total_loops++ >= LOCAL_TX_MAX_WAIT_LOOPS) {
            pthread_mutex_unlock(&queue->tx_lock);
            return -1;
        }
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
        if (wait_loops++ > 50) {
            usleep(100); 
            wait_loops = 0;
        }
        sched_yield();
    }

    {
        uint32_t frame_count = iface->umem_size / iface->frame_size;
        uint64_t addr = ((queue->tx_slot % (frame_count / 2)) + frame_count / 2) * iface->frame_size;
        queue->tx_slot++;

        void *tx_buf = (uint8_t *)queue->bufs + addr;
        memcpy(tx_buf, pkt_data, pkt_len);

        eth = (struct ether_header *)tx_buf;
    if (local_cfg->dst_mac[0] | local_cfg->dst_mac[1] | local_cfg->dst_mac[2] |
        local_cfg->dst_mac[3] | local_cfg->dst_mac[4] | local_cfg->dst_mac[5]) {
        memcpy(eth->ether_dhost, local_cfg->dst_mac, MAC_LEN);
    }
    if (local_cfg->src_mac[0] | local_cfg->src_mac[1] | local_cfg->src_mac[2] |
        local_cfg->src_mac[3] | local_cfg->src_mac[4] | local_cfg->src_mac[5]) {
        memcpy(eth->ether_shost, local_cfg->src_mac, MAC_LEN);
    }

        xsk_ring_prod__tx_desc(&queue->tx, idx)->addr = addr;
        xsk_ring_prod__tx_desc(&queue->tx, idx)->len = pkt_len;
        xsk_ring_prod__submit(&queue->tx, 1);
    }

    queue->pending_tx_count++;
    __sync_fetch_and_add(&iface->tx_packets, 1);
    __sync_fetch_and_add(&iface->tx_bytes, pkt_len);

    if (queue->pending_tx_count >= 4) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }

    pthread_mutex_unlock(&queue->tx_lock);
    return 0;
}

void interface_send_to_local_flush_queue(struct xsk_interface *iface,
                                          int queue_idx) {
    if (queue_idx >= iface->queue_count)
        return;

    struct xsk_queue *queue = &iface->queues[queue_idx];
    pthread_mutex_lock(&queue->tx_lock);
    if (queue->pending_tx_count > 0) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }
    pthread_mutex_unlock(&queue->tx_lock);
}