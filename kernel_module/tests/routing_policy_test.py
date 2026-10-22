"""Exercise production routing-only and RX NULL-flow branches with C stubs.

These are host regression tests, not a substitute for module/device testing.
"""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def block(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def run_test(name, source):
    with tempfile.TemporaryDirectory(prefix="mwan-policy-") as folder:
        executable = str(pathlib.Path(folder) / name)
        subprocess.run(
            ["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
             "-fno-sanitize-recover=all", "-x", "c", "-", "-o", executable],
            input=source, text=True, check=True,
        )
        subprocess.run([executable], check=True)
    print(name + ": passed")


steer = (ROOT / "kernel/mwan_steer.c").read_text()
route_branch = block(steer, "if (!READ_ONCE(cfg->weight_enabled))")
run_test("routing-only", r"""
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
typedef unsigned char u8;
#define READ_ONCE(x) (x)
#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define MWAN_ENCAP_NONE 0
struct mwan_tunnel { int ifindex, encap_type; bool published_up; };
struct mwan_config { bool weight_enabled; struct mwan_tunnel tunnels[2]; };
struct device { int ifindex; };
struct hook_state { struct device *out; };
struct packet { int unused; };
static int confirmations, dispatches, selected, unlocks;
static unsigned int confirm_result = NF_ACCEPT;
static void rcu_read_unlock(void) { unlocks++; }
static int nf_conntrack_confirm(struct packet *skb) {
    (void)skb; confirmations++; return confirm_result;
}
static struct mwan_tunnel *find_mwan_tunnel(struct mwan_config *cfg, int index) {
    for (int i = 0; i < 2; i++)
        if (cfg->tunnels[i].ifindex == index) return &cfg->tunnels[i];
    return NULL;
}
static unsigned int mwan_dispatch_encap(struct packet *skb,
    struct mwan_config *cfg, u8 index, void *context) {
    (void)skb; (void)cfg; assert(context == NULL);
    dispatches++; selected = index; return NF_STOLEN;
}
static unsigned int route(struct mwan_config *cfg, struct packet *skb,
                          struct hook_state *state) {
""" + route_branch + r"""
    return 99; /* continue into weighted mode */
}
int main(void) {
    struct mwan_config cfg = {false, {{10, 1, false}, {20, 1, true}}};
    struct device out = {10};
    struct hook_state state = {&out};
    struct packet skb = {0};
    assert(route(&cfg, &skb, &state) == NF_STOLEN);
    assert(selected == 0); /* BFD DOWN must not redirect routing-only data */
    out.ifindex = 20;
    assert(route(&cfg, &skb, &state) == NF_STOLEN);
    assert(selected == 1); /* follow Linux routing change */
    cfg.tunnels[1].encap_type = MWAN_ENCAP_NONE;
    assert(route(&cfg, &skb, &state) == NF_ACCEPT);
    assert(dispatches == 2 && confirmations == 2);
    cfg.tunnels[1].encap_type = 1; confirm_result = NF_DROP;
    assert(route(&cfg, &skb, &state) == NF_DROP);
    assert(dispatches == 2);
    out.ifindex = 30;
    assert(route(&cfg, &skb, &state) == NF_DROP);
    assert(unlocks == 5);
    cfg.weight_enabled = true;
    assert(route(&cfg, &skb, &state) == 99);
    assert(unlocks == 5);
    return 0;
}
""")

rx = (ROOT / "kernel/decap/decap_l2_pqc.c").read_text()
start = rx.index("atomic64_inc(&mwan_l2_rx_diag_flows_count);",
                 rx.index("static int mwan_l2_enqueue_skb("))
start = rx.index(";", start) + 1
end = rx.index("    worker = &cfg->l2_workers[owner];", start)
run_test("rx-null-flow", r"""
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#define READ_ONCE(x) (*(volatile int *)&(x))
struct worker { int cpu; };
struct config { int num_workers; struct worker *l2_workers; };
struct flow { int owner_worker; };
static int calls;
static int cpu_online(int cpu) { return cpu != 99; }
static int mwan_l2_select_rx_lane(struct config *cfg, unsigned id,
                                unsigned seq, int home) {
    (void)cfg; (void)id; (void)seq;
    assert(home == 1); calls++; return 2;
}
static int choose(struct config *cfg, struct flow *flow, int owner) {
    unsigned diag_id = 42, flow_seq = 1;
""" + rx[start:end] + r"""
    return owner;
}
int main(void) {
    struct worker workers[] = {{0}, {1}, {2}};
    struct config cfg = {3, workers};
    struct flow flow = {1};
    assert(choose(&cfg, NULL, 1) == 1);
    assert(calls == 0);
    assert(choose(&cfg, NULL, -1) == -ENODEV);
    assert(choose(&cfg, NULL, 3) == -ENODEV);
    workers[1].cpu = 99;
    assert(choose(&cfg, NULL, 1) == -ENODEV);
    assert(choose(&cfg, &flow, 1) == 2);
    assert(calls == 1);
    return 0;
}
""")
