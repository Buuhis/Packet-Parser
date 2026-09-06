#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "mwan_state.h"

bool mwan_l2_diag_enabled;
bool mwan_fw_diag_enabled;
unsigned int mwan_l2_diag_limit = 64;
unsigned int mwan_l2_softirq_high_pct = 91;
unsigned int mwan_l2_softirq_low_pct = 70;
unsigned int mwan_l2_softirq_sample_ms = 50;
unsigned int mwan_l2_idle_unblock_pct = 20;
unsigned int mwan_l2_emergency_pct = 97;
unsigned int mwan_l2_max_shed_pct = 50;
static bool mwan_l2_diag_reset_param;
module_param_named(l2_diag, mwan_l2_diag_enabled, bool, 0644);
MODULE_PARM_DESC(l2_diag,
                 "Log the first L2-PQC TX/RX/worker observation per flow");
module_param_named(fw_diag, mwan_fw_diag_enabled, bool, 0644);
MODULE_PARM_DESC(fw_diag,
                 "Log MWAN TX/RX/FORWARD path and conntrack observations");
module_param_named(l2_diag_limit, mwan_l2_diag_limit, uint, 0644);
MODULE_PARM_DESC(l2_diag_limit,
                 "Maximum number of distinct L2-PQC flows logged per stage");
module_param_named(l2_softirq_high, mwan_l2_softirq_high_pct, uint, 0644);
MODULE_PARM_DESC(l2_softirq_high,
                 "Compatibility name: busy/sys/soft percent blocking new flows");
module_param_named(l2_softirq_low, mwan_l2_softirq_low_pct, uint, 0644);
MODULE_PARM_DESC(l2_softirq_low,
                 "Maximum system/softirq percent allowed while unblocking a CPU");
module_param_named(l2_softirq_sample_ms, mwan_l2_softirq_sample_ms, uint,
                   0644);
MODULE_PARM_DESC(l2_softirq_sample_ms,
                 "Per-CPU accounting sample interval in milliseconds");
module_param_named(l2_idle_unblock, mwan_l2_idle_unblock_pct, uint, 0644);
MODULE_PARM_DESC(l2_idle_unblock,
                 "Raw and EWMA idle percent required to unblock a CPU");
module_param_named(l2_emergency, mwan_l2_emergency_pct, uint, 0644);
MODULE_PARM_DESC(l2_emergency,
                 "Busy/sys/soft candidate threshold; shedding also requires three samples and TX queue pressure");
module_param_named(l2_max_shed, mwan_l2_max_shed_pct, uint, 0644);
MODULE_PARM_DESC(l2_max_shed,
                 "Maximum percentage of eligible data packets shed per CPU");

static int mwan_l2_diag_reset_set(const char *val,
                                  const struct kernel_param *kp)
{
    bool requested;
    int err;

    (void)kp;
    err = kstrtobool(val, &requested);
    if (err)
        return err;
    if (requested)
        mwan_l2_diag_reset_all();
    WRITE_ONCE(mwan_l2_diag_reset_param, false);
    return 0;
}

static int mwan_l2_diag_reset_get(char *buffer,
                                  const struct kernel_param *kp)
{
    (void)kp;
    return sysfs_emit(buffer, "0\n");
}

static const struct kernel_param_ops mwan_l2_diag_reset_ops = {
    .set = mwan_l2_diag_reset_set,
    .get = mwan_l2_diag_reset_get,
};

module_param_cb(l2_diag_reset, &mwan_l2_diag_reset_ops,
                &mwan_l2_diag_reset_param, 0644);
MODULE_PARM_DESC(l2_diag_reset,
                 "Write 1 to reset L2 diagnostic state and counters");

// Forward declarations for initialization functions we will write later
int mwan_steer_init(void);
void mwan_steer_cleanup(void);
int mwan_netlink_init(void);
void mwan_netlink_cleanup(void);

// Provide stub implementations here until we write the real ones so the module builds!
int __weak mwan_steer_init(void) { return 0; }
void __weak mwan_steer_cleanup(void) {}
int __weak mwan_netlink_init(void) { return 0; }
void __weak mwan_netlink_cleanup(void) {}

static int __init mwan_kmod_init(void)
{
    int ret;

    pr_info("mwan_kmod: Initializing Zero-Copy Overlay Datapath...\n");

    mwan_state_init();

    /* Bring up the packet path/workqueue before exposing the configuration
     * API, so a SET_CONFIG request can always create its L2 workers. */
    ret = mwan_steer_init();
    if (ret < 0) {
        pr_err("mwan_kmod: Failed to register packet steering hooks\n");
        goto err_steer;
    }

    ret = mwan_netlink_init();
    if (ret < 0) {
        pr_err("mwan_kmod: Failed to initialize Netlink listener\n");
        goto err_netlink;
    }

    pr_info("mwan_kmod: Initialization complete.\n");
    return 0;

err_netlink:
    mwan_steer_cleanup();
err_steer:
    mwan_state_cleanup();
    return ret;
}

static void __exit mwan_kmod_exit(void)
{
    pr_info("mwan_kmod: Shutting down...\n");
    /* Stop config updates before tearing down packet workers and state. */
    mwan_netlink_cleanup();
    mwan_steer_cleanup();
    mwan_state_cleanup();
    pr_info("mwan_kmod: Unloaded successfully.\n");
}

module_init(mwan_kmod_init);
module_exit(mwan_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ahihi");
MODULE_DESCRIPTION("Multi-WAN Zero-Copy Kernel Datapath Module");
