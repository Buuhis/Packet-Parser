#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "mwan_state.h"

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
