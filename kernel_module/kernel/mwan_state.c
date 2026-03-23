#include "mwan_state.h"
#include <linux/slab.h>
#include <linux/spinlock.h>

/* Global Configuration Pointer (RCU Protected) */
struct mwan_config __rcu *g_mwan_cfg = NULL;

/* Spinlock to protect concurrent updates to the configuration */
static DEFINE_SPINLOCK(cfg_lock);

void mwan_state_init(void) {
    /* Optional: allocate an initial empty config if needed */
}

void mwan_state_cleanup(void) {
    struct mwan_config *old;
    
    spin_lock(&cfg_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&cfg_lock));
    if (old) {
        RCU_INIT_POINTER(g_mwan_cfg, NULL);
        kfree_rcu(old, rcu);
    }
    spin_unlock(&cfg_lock);
}

int mwan_state_update(struct mwan_config *new_cfg) {
    struct mwan_config *old;
    
    if (!new_cfg) return -EINVAL;

    spin_lock(&cfg_lock);
    old = rcu_dereference_protected(g_mwan_cfg, lockdep_is_held(&cfg_lock));
    
    /* Safely publish the new configuration */
    rcu_assign_pointer(g_mwan_cfg, new_cfg);
    
    /* Defer the freeing of the old configuration until all readers are done */
    if (old) {
        kfree_rcu(old, rcu);
    }
    spin_unlock(&cfg_lock);
    
    return 0;
}
