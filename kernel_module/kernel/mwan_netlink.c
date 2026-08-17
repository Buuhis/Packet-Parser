#include "mwan_netlink.h"
#include "mwan_proto.h"
#include "mwan_state.h"

#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/slab.h>

/* Netlink Policy for parsing payload */
static const struct nla_policy mwan_genl_policy[MWAN_ATTR_MAX + 1] = {
    [MWAN_ATTR_NODE_ID]   = { .type = NLA_U32 },
    [MWAN_ATTR_TUNNELS]   = { .type = NLA_NESTED },
    [MWAN_ATTR_ENCRYPT_ON]   = { .type = NLA_U8 },
    [MWAN_ATTR_ENCRYPT_TYPE] = { .type = NLA_U8 },
    [MWAN_ATTR_ENCRYPT_KEY]  = { .type = NLA_BINARY, .len = MWAN_MAX_KEY_LEN },
    [MWAN_ATTR_ENCRYPT_SALT] = NLA_POLICY_EXACT_LEN(MWAN_SALT_LEN),
    [MWAN_ATTR_ENCRYPT_LAYER] = { .type = NLA_U8 },
};

static const struct nla_policy mwan_tunnel_policy[MWAN_TUN_MAX + 1] = {
    [MWAN_TUN_IFINDEX] = { .type = NLA_U32 },
    [MWAN_TUN_WEIGHT]  = { .type = NLA_U32 },
};

/* Callback to handle SET_CONFIG message */
static int mwan_genl_set_config(struct sk_buff *skb, struct genl_info *info)
{
    struct mwan_config *new_cfg;
    struct nlattr *nla_tunnels;
    struct nlattr *tun;
    u32 node_id, num_tunnels;
    int rem, err, ret;

    if (!info->attrs[MWAN_ATTR_NODE_ID]) {
        return -EINVAL;
    }

    new_cfg = kvzalloc(sizeof(*new_cfg), GFP_KERNEL);
    if (!new_cfg)
        return -ENOMEM;

    new_cfg->node_id   = nla_get_u32(info->attrs[MWAN_ATTR_NODE_ID]);
    new_cfg->num_tunnels = 0;

    nla_tunnels = info->attrs[MWAN_ATTR_TUNNELS];
    if (nla_tunnels) {
        nla_for_each_nested(tun, nla_tunnels, rem) {
            struct nlattr *tb[MWAN_TUN_MAX + 1];

            err = nla_parse_nested_deprecated(tb, MWAN_TUN_MAX, tun,
                                              mwan_tunnel_policy, NULL);
            if (err < 0) {
                ret = err;
                goto err_free_config;
            }

            if (!tb[MWAN_TUN_IFINDEX] || !tb[MWAN_TUN_WEIGHT] ||
                nla_get_u32(tb[MWAN_TUN_IFINDEX]) == 0 ||
                nla_get_u32(tb[MWAN_TUN_WEIGHT]) == 0 ||
                new_cfg->num_tunnels >= MAX_MWAN_TUNNELS) {
                ret = -EINVAL;
                goto err_free_config;
            }

            new_cfg->tunnels[new_cfg->num_tunnels].ifindex =
                nla_get_u32(tb[MWAN_TUN_IFINDEX]);
            new_cfg->tunnels[new_cfg->num_tunnels].weight =
                nla_get_u32(tb[MWAN_TUN_WEIGHT]);

            new_cfg->num_tunnels++;
        }
    }

    /* Parse encryption config */
    if (info->attrs[MWAN_ATTR_ENCRYPT_ON]) {
        new_cfg->encrypt_on = (nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_ON]) != 0);
        
        if (new_cfg->encrypt_on) {
            if (info->attrs[MWAN_ATTR_ENCRYPT_LAYER])
                new_cfg->encrypt_layer = nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_LAYER]);
            else
                new_cfg->encrypt_layer = 3; // Default L3

            if (info->attrs[MWAN_ATTR_ENCRYPT_TYPE])
                new_cfg->encrypt_type = nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_TYPE]);
            
            if (info->attrs[MWAN_ATTR_ENCRYPT_KEY]) {
                int klen = nla_len(info->attrs[MWAN_ATTR_ENCRYPT_KEY]);
                if (klen == 16 || klen == 32) {
                    new_cfg->encrypt_key_len = klen;
                    memcpy(new_cfg->encrypt_key, nla_data(info->attrs[MWAN_ATTR_ENCRYPT_KEY]), klen);
                } else {
                    ret = -EINVAL;
                    goto err_free_config;
                }
            }
            
            if (info->attrs[MWAN_ATTR_ENCRYPT_SALT]) {
                memcpy(new_cfg->encrypt_salt, nla_data(info->attrs[MWAN_ATTR_ENCRYPT_SALT]), MWAN_SALT_LEN);
            }

            if (!info->attrs[MWAN_ATTR_ENCRYPT_KEY] ||
                !info->attrs[MWAN_ATTR_ENCRYPT_SALT]) {
                ret = -EINVAL;
                goto err_free_config;
            }
            
            pr_info("mwan_kmod: Encryption ON (layer: %u, type: %u, key_len: %u)\n",
                    new_cfg->encrypt_layer, new_cfg->encrypt_type, new_cfg->encrypt_key_len);
        }
    }

    node_id = new_cfg->node_id;
    num_tunnels = new_cfg->num_tunnels;
    ret = mwan_state_update(new_cfg);
    if (ret < 0) {
        goto err_free_config;
    }

    pr_info("mwan_kmod: Netlink config updated (Node: %u, Tunnels: %u)\n", 
            node_id, num_tunnels);
            
    return 0;

err_free_config:
    kvfree_sensitive(new_cfg, sizeof(*new_cfg));
    return ret;
}

/* Operation Definition */
static const struct genl_ops mwan_genl_ops[] = {
    {
        .cmd    = MWAN_CMD_SET_CONFIG,
        .flags  = 0,
        .policy = mwan_genl_policy,
        .doit   = mwan_genl_set_config,
        .dumpit = NULL,
    },
};

/* Family Definition */
static struct genl_family mwan_genl_family = {
    .name     = MWAN_GENL_NAME,
    .version  = MWAN_GENL_VERSION,
    .maxattr  = MWAN_ATTR_MAX,
    .netnsok  = true,
    .module   = THIS_MODULE,
    .ops      = mwan_genl_ops,
    .n_ops    = ARRAY_SIZE(mwan_genl_ops),
};

int mwan_netlink_init(void) {
    pr_info("mwan_kmod: Registering Netlink family %s\n", MWAN_GENL_NAME);
    return genl_register_family(&mwan_genl_family);
}

void mwan_netlink_cleanup(void) {
    pr_info("mwan_kmod: Unregistering Netlink family\n");
    genl_unregister_family(&mwan_genl_family);
}
