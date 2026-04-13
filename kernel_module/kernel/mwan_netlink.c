#include "mwan_netlink.h"
#include "mwan_proto.h"
#include "mwan_state.h"

#include <net/genetlink.h>
#include <linux/module.h>

/* Netlink Policy for parsing payload */
static const struct nla_policy mwan_genl_policy[MWAN_ATTR_MAX + 1] = {
    [MWAN_ATTR_NODE_ID]   = { .type = NLA_U32 },
    [MWAN_ATTR_CIDR_IP]   = { .type = NLA_U32 },
    [MWAN_ATTR_CIDR_MASK] = { .type = NLA_U32 },
    [MWAN_ATTR_TUNNELS]   = { .type = NLA_NESTED },
    [MWAN_ATTR_LOCAL_IP]   = { .type = NLA_U32 },
    [MWAN_ATTR_LOCAL_MASK] = { .type = NLA_U32 },
    [MWAN_ATTR_LOCAL_IFINDEX] = { .type = NLA_U32 },
    [MWAN_ATTR_ENCRYPT_ON]   = { .type = NLA_U8 },
    [MWAN_ATTR_ENCRYPT_TYPE] = { .type = NLA_U8 },
    [MWAN_ATTR_ENCRYPT_KEY]  = { .type = NLA_BINARY, .len = MWAN_MAX_KEY_LEN },
    [MWAN_ATTR_ENCRYPT_SALT] = { .type = NLA_BINARY, .len = MWAN_SALT_LEN },
};

/* Callback to handle SET_CONFIG message */
static int mwan_genl_set_config(struct sk_buff *skb, struct genl_info *info)
{
    struct mwan_config *new_cfg;
    struct nlattr *nla_tunnels;
    struct nlattr *tun;
    int rem, err, ret;

    if (!info->attrs[MWAN_ATTR_NODE_ID] ||
        !info->attrs[MWAN_ATTR_CIDR_IP] ||
        !info->attrs[MWAN_ATTR_CIDR_MASK]) {
        return -EINVAL;
    }

    new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
    if (!new_cfg) return -ENOMEM;

    new_cfg->node_id   = nla_get_u32(info->attrs[MWAN_ATTR_NODE_ID]);
    new_cfg->cidr_ip   = (__force __be32)nla_get_u32(info->attrs[MWAN_ATTR_CIDR_IP]);
    new_cfg->cidr_mask = (__force __be32)nla_get_u32(info->attrs[MWAN_ATTR_CIDR_MASK]);
    new_cfg->num_tunnels = 0;

    if (info->attrs[MWAN_ATTR_LOCAL_IP])
        new_cfg->local_ip = (__force __be32)nla_get_u32(info->attrs[MWAN_ATTR_LOCAL_IP]);
    if (info->attrs[MWAN_ATTR_LOCAL_MASK])
        new_cfg->local_mask = (__force __be32)nla_get_u32(info->attrs[MWAN_ATTR_LOCAL_MASK]);
    if (info->attrs[MWAN_ATTR_LOCAL_IFINDEX])
        new_cfg->local_ifindex = nla_get_u32(info->attrs[MWAN_ATTR_LOCAL_IFINDEX]);

    nla_tunnels = info->attrs[MWAN_ATTR_TUNNELS];
    if (nla_tunnels) {
        nla_for_each_nested(tun, nla_tunnels, rem) {
            struct nlattr *tb[MWAN_TUN_MAX + 1];
            // Since we're using generic nested arrays, each element might be a nested attribute itself.
            // Simplified here: assume flat array or properly nested. Real parser requires nla_parse_nested.
            
            err = nla_parse_nested_deprecated(tb, MWAN_TUN_MAX, tun, NULL, NULL);
            if (err < 0) continue;

            if (tb[MWAN_TUN_IFINDEX] && tb[MWAN_TUN_WEIGHT]) {
                if (new_cfg->num_tunnels < MAX_MWAN_TUNNELS) {
                    new_cfg->tunnels[new_cfg->num_tunnels].ifindex = nla_get_u32(tb[MWAN_TUN_IFINDEX]);
                    new_cfg->tunnels[new_cfg->num_tunnels].weight  = nla_get_u32(tb[MWAN_TUN_WEIGHT]);
                    
                    if (tb[MWAN_TUN_GATEWAY]) {
                        new_cfg->tunnels[new_cfg->num_tunnels].gateway = (__force __be32)nla_get_u32(tb[MWAN_TUN_GATEWAY]);
                    }
                    
                    new_cfg->num_tunnels++;
                }
            }
        }
    }

    /* Parse encryption config */
    if (info->attrs[MWAN_ATTR_ENCRYPT_ON]) {
        new_cfg->encrypt_on = (nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_ON]) != 0);
        
        if (new_cfg->encrypt_on) {
            if (info->attrs[MWAN_ATTR_ENCRYPT_TYPE])
                new_cfg->encrypt_type = nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_TYPE]);
            
            if (info->attrs[MWAN_ATTR_ENCRYPT_KEY]) {
                int klen = nla_len(info->attrs[MWAN_ATTR_ENCRYPT_KEY]);
                if (klen > 0 && klen <= MWAN_MAX_KEY_LEN) {
                    new_cfg->encrypt_key_len = klen;
                    memcpy(new_cfg->encrypt_key, nla_data(info->attrs[MWAN_ATTR_ENCRYPT_KEY]), klen);
                }
            }
            
            if (info->attrs[MWAN_ATTR_ENCRYPT_SALT]) {
                memcpy(new_cfg->encrypt_salt, nla_data(info->attrs[MWAN_ATTR_ENCRYPT_SALT]), MWAN_SALT_LEN);
            }
            
            pr_info("mwan_kmod: Encryption ON (type: %u, key_len: %u)\n",
                    new_cfg->encrypt_type, new_cfg->encrypt_key_len);
        }
    }

    ret = mwan_state_update(new_cfg);
    if (ret < 0) {
        kfree(new_cfg);
        return ret;
    }

    pr_info("mwan_kmod: Netlink config updated (Node: %u, Tunnels: %u)\n", 
            new_cfg->node_id, new_cfg->num_tunnels);
            
    return 0;
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
