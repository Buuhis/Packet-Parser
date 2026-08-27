#include "mwan_netlink.h"
#include "mwan_mac_discovery.h"
#include "mwan_proto.h"
#include "mwan_state.h"

#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/slab.h>

static struct genl_family mwan_genl_family;

/* Netlink Policy for parsing payload */
static const struct nla_policy mwan_genl_policy[MWAN_ATTR_MAX + 1] = {
    [MWAN_ATTR_NODE_ID]   = { .type = NLA_U32 },
    [MWAN_ATTR_TUNNELS]   = { .type = NLA_NESTED },
    [MWAN_ATTR_ENCRYPT_ON]   = { .type = NLA_U8 },
    [MWAN_ATTR_ENCRYPT_TYPE] = { .type = NLA_U8 },
    [MWAN_ATTR_ENCRYPT_KEY]  = { .type = NLA_BINARY, .len = MWAN_MAX_KEY_LEN },
    [MWAN_ATTR_ENCRYPT_SALT] = NLA_POLICY_EXACT_LEN(MWAN_SALT_LEN),
    [MWAN_ATTR_ENCRYPT_LAYER] = { .type = NLA_U8 },
    [MWAN_ATTR_KEY_ID] = { .type = NLA_U8 },
    [MWAN_ATTR_PREV_KEY] = NLA_POLICY_EXACT_LEN(MWAN_MAX_KEY_LEN),
    [MWAN_ATTR_PREV_KEY_ID] = { .type = NLA_U8 },
    [MWAN_ATTR_QUERY_IFINDEX] = { .type = NLA_U32 },
    [MWAN_ATTR_PEER_TUNNEL_IP] = NLA_POLICY_EXACT_LEN(sizeof(__be32)),
    [MWAN_ATTR_PEER_RESOLVED] = { .type = NLA_U8 },
    [MWAN_ATTR_CONFIG_GENERATION] = { .type = NLA_U32 },
    [MWAN_ATTR_TUNNEL_STATE] = { .type = NLA_U8 },
    [MWAN_ATTR_STATE_SEQUENCE] = { .type = NLA_U32 },
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

    pr_info("mwan_kmod: CFG-TRACE nlseq=%u portid=%u ENTER SET_CONFIG\n",
            info->snd_seq, info->snd_portid);

    if (!info->attrs[MWAN_ATTR_NODE_ID] ||
        !info->attrs[MWAN_ATTR_CONFIG_GENERATION]) {
        pr_err("mwan_kmod: CFG-TRACE nlseq=%u REJECT missing_node_or_generation ret=%d\n",
               info->snd_seq, -EINVAL);
        return -EINVAL;
    }

    new_cfg = kvzalloc(sizeof(*new_cfg), GFP_KERNEL);
    if (!new_cfg)
        return -ENOMEM;

    new_cfg->node_id   = nla_get_u32(info->attrs[MWAN_ATTR_NODE_ID]);
    new_cfg->generation =
        nla_get_u32(info->attrs[MWAN_ATTR_CONFIG_GENERATION]);
    if (new_cfg->generation == 0) {
        ret = -EINVAL;
        goto err_free_config;
    }
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
            new_cfg->tunnels[new_cfg->num_tunnels].configured_ifindex =
                new_cfg->tunnels[new_cfg->num_tunnels].ifindex;
            new_cfg->tunnels[new_cfg->num_tunnels].weight =
                nla_get_u32(tb[MWAN_TUN_WEIGHT]);

            pr_info("mwan_kmod: CFG-TRACE nlseq=%u TUNNEL slot=%u ifindex=%u weight=%u\n",
                    info->snd_seq, new_cfg->num_tunnels,
                    new_cfg->tunnels[new_cfg->num_tunnels].ifindex,
                    new_cfg->tunnels[new_cfg->num_tunnels].weight);

            new_cfg->num_tunnels++;
        }
    }

    /* Parse encryption config */
    if (info->attrs[MWAN_ATTR_ENCRYPT_ON]) {
        new_cfg->encrypt_on = (nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_ON]) != 0);
        
        if (new_cfg->encrypt_on) {
            if (!info->attrs[MWAN_ATTR_ENCRYPT_LAYER] ||
                !info->attrs[MWAN_ATTR_ENCRYPT_TYPE] ||
                !info->attrs[MWAN_ATTR_ENCRYPT_KEY] ||
                !info->attrs[MWAN_ATTR_ENCRYPT_SALT]) {
                pr_err("mwan_kmod: Incomplete encryption configuration\n");
                ret = -EINVAL;
                goto err_free_config;
            }

            new_cfg->encrypt_layer =
                nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_LAYER]);
            new_cfg->encrypt_type =
                nla_get_u8(info->attrs[MWAN_ATTR_ENCRYPT_TYPE]);
            
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

            new_cfg->key_id = 1;
            if (info->attrs[MWAN_ATTR_KEY_ID]) {
                new_cfg->key_id = nla_get_u8(info->attrs[MWAN_ATTR_KEY_ID]);
                if (new_cfg->key_id == 0) {
                    ret = -EINVAL;
                    goto err_free_config;
                }
            }
            if (info->attrs[MWAN_ATTR_PREV_KEY] ||
                info->attrs[MWAN_ATTR_PREV_KEY_ID]) {
                if (!info->attrs[MWAN_ATTR_PREV_KEY] ||
                    !info->attrs[MWAN_ATTR_PREV_KEY_ID]) {
                    ret = -EINVAL;
                    goto err_free_config;
                }
                new_cfg->prev_key_id =
                    nla_get_u8(info->attrs[MWAN_ATTR_PREV_KEY_ID]);
                if (new_cfg->prev_key_id == 0 ||
                    new_cfg->prev_key_id == new_cfg->key_id) {
                    ret = -EINVAL;
                    goto err_free_config;
                }
                memcpy(new_cfg->prev_key,
                       nla_data(info->attrs[MWAN_ATTR_PREV_KEY]),
                       MWAN_MAX_KEY_LEN);
                new_cfg->prev_key_len = MWAN_MAX_KEY_LEN;
                new_cfg->prev_key_valid = true;
            }

            pr_info("mwan_kmod: Encryption ON (layer: %u, type: %u, key_len: %u)\n",
                    new_cfg->encrypt_layer, new_cfg->encrypt_type, new_cfg->encrypt_key_len);
        }
    }

    node_id = new_cfg->node_id;
    num_tunnels = new_cfg->num_tunnels;
    pr_info("mwan_kmod: CFG-TRACE nlseq=%u PARSED node=%u tunnels=%u enabled=%u layer=%u type=%u key_len=%u key_id=%u prev_key=%u\n",
            info->snd_seq, node_id, num_tunnels, new_cfg->encrypt_on,
            new_cfg->encrypt_layer, new_cfg->encrypt_type,
            new_cfg->encrypt_key_len, new_cfg->key_id,
            new_cfg->prev_key_valid);
    ret = mwan_state_update(new_cfg);
    if (ret < 0) {
        pr_err("mwan_kmod: CFG-TRACE nlseq=%u REJECT node=%u ret=%d\n",
               info->snd_seq, node_id, ret);
        goto err_free_config;
    }

    pr_info("mwan_kmod: CFG-TRACE nlseq=%u ACCEPT_ACTIVE node=%u tunnels=%u enabled=%u layer=%u type=%u key_len=%u key_id=%u prev_key=%u\n",
            info->snd_seq, node_id, num_tunnels, new_cfg->encrypt_on,
            new_cfg->encrypt_layer, new_cfg->encrypt_type,
            new_cfg->encrypt_key_len, new_cfg->key_id,
            new_cfg->prev_key_valid);
    pr_info("mwan_kmod: Netlink config updated (Node: %u, Tunnels: %u)\n",
            node_id, num_tunnels);
            
    return 0;

err_free_config:
    kvfree_sensitive(new_cfg, sizeof(*new_cfg));
    return ret;
}

static int mwan_genl_set_tunnel_state(struct sk_buff *skb,
                                      struct genl_info *info)
{
    u32 ifindex;
    u32 generation;
    u32 sequence;
    u8 state;

    (void)skb;
    if (!info->attrs[MWAN_ATTR_QUERY_IFINDEX] ||
        !info->attrs[MWAN_ATTR_CONFIG_GENERATION] ||
        !info->attrs[MWAN_ATTR_STATE_SEQUENCE] ||
        !info->attrs[MWAN_ATTR_TUNNEL_STATE])
        return -EINVAL;

    ifindex = nla_get_u32(info->attrs[MWAN_ATTR_QUERY_IFINDEX]);
    generation = nla_get_u32(info->attrs[MWAN_ATTR_CONFIG_GENERATION]);
    sequence = nla_get_u32(info->attrs[MWAN_ATTR_STATE_SEQUENCE]);
    state = nla_get_u8(info->attrs[MWAN_ATTR_TUNNEL_STATE]);
    if (state > 1)
        return -EINVAL;

    return mwan_state_set_tunnel_state(ifindex, generation, sequence,
                                       state != 0);
}

static int mwan_genl_get_tunnel_state(struct sk_buff *skb,
                                      struct genl_info *info)
{
    struct sk_buff *reply;
    void *reply_hdr;
    u32 ifindex;
    u32 generation;
    u32 sequence;
    bool up;
    int ret;

    (void)skb;
    if (!info->attrs[MWAN_ATTR_QUERY_IFINDEX])
        return -EINVAL;
    ifindex = nla_get_u32(info->attrs[MWAN_ATTR_QUERY_IFINDEX]);
    ret = mwan_state_get_tunnel_state(ifindex, &generation, &sequence, &up);
    if (ret)
        return ret;

    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    reply_hdr = genlmsg_put_reply(reply, info, &mwan_genl_family, 0,
                                  MWAN_CMD_GET_TUNNEL_STATE);
    if (!reply_hdr) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }
    ret = nla_put_u32(reply, MWAN_ATTR_QUERY_IFINDEX, ifindex);
    if (!ret)
        ret = nla_put_u32(reply, MWAN_ATTR_CONFIG_GENERATION, generation);
    if (!ret)
        ret = nla_put_u32(reply, MWAN_ATTR_STATE_SEQUENCE, sequence);
    if (!ret)
        ret = nla_put_u8(reply, MWAN_ATTR_TUNNEL_STATE, up ? 1 : 0);
    if (ret) {
        genlmsg_cancel(reply, reply_hdr);
        nlmsg_free(reply);
        return ret;
    }
    genlmsg_end(reply, reply_hdr);
    return genlmsg_reply(reply, info);
}

/* Read-only runtime query. Discovery owns the peer tuple; userspace supplies
 * only the data-tunnel ifindex so no database value can become authoritative
 * for liveness/failover. */
static int mwan_genl_get_tunnel_peers(struct sk_buff *skb,
                                      struct genl_info *info)
{
    struct mwan_config *cfg;
    struct mwan_tunnel *tun = NULL;
    struct sk_buff *reply;
    void *reply_hdr;
    __be32 peer_tunnel_ip = 0;
    u32 ifindex;
    bool resolved = false;
    u32 i;
    int ret;

    (void)skb;
    if (!info->attrs[MWAN_ATTR_QUERY_IFINDEX])
        return -EINVAL;
    ifindex = nla_get_u32(info->attrs[MWAN_ATTR_QUERY_IFINDEX]);
    if (ifindex == 0)
        return -EINVAL;

    rcu_read_lock();
    cfg = rcu_dereference(g_mwan_cfg);
    if (cfg) {
        for (i = 0; i < cfg->num_tunnels; i++) {
            if (cfg->tunnels[i].ifindex == ifindex ||
                cfg->tunnels[i].configured_ifindex == ifindex) {
                tun = &cfg->tunnels[i];
                resolved = mwan_mac_get_peer_tunnel_ip(
                    tun, &peer_tunnel_ip);
                break;
            }
        }
    }
    rcu_read_unlock();
    if (!tun)
        return -ENOENT;

    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    reply_hdr = genlmsg_put_reply(reply, info, &mwan_genl_family, 0,
                                  MWAN_CMD_GET_TUNNEL_PEERS);
    if (!reply_hdr) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }

    ret = nla_put_u32(reply, MWAN_ATTR_QUERY_IFINDEX, ifindex);
    if (!ret)
        ret = nla_put_u8(reply, MWAN_ATTR_PEER_RESOLVED,
                         resolved ? 1 : 0);
    if (!ret && resolved)
        ret = nla_put(reply, MWAN_ATTR_PEER_TUNNEL_IP,
                      sizeof(peer_tunnel_ip), &peer_tunnel_ip);
    if (ret) {
        genlmsg_cancel(reply, reply_hdr);
        nlmsg_free(reply);
        return ret;
    }

    genlmsg_end(reply, reply_hdr);
    return genlmsg_reply(reply, info);
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
    {
        .cmd    = MWAN_CMD_GET_TUNNEL_PEERS,
        .flags  = 0,
        .policy = mwan_genl_policy,
        .doit   = mwan_genl_get_tunnel_peers,
        .dumpit = NULL,
    },
    {
        .cmd    = MWAN_CMD_SET_TUNNEL_STATE,
        .flags  = 0,
        .policy = mwan_genl_policy,
        .doit   = mwan_genl_set_tunnel_state,
        .dumpit = NULL,
    },
    {
        .cmd    = MWAN_CMD_GET_TUNNEL_STATE,
        .flags  = 0,
        .policy = mwan_genl_policy,
        .doit   = mwan_genl_get_tunnel_state,
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
