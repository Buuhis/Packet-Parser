#include "config_semantics.h"

#include "../kernel/mwan_proto.h"

#include <string.h>

static bool encrypt_equal(const encrypt_cfg_t *left,
                          const encrypt_cfg_t *right)
{
    if (left->enabled != right->enabled ||
        left->layer != right->layer ||
        left->type != right->type ||
        left->key_len != right->key_len ||
        memcmp(left->salt, right->salt, sizeof(left->salt)) != 0)
        return false;

    return left->key_len == 0 ||
           memcmp(left->key, right->key, left->key_len) == 0;
}

static bool tunnel_equal(const sdwan_tun_cfg_t *left,
                         const sdwan_tun_cfg_t *right)
{
    return strcmp(left->tunnel_ifname, right->tunnel_ifname) == 0 &&
           strcmp(left->physical_ifname, right->physical_ifname) == 0 &&
           strcmp(left->tunnel_ip, right->tunnel_ip) == 0 &&
           left->segment_id == right->segment_id &&
           left->weight == right->weight &&
           strcmp(left->latency_ip, right->latency_ip) == 0 &&
           left->latency == right->latency &&
           left->latency_enabled == right->latency_enabled &&
           strcmp(left->loss_ip, right->loss_ip) == 0 &&
           left->loss_percentage == right->loss_percentage &&
           left->loss_enabled == right->loss_enabled;
}

bool config_runtime_equal(const app_config_t *left,
                          const app_config_t *right)
{
    size_t i;

    if (!left || !right ||
        left->node_id != right->node_id ||
        left->sdwan_tun_count != right->sdwan_tun_count ||
        left->weight_enabled != right->weight_enabled ||
        left->latency_enabled != right->latency_enabled ||
        left->loss_enabled != right->loss_enabled ||
        left->latency_duration != right->latency_duration ||
        left->loss_duration != right->loss_duration ||
        !encrypt_equal(&left->encrypt, &right->encrypt))
        return false;

    for (i = 0; i < left->sdwan_tun_count; i++) {
        if (!tunnel_equal(&left->sdwan_tuns[i],
                          &right->sdwan_tuns[i]))
            return false;
    }
    return true;
}

bool config_kernel_equal(const app_config_t *left,
                         const app_config_t *right)
{
    size_t i;

    if (!left || !right ||
        left->node_id != right->node_id ||
        left->sdwan_tun_count != right->sdwan_tun_count ||
        !encrypt_equal(&left->encrypt, &right->encrypt))
        return false;

    for (i = 0; i < left->sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *left_tun = &left->sdwan_tuns[i];
        const sdwan_tun_cfg_t *right_tun = &right->sdwan_tuns[i];

        if (strcmp(left_tun->tunnel_ifname,
                   right_tun->tunnel_ifname) != 0 ||
            left_tun->weight != right_tun->weight)
            return false;
    }
    return true;
}

bool config_failover_equal(const app_config_t *left,
                           const app_config_t *right)
{
    size_t i;

    if (!left || !right ||
        left->node_id != right->node_id ||
        left->sdwan_tun_count != right->sdwan_tun_count)
        return false;

    for (i = 0; i < left->sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *left_tun = &left->sdwan_tuns[i];
        const sdwan_tun_cfg_t *right_tun = &right->sdwan_tuns[i];

        if (strcmp(left_tun->tunnel_ifname,
                   right_tun->tunnel_ifname) != 0 ||
            strcmp(left_tun->tunnel_ip, right_tun->tunnel_ip) != 0)
            return false;
    }
    return true;
}

bool config_pqc_policy_changed(const app_config_t *old_cfg,
                               const app_config_t *new_cfg)
{
    bool old_pqc;
    bool new_pqc;

    if (!old_cfg || !new_cfg)
        return true;

    old_pqc = old_cfg->encrypt.enabled &&
              old_cfg->encrypt.type == MWAN_CRYPT_PQC_GCM;
    new_pqc = new_cfg->encrypt.enabled &&
              new_cfg->encrypt.type == MWAN_CRYPT_PQC_GCM;

    if (!old_pqc && !new_pqc)
        return false;
    if (old_pqc != new_pqc)
        return true;

    /* The traffic key is runtime output from the handshake, not handshake
     * identity input. Only a policy transition requires lifecycle teardown. */
    return old_cfg->encrypt.layer != new_cfg->encrypt.layer;
}

static bool field_is(const char *field, const char *expected)
{
    return strcmp(field, expected) == 0;
}

static bool common_audit_field(const char *field)
{
    return field_is(field, "created_at") ||
           field_is(field, "created_by") ||
           field_is(field, "updated_at") ||
           field_is(field, "updated_by");
}

bool config_edit_field_is_metadata(const char *qualified_field)
{
    const char *field;

    if (!qualified_field)
        return false;

    if (strncmp(qualified_field, "sdwan_profiles.", 15) == 0) {
        field = qualified_field + 15;
        return field_is(field, "name") ||
               field_is(field, "description") ||
               common_audit_field(field);
    }
    if (strncmp(qualified_field, "sdwan_tunnels.", 14) == 0) {
        field = qualified_field + 14;
        return common_audit_field(field);
    }
    if (strncmp(qualified_field, "pqc_keys.", 9) == 0) {
        field = qualified_field + 9;
        /* status is not queried by the daemon; it is presentation/control
         * metadata in the current schema. */
        return field_is(field, "status") || common_audit_field(field);
    }
    if (strncmp(qualified_field, "pqc_exchange_tunnels.", 21) == 0) {
        field = qualified_field + 21;
        return common_audit_field(field);
    }
    return false;
}
