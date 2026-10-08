#include "provision_reconcile.h"

#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

struct provision_runtime {
    pthread_mutex_t lock;
    int profile_id;
    bool accepted;
    bool key_ready;
    enum provision_state state;
    size_t desired_count;
    char desired_ifnames[MAX_SDWAN_TUNS][IFNAMSIZ];
    bool acknowledged[MAX_SDWAN_TUNS];
    bool transaction_valid;
    enum provision_transaction_kind transaction_kind;
    app_context_t transaction_candidate;
    uint64_t transaction_generation;
    uint64_t transaction_previous_generation;
};

static struct provision_runtime provision = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = PROVISION_UNPROVISIONED,
};

void provision_transaction_stage(enum provision_transaction_kind kind,
                                 const app_context_t *candidate,
                                 uint64_t generation,
                                 uint64_t previous_generation)
{
    pthread_mutex_lock(&provision.lock);
    provision.transaction_valid = candidate && kind != PROVISION_TX_NONE &&
                                  generation != 0;
    provision.transaction_kind = provision.transaction_valid ? kind :
                                                            PROVISION_TX_NONE;
    if (candidate)
        provision.transaction_candidate = *candidate;
    else
        memset(&provision.transaction_candidate, 0,
               sizeof(provision.transaction_candidate));
    provision.transaction_generation = provision.transaction_valid ?
        generation : 0;
    provision.transaction_previous_generation = provision.transaction_valid ?
        previous_generation : 0;
    pthread_mutex_unlock(&provision.lock);
}

bool provision_transaction_snapshot(int profile_id,
                                    app_context_t *candidate,
                                    enum provision_transaction_kind *kind,
                                    uint64_t *generation,
                                    uint64_t *previous_generation)
{
    bool found;

    pthread_mutex_lock(&provision.lock);
    found = provision.transaction_valid &&
            (profile_id <= 0 ||
             provision.transaction_candidate.cfg.node_id == profile_id);
    if (found) {
        if (candidate)
            *candidate = provision.transaction_candidate;
        if (kind)
            *kind = provision.transaction_kind;
        if (generation)
            *generation = provision.transaction_generation;
        if (previous_generation)
            *previous_generation =
                provision.transaction_previous_generation;
    }
    pthread_mutex_unlock(&provision.lock);
    return found;
}

bool provision_transaction_any(void)
{
    bool active;

    pthread_mutex_lock(&provision.lock);
    active = provision.transaction_valid;
    pthread_mutex_unlock(&provision.lock);
    return active;
}

int provision_transaction_update(const app_context_t *candidate,
                                 uint64_t generation)
{
    int ret = 0;

    if (!candidate || !generation)
        return -EINVAL;
    pthread_mutex_lock(&provision.lock);
    if (!provision.transaction_valid ||
        provision.transaction_generation != generation ||
        provision.transaction_candidate.cfg.node_id !=
            candidate->cfg.node_id) {
        ret = -ESTALE;
    } else {
        provision.transaction_candidate = *candidate;
    }
    pthread_mutex_unlock(&provision.lock);
    return ret;
}

int provision_transaction_replace_full_apply(const app_context_t *candidate,
                                             uint64_t expected_generation,
                                             uint64_t new_generation)
{
    int ret = 0;

    if (!candidate || !expected_generation || !new_generation)
        return -EINVAL;

    pthread_mutex_lock(&provision.lock);
    if (!provision.transaction_valid ||
        provision.transaction_kind != PROVISION_TX_FULL_APPLY ||
        provision.transaction_generation != expected_generation ||
        provision.transaction_candidate.cfg.node_id !=
            candidate->cfg.node_id) {
        ret = -ESTALE;
    } else {
        /* Keep transaction_previous_generation unchanged. It identifies the
         * ACTIVE generation that predates the whole full-apply sequence. */
        provision.transaction_candidate = *candidate;
        provision.transaction_generation = new_generation;
    }
    pthread_mutex_unlock(&provision.lock);
    return ret;
}

static void transaction_clear_locked(void)
{
    provision.transaction_valid = false;
    provision.transaction_kind = PROVISION_TX_NONE;
    memset(&provision.transaction_candidate, 0,
           sizeof(provision.transaction_candidate));
    provision.transaction_generation = 0;
    provision.transaction_previous_generation = 0;
}

void provision_transaction_finish(uint64_t generation)
{
    pthread_mutex_lock(&provision.lock);
    if (provision.transaction_valid &&
        provision.transaction_generation == generation)
        transaction_clear_locked();
    pthread_mutex_unlock(&provision.lock);
}

void provision_transaction_cancel(uint64_t generation)
{
    provision_transaction_finish(generation);
}

static size_t count_missing_locked(void)
{
    size_t missing = 0;
    size_t i;

    for (i = 0; i < provision.desired_count; i++) {
        if (!provision.acknowledged[i] ||
            !if_nametoindex(provision.desired_ifnames[i]))
            missing++;
    }
    return missing;
}

static void refresh_state_locked(void)
{
    if (!provision.accepted) {
        provision.state = PROVISION_UNPROVISIONED;
    } else if (count_missing_locked() != 0) {
        provision.state = PROVISION_WAIT_TUNNEL;
    } else if (!provision.key_ready) {
        provision.state = PROVISION_WAIT_KEY;
    } else {
        provision.state = PROVISION_READY;
    }
}

void provision_reconcile_accept(const app_context_t *desired)
{
    char old_ifnames[MAX_SDWAN_TUNS][IFNAMSIZ];
    bool old_acknowledged[MAX_SDWAN_TUNS];
    size_t old_count;
    int old_profile;
    bool old_accepted;
    size_t i;
    size_t j;

    pthread_mutex_lock(&provision.lock);
    memcpy(old_ifnames, provision.desired_ifnames, sizeof(old_ifnames));
    memcpy(old_acknowledged, provision.acknowledged,
           sizeof(old_acknowledged));
    old_count = provision.desired_count;
    old_profile = provision.profile_id;
    old_accepted = provision.accepted;
    memset(provision.desired_ifnames, 0, sizeof(provision.desired_ifnames));
    memset(provision.acknowledged, 0, sizeof(provision.acknowledged));
    provision.profile_id = desired ? desired->cfg.node_id : 0;
    provision.accepted = desired && desired->cfg.node_id > 0;
    provision.key_ready = desired && desired->cfg.encrypt.key_len == 32;
    provision.desired_count = desired ? desired->cfg.sdwan_tun_count : 0;
    if (provision.desired_count > MAX_SDWAN_TUNS)
        provision.desired_count = MAX_SDWAN_TUNS;
    for (i = 0; desired && i < provision.desired_count; i++) {
        bool known = false;

        snprintf(provision.desired_ifnames[i], IFNAMSIZ, "%s",
                 desired->cfg.sdwan_tuns[i].tunnel_ifname);
        if (!old_accepted || old_profile != provision.profile_id) {
            provision.acknowledged[i] =
                if_nametoindex(provision.desired_ifnames[i]) != 0;
            continue;
        }
        for (j = 0; j < old_count; j++) {
            if (strncmp(old_ifnames[j], provision.desired_ifnames[i],
                        IFNAMSIZ) == 0) {
                known = true;
                provision.acknowledged[i] = old_acknowledged[j];
                break;
            }
        }
        if (!known)
            provision.acknowledged[i] =
                if_nametoindex(provision.desired_ifnames[i]) != 0;
    }
    refresh_state_locked();
    pthread_mutex_unlock(&provision.lock);
}

void provision_reconcile_clear(void)
{
    pthread_mutex_lock(&provision.lock);
    provision.profile_id = 0;
    provision.accepted = false;
    provision.key_ready = false;
    provision.desired_count = 0;
    memset(provision.desired_ifnames, 0, sizeof(provision.desired_ifnames));
    memset(provision.acknowledged, 0, sizeof(provision.acknowledged));
    provision.state = PROVISION_UNPROVISIONED;
    transaction_clear_locked();
    pthread_mutex_unlock(&provision.lock);
}

void provision_reconcile_note_key(int profile_id, bool ready)
{
    pthread_mutex_lock(&provision.lock);
    if (provision.accepted && provision.profile_id == profile_id) {
        provision.key_ready = ready;
        refresh_state_locked();
    }
    pthread_mutex_unlock(&provision.lock);
}

int provision_reconcile_validate_profile(int profile_id)
{
    int ret = 0;

    pthread_mutex_lock(&provision.lock);
    if (!provision.accepted)
        ret = -EAGAIN;
    else if (provision.profile_id != profile_id)
        ret = -EXDEV;
    pthread_mutex_unlock(&provision.lock);
    return ret;
}

bool provision_reconcile_tunnel_desired(int profile_id, const char *ifname)
{
    bool found = false;
    size_t i;

    if (!ifname)
        return false;
    pthread_mutex_lock(&provision.lock);
    if (provision.accepted && provision.profile_id == profile_id) {
        for (i = 0; i < provision.desired_count; i++) {
            if (strncmp(provision.desired_ifnames[i], ifname,
                        IFNAMSIZ) == 0) {
                found = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&provision.lock);
    return found;
}

bool provision_reconcile_tunnel_acknowledged(int profile_id,
                                             const char *ifname)
{
    bool acknowledged = false;
    size_t i;

    if (!ifname)
        return false;
    pthread_mutex_lock(&provision.lock);
    if (provision.accepted && provision.profile_id == profile_id) {
        for (i = 0; i < provision.desired_count; i++) {
            if (strncmp(provision.desired_ifnames[i], ifname,
                        IFNAMSIZ) == 0) {
                acknowledged = provision.acknowledged[i];
                break;
            }
        }
    }
    pthread_mutex_unlock(&provision.lock);
    return acknowledged;
}

int provision_reconcile_ack_tunnel(int profile_id, const char *ifname)
{
    size_t i;
    int ret = -ENOENT;

    if (!ifname || !if_nametoindex(ifname))
        return -ENODEV;
    pthread_mutex_lock(&provision.lock);
    if (!provision.accepted) {
        ret = -EAGAIN;
        goto out;
    }
    if (provision.profile_id != profile_id) {
        ret = -EXDEV;
        goto out;
    }
    for (i = 0; i < provision.desired_count; i++) {
        if (strncmp(provision.desired_ifnames[i], ifname, IFNAMSIZ) == 0) {
            provision.acknowledged[i] = true;
            refresh_state_locked();
            ret = 0;
            goto out;
        }
    }
    if (provision.desired_count >= MAX_SDWAN_TUNS) {
        ret = -ENOSPC;
        goto out;
    }
    snprintf(provision.desired_ifnames[provision.desired_count], IFNAMSIZ,
             "%s", ifname);
    provision.acknowledged[provision.desired_count] = true;
    provision.desired_count++;
    refresh_state_locked();
    ret = 0;
out:
    pthread_mutex_unlock(&provision.lock);
    return ret;
}

void provision_reconcile_rollback_tunnel(int profile_id, const char *ifname,
                                         bool remove_entry)
{
    size_t i;

    if (!ifname)
        return;
    pthread_mutex_lock(&provision.lock);
    if (!provision.accepted || provision.profile_id != profile_id)
        goto out;
    for (i = 0; i < provision.desired_count; i++) {
        if (strncmp(provision.desired_ifnames[i], ifname, IFNAMSIZ) != 0)
            continue;
        if (remove_entry) {
            size_t remaining = provision.desired_count - i - 1;

            if (remaining) {
                memmove(&provision.desired_ifnames[i],
                        &provision.desired_ifnames[i + 1],
                        remaining * sizeof(provision.desired_ifnames[0]));
                memmove(&provision.acknowledged[i],
                        &provision.acknowledged[i + 1],
                        remaining * sizeof(provision.acknowledged[0]));
            }
            provision.desired_count--;
            memset(provision.desired_ifnames[provision.desired_count], 0,
                   IFNAMSIZ);
            provision.acknowledged[provision.desired_count] = false;
        } else {
            provision.acknowledged[i] = false;
        }
        refresh_state_locked();
        break;
    }
out:
    pthread_mutex_unlock(&provision.lock);
}

int provision_reconcile_build_present(const app_context_t *desired,
                                      app_context_t *present,
                                      size_t *missing_count)
{
    size_t missing = 0;
    size_t i;

    if (!desired || !present)
        return -EINVAL;
    *present = *desired;
    present->cfg.sdwan_tun_count = 0;
    memset(present->cfg.sdwan_tuns, 0, sizeof(present->cfg.sdwan_tuns));
    pthread_mutex_lock(&provision.lock);
    for (i = 0; i < desired->cfg.sdwan_tun_count; i++) {
        const sdwan_tun_cfg_t *source = &desired->cfg.sdwan_tuns[i];
        bool acknowledged = false;
        bool known = false;
        size_t j;

        if (!provision.accepted ||
            provision.profile_id != desired->cfg.node_id) {
            acknowledged = if_nametoindex(source->tunnel_ifname) != 0;
        } else {
            for (j = 0; j < provision.desired_count; j++) {
                if (strncmp(provision.desired_ifnames[j],
                            source->tunnel_ifname, IFNAMSIZ) == 0) {
                    known = true;
                    acknowledged = provision.acknowledged[j];
                    break;
                }
            }
            /* An unmatched entry comes from a new -id desired snapshot.
             * Existing entries remain event-gated, while a fresh profile
             * row may be acknowledged by that -id operation itself. */
            if (!known)
                acknowledged =
                    if_nametoindex(source->tunnel_ifname) != 0;
        }

        if (!acknowledged || !if_nametoindex(source->tunnel_ifname)) {
            missing++;
            continue;
        }
        present->cfg.sdwan_tuns[present->cfg.sdwan_tun_count++] = *source;
    }
    pthread_mutex_unlock(&provision.lock);
    if (missing_count)
        *missing_count = missing;
    return present->cfg.sdwan_tun_count ? 0 : -EAGAIN;
}

enum provision_state provision_reconcile_state(void)
{
    enum provision_state state;

    pthread_mutex_lock(&provision.lock);
    refresh_state_locked();
    state = provision.state;
    pthread_mutex_unlock(&provision.lock);
    return state;
}
