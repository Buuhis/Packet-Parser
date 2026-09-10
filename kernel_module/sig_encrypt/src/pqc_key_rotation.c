#include "../inc/pqc_key_rotation.h"
#include "../inc/pqc_handshake.h"
#include "../../src/kernel_sync.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

void pqc_key_rotation_init(pqc_key_rotation_t *rotation)
{
    if (rotation)
        memset(rotation, 0, sizeof(*rotation));
}

bool pqc_key_rotation_in_progress(const pqc_key_rotation_t *rotation)
{
    return rotation && rotation->state != PQC_REKEY_STABLE &&
           rotation->state != PQC_REKEY_ACTIVE_WITH_PREV;
}

uint8_t pqc_key_rotation_choose_id(uint8_t current_id, uint8_t previous_id,
                                   const uint8_t fingerprint[32])
{
    unsigned int i;

    if (!fingerprint)
        return 0;
    for (i = 0; i < 32; i++) {
        uint8_t candidate = fingerprint[i];

        if (candidate && candidate != current_id &&
            candidate != previous_id)
            return candidate;
    }
    for (i = 1; i <= 255; i++) {
        if ((uint8_t)i != current_id && (uint8_t)i != previous_id)
            return (uint8_t)i;
    }
    return 0;
}

int pqc_key_rotation_stage(pqc_key_rotation_t *rotation, int profile_id,
                           uint64_t epoch, uint8_t next_id,
                           const uint8_t next_key[32],
                           const uint8_t fingerprint[32],
                           uint8_t keys[3][32], uint8_t key_ids[3],
                           bool slots_valid[3], uint64_t now_ms)
{
    int ret;

    if (!rotation || profile_id <= 0 || !epoch || !next_id || !next_key ||
        !fingerprint || !keys || !key_ids || !slots_valid ||
        !slots_valid[KEY_SLOT_CURRENT])
        return -EINVAL;
    if (rotation->epoch == epoch &&
        rotation->state >= PQC_REKEY_NEXT_STAGED &&
        rotation->next_id == next_id &&
        memcmp(rotation->fingerprint, fingerprint, 32) == 0)
        return 0;
    if (pqc_key_rotation_in_progress(rotation) ||
        slots_valid[KEY_SLOT_NEXT])
        return -EBUSY;

    /* A full recovery handshake from the legacy path may have installed a
     * PREV slot with epoch 0.  By the time scheduled rotation runs, that key
     * is at least one full rotation interval old.  Retire it through the
     * same queue-safe kernel path before staging a new transaction. */
    if (slots_valid[KEY_SLOT_PREV]) {
        ret = kernel_sync_retire_pqc_key(
            profile_id, 0, key_ids[KEY_SLOT_PREV]);
        if (ret)
            return ret;
        memset(keys[KEY_SLOT_PREV], 0, 32);
        key_ids[KEY_SLOT_PREV] = 0;
        slots_valid[KEY_SLOT_PREV] = false;
    }

    ret = kernel_sync_stage_pqc_key(profile_id, epoch, next_id, next_key);
    if (ret)
        return ret;
    memcpy(keys[KEY_SLOT_NEXT], next_key, 32);
    key_ids[KEY_SLOT_NEXT] = next_id;
    slots_valid[KEY_SLOT_NEXT] = true;
    rotation->state = PQC_REKEY_NEXT_STAGED;
    rotation->epoch = epoch;
    rotation->started_ms = now_ms;
    rotation->next_id = next_id;
    rotation->previous_id = key_ids[KEY_SLOT_CURRENT];
    memcpy(rotation->fingerprint, fingerprint, 32);
    rotation->peer_committed = false;
    fprintf(stderr,
            "[PQC-REKEY] Profile %d NEXT staged epoch=%llu current=%u next=%u.\n",
            profile_id, (unsigned long long)epoch,
            key_ids[KEY_SLOT_CURRENT], next_id);
    return 0;
}

int pqc_key_rotation_activate(pqc_key_rotation_t *rotation, int profile_id,
                              uint8_t keys[3][32], uint8_t key_ids[3],
                              bool slots_valid[3], uint8_t encrypt_key[32],
                              uint8_t decrypt_key[32], uint64_t now_ms)
{
    int ret;

    if (!rotation || profile_id <= 0 || !keys || !key_ids || !slots_valid ||
        !encrypt_key || !decrypt_key)
        return -EINVAL;
    if (rotation->state == PQC_REKEY_ACTIVE_WITH_PREV)
        return 0;
    if (
        rotation->state < PQC_REKEY_NEXT_STAGED ||
        !slots_valid[KEY_SLOT_CURRENT] || !slots_valid[KEY_SLOT_NEXT] ||
        key_ids[KEY_SLOT_NEXT] != rotation->next_id)
        return -EINVAL;

    ret = kernel_sync_activate_pqc_key(profile_id, rotation->epoch,
                                       rotation->next_id);
    if (ret)
        return ret;
    memcpy(keys[KEY_SLOT_PREV], keys[KEY_SLOT_CURRENT], 32);
    key_ids[KEY_SLOT_PREV] = key_ids[KEY_SLOT_CURRENT];
    slots_valid[KEY_SLOT_PREV] = true;
    memcpy(keys[KEY_SLOT_CURRENT], keys[KEY_SLOT_NEXT], 32);
    key_ids[KEY_SLOT_CURRENT] = key_ids[KEY_SLOT_NEXT];
    slots_valid[KEY_SLOT_CURRENT] = true;
    memset(keys[KEY_SLOT_NEXT], 0, 32);
    key_ids[KEY_SLOT_NEXT] = 0;
    slots_valid[KEY_SLOT_NEXT] = false;
    memcpy(encrypt_key, keys[KEY_SLOT_CURRENT], 32);
    memcpy(decrypt_key, keys[KEY_SLOT_CURRENT], 32);
    rotation->state = PQC_REKEY_ACTIVE_WITH_PREV;
    rotation->activated_ms = now_ms;
    fprintf(stderr,
            "[PQC-REKEY] Profile %d COMMIT epoch=%llu current=%u prev=%u.\n",
            profile_id, (unsigned long long)rotation->epoch,
            key_ids[KEY_SLOT_CURRENT], key_ids[KEY_SLOT_PREV]);
    return 0;
}

void pqc_key_rotation_mark_peer_committed(pqc_key_rotation_t *rotation,
                                          uint64_t epoch, uint8_t key_id,
                                          const uint8_t fingerprint[32])
{
    if (!rotation || rotation->epoch != epoch ||
        rotation->next_id != key_id || !fingerprint ||
        memcmp(rotation->fingerprint, fingerprint, 32) != 0)
        return;
    rotation->peer_committed = true;
}

int pqc_key_rotation_abort(pqc_key_rotation_t *rotation, int profile_id,
                           uint8_t keys[3][32], uint8_t key_ids[3],
                           bool slots_valid[3])
{
    int ret;

    if (!rotation || profile_id <= 0 || !keys || !key_ids || !slots_valid)
        return -EINVAL;
    if (rotation->state == PQC_REKEY_STABLE)
        return 0;
    if (rotation->state == PQC_REKEY_ACTIVE_WITH_PREV)
        return -EALREADY;
    ret = kernel_sync_abort_pqc_key(profile_id, rotation->epoch,
                                    rotation->next_id);
    if (ret && ret != -ENOENT && ret != -ESTALE)
        return ret;
    memset(keys[KEY_SLOT_NEXT], 0, 32);
    key_ids[KEY_SLOT_NEXT] = 0;
    slots_valid[KEY_SLOT_NEXT] = false;
    fprintf(stderr,
            "[PQC-REKEY] Profile %d ABORT epoch=%llu; CURRENT retained.\n",
            profile_id, (unsigned long long)rotation->epoch);
    pqc_key_rotation_init(rotation);
    return 0;
}

int pqc_key_rotation_maybe_retire(pqc_key_rotation_t *rotation,
                                  int profile_id, uint8_t keys[3][32],
                                  uint8_t key_ids[3],
                                  bool slots_valid[3], uint64_t now_ms)
{
    uint8_t previous_id;
    int ret;

    if (!rotation || profile_id <= 0 || !keys || !key_ids || !slots_valid)
        return -EINVAL;
    if (rotation->state != PQC_REKEY_ACTIVE_WITH_PREV ||
        !rotation->peer_committed || !rotation->activated_ms ||
        now_ms - rotation->activated_ms < PQC_REKEY_DRAIN_MS)
        return 1;
    if (!slots_valid[KEY_SLOT_PREV]) {
        pqc_key_rotation_init(rotation);
        return 0;
    }
    previous_id = key_ids[KEY_SLOT_PREV];
    ret = kernel_sync_retire_pqc_key(profile_id, rotation->epoch,
                                     previous_id);
    if (ret)
        return ret;
    memset(keys[KEY_SLOT_PREV], 0, 32);
    key_ids[KEY_SLOT_PREV] = 0;
    slots_valid[KEY_SLOT_PREV] = false;
    fprintf(stderr,
            "[PQC-REKEY] Profile %d PREV retired epoch=%llu current=%u.\n",
            profile_id, (unsigned long long)rotation->epoch,
            key_ids[KEY_SLOT_CURRENT]);
    pqc_key_rotation_init(rotation);
    return 0;
}
