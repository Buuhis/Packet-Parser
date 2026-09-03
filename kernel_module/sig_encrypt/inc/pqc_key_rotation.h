#ifndef PQC_KEY_ROTATION_H
#define PQC_KEY_ROTATION_H

#include <stdbool.h>
#include <stdint.h>

#define PQC_REKEY_KEY_SIZE 32
#define PQC_REKEY_FINGERPRINT_SIZE 32
#define PQC_REKEY_DRAIN_MS 60000ULL
#define PQC_REKEY_NEGOTIATION_TIMEOUT_MS 15000ULL

typedef enum {
    PQC_REKEY_STABLE = 0,
    PQC_REKEY_NEXT_STAGED,
    PQC_REKEY_COMMITTING,
    PQC_REKEY_ACTIVE_WITH_PREV,
} pqc_rekey_state_t;

typedef struct {
    pqc_rekey_state_t state;
    uint64_t epoch;
    uint64_t started_ms;
    uint64_t activated_ms;
    uint8_t next_id;
    uint8_t previous_id;
    uint8_t fingerprint[PQC_REKEY_FINGERPRINT_SIZE];
    bool peer_committed;
} pqc_key_rotation_t;

void pqc_key_rotation_init(pqc_key_rotation_t *rotation);
bool pqc_key_rotation_in_progress(const pqc_key_rotation_t *rotation);
uint8_t pqc_key_rotation_choose_id(uint8_t current_id, uint8_t previous_id,
                                   const uint8_t fingerprint[32]);
int pqc_key_rotation_stage(pqc_key_rotation_t *rotation, int profile_id,
                           uint64_t epoch, uint8_t next_id,
                           const uint8_t next_key[32],
                           const uint8_t fingerprint[32],
                           uint8_t keys[3][32], uint8_t key_ids[3],
                           bool slots_valid[3], uint64_t now_ms);
int pqc_key_rotation_activate(pqc_key_rotation_t *rotation, int profile_id,
                              uint8_t keys[3][32], uint8_t key_ids[3],
                              bool slots_valid[3], uint8_t encrypt_key[32],
                              uint8_t decrypt_key[32], uint64_t now_ms);
void pqc_key_rotation_mark_peer_committed(pqc_key_rotation_t *rotation,
                                          uint64_t epoch, uint8_t key_id,
                                          const uint8_t fingerprint[32]);
int pqc_key_rotation_abort(pqc_key_rotation_t *rotation, int profile_id,
                           uint8_t keys[3][32], uint8_t key_ids[3],
                           bool slots_valid[3]);
int pqc_key_rotation_maybe_retire(pqc_key_rotation_t *rotation,
                                  int profile_id, uint8_t keys[3][32],
                                  uint8_t key_ids[3],
                                  bool slots_valid[3], uint64_t now_ms);

#endif /* PQC_KEY_ROTATION_H */
