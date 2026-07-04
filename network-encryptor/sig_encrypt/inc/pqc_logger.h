#ifndef PQC_LOGGER_H
#define PQC_LOGGER_H

#define PQC_LOG_LEVEL_INFO  "INFO"
#define PQC_LOG_LEVEL_ERROR "ERROR"

#define PQC_LOG_STATUS_SUCCESS         "SUCCESS"
#define PQC_LOG_STATUS_FAILED          "FAILED"
#define PQC_LOG_STATUS_ROTATION_FAILED "ROTATION_FAILED"

// Thread-safe log writer.
// Formats log and writes it to the top of /var/log/NE/authen_pqc.log,
// keeping only up to 5,000 lines and pruning lines older than 15 days.
void sig_pqc_write_log(int policy_id, const char *key_id, const char *level, const char *status, const char *msg);

#endif // PQC_LOGGER_H
