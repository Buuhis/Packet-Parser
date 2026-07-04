#include "../inc/pqc_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdbool.h>

#define LOG_DIR "/var/log/NE"
#define LOG_FILE "/var/log/NE/authen_pqc.log"
#define MAX_LOG_LINES 5000
#define MAX_LINE_LEN 512

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void get_iso8601_time(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S%z", tm_info);
    
    // Format timezone offset correctly with colon (e.g., +0700 to +07:00)
    size_t l = strlen(buf);
    if (l >= 5 && (buf[l-5] == '+' || buf[l-5] == '-')) {
        char min[3];
        strcpy(min, buf + l - 2);
        buf[l-2] = ':';
        strcpy(buf + l - 1, min);
    }
}

void sig_pqc_write_log(int policy_id, const char *key_id, const char *level, const char *status, const char *msg) {
    pthread_mutex_lock(&g_log_mutex);

    // 1. Ensure log directory exists
    mkdir(LOG_DIR, 0755);

    // 2. Format current time
    char time_str[64];
    memset(time_str, 0, sizeof(time_str));
    get_iso8601_time(time_str, sizeof(time_str));

    // 3. Read and parse existing log entries (applying retention and limit rules)
    char **saved_lines = malloc(MAX_LOG_LINES * sizeof(char *));
    int saved_count = 0;
    if (saved_lines == NULL) {
        pthread_mutex_unlock(&g_log_mutex);
        return;
    }

    FILE *fp = fopen(LOG_FILE, "r");
    if (fp) {
        char line_buf[MAX_LINE_LEN];
        time_t now = time(NULL);
        
        while (fgets(line_buf, sizeof(line_buf), fp) && saved_count < MAX_LOG_LINES) {
            // Check timestamp for 15-day expiration
            int yr, mo, dy, hr, mi, se;
            char tz_sign;
            int tz_hr, tz_mi;
            bool keep = true;

            if (sscanf(line_buf, "%d-%d-%dT%d:%d:%d%c%d:%d", 
                       &yr, &mo, &dy, &hr, &mi, &se, 
                       &tz_sign, &tz_hr, &tz_mi) == 9) {
                struct tm t;
                memset(&t, 0, sizeof(t));
                t.tm_year = yr - 1900;
                t.tm_mon = mo - 1;
                t.tm_mday = dy;
                t.tm_hour = hr;
                t.tm_min = mi;
                t.tm_sec = se;
                t.tm_isdst = -1;

                time_t log_time = mktime(&t);
                if (log_time != (time_t)-1) {
                    if (difftime(now, log_time) > 15.0 * 86400.0) {
                        keep = false; // Expired
                    }
                }
            }

            if (!keep) {
                // Optimization: Since logs are prepended, the first expired log entry 
                // means all subsequent lines are also expired. Stop reading.
                break;
            }

            // Remove trailing newlines
            line_buf[strcspn(line_buf, "\r\n")] = '\0';
            if (strlen(line_buf) > 0) {
                saved_lines[saved_count++] = strdup(line_buf);
            }
        }
        fclose(fp);
    }

    // 4. Write back new entry at the top, followed by valid saved entries
    fp = fopen(LOG_FILE, "w");
    if (fp) {
        // Write newest entry
        fprintf(fp, "%s [%s] [Policy: %d] [Key_id: %s] Status: %s | MSG: %s\n", 
                time_str, level, policy_id, key_id ? key_id : "N/A", status, msg);
        
        // Write kept old entries (limit to MAX_LOG_LINES - 1 to account for the new one)
        for (int i = 0; i < saved_count && i < (MAX_LOG_LINES - 1); i++) {
            fprintf(fp, "%s\n", saved_lines[i]);
        }
        fclose(fp);
    }

    // 5. Clean up allocated memory
    for (int i = 0; i < saved_count; i++) {
        free(saved_lines[i]);
    }
    free(saved_lines);

    pthread_mutex_unlock(&g_log_mutex);
}
