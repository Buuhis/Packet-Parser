#include "logger.h"
#include <stdarg.h>
#include <time.h>

static log_level_t g_level = LOG_INFO;

void log_set_level(log_level_t lvl) {
    g_level = lvl;
}

static const char *lvl_str(log_level_t lvl) {
    switch (lvl) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        default:        return "UNK";
    }
}

static void vlog_print(log_level_t lvl, const char *fmt, va_list ap) {
    if (lvl < g_level) return;

    time_t t = time(NULL);
    struct tm tmv;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
    localtime_r(&t, &tmv);
#else
    tmv = *localtime(&t);
#endif

    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    fprintf(stderr, "%s [%s] ", ts, lvl_str(lvl));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

void log_debug(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog_print(LOG_DEBUG, fmt, ap);
    va_end(ap);
}
void log_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog_print(LOG_INFO, fmt, ap);
    va_end(ap);
}
void log_warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog_print(LOG_WARN, fmt, ap);
    va_end(ap);
}
void log_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vlog_print(LOG_ERROR, fmt, ap);
    va_end(ap);
}
