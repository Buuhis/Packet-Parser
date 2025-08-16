#include "../../util/inc/logger.h"

static FILE *log_file = NULL;

int init_logger(const char *filename) {
    log_file = fopen(filename, "a"); 
    if (!log_file) {
        perror("fopen");
        return -1;
    }
    return 0;
}

void log_message(const char *fmt, ...) {
    va_list args;

    // Output to console (stdout) - immediate visibility
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    // Output to log file if it's open
    if (log_file) {
        va_start(args, fmt);
        vfprintf(log_file, fmt, args);  // Write formatted output to file
        va_end(args);
        fflush(log_file);  // Force immediate write to disk for real-time monitoring
    }
}

void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

