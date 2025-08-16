#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>

/**
 * @brief Initialize the logging system
 * 
 * Opens the specified file for logging output. The file is opened in append mode
 * so that multiple runs of the program will accumulate logs rather than overwrite.
 * 
 * @param filename Name of the log file to create/open
 * @return 0 on success, -1 on failure (check errno for details)
 */
int init_logger(const char *filename);

/**
 * @brief Log a formatted message to both console and file
 * 
 * This function works like printf() but outputs to both the console and the log file.
 * The message is automatically flushed to ensure real-time visibility during packet capture.
 * 
 * @param fmt Format string (same syntax as printf)
 * @param ... Variable arguments matching the format string
 */
void log_message(const char *fmt, ...);

/**
 * @brief Close the logging system and cleanup resources
 * 
 * Closes the log file and frees associated resources. Should be called
 * before the program exits to ensure all buffered data is written.
 */
void close_logger();

#endif // LOGGER_H
