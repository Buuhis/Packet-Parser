#ifndef CLI_HANDLER_H
#define CLI_HANDLER_H

#include "app_context.h"

/**
 * Parse CLI arguments and handle client-mode commands.
 * Returns:
 *   0  - Command handled successfully (exit with 0)
 *   1  - Command handled with error (exit with 1)
 *  -1  - Not a client command, proceed to daemon mode
 */
int cli_handle_client_args(int argc, char **argv, const char *socket_path);

/**
 * Process a single message received on the daemon's Unix socket.
 * Called from the daemon's accept() loop for each incoming client.
 *
 * @param client_fd   The connected client socket fd
 * @param buf         The raw message buffer (already trimmed)
 * @param running_ctx Pointer to the daemon's live running context
 */
void cli_handle_daemon_message(int client_fd, const char *buf, app_context_t *running_ctx);

#endif /* CLI_HANDLER_H */
