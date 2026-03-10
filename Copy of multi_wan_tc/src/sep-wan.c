#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -id <node_id>\n", prog);
    exit(1);
}

int main(int argc, char **argv) {
    const char *node_id = NULL;
    const char *env_sock = getenv("MWAN_SOCKET_PATH");
    const char *socket_path = env_sock ? env_sock : "/var/run/sep-wan.sock";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            node_id = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        }
    }

    if (!node_id) {
        usage(argv[0]);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        fprintf(stderr, "Is mwanc daemon running? (socket: %s)\n", socket_path);
        close(fd);
        return 1;
    }

    if (send(fd, node_id, strlen(node_id), 0) < 0) {
        perror("send");
        close(fd);
        return 1;
    }

    printf("Command sent successfully! Node ID: %s\n", node_id);
    close(fd);
    return 0;
}
