#include "vault_db_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>

#define DEFAULT_ENV_PATH ".env"

static char g_vault_host[128] = "127.0.0.1";
static int g_vault_port = 8200;
static char g_vault_token[256] = "";
static int g_env_loaded = 0;

static void trim_val(char *str) {
    if (!str) return;
    char *end;
    while (*str == ' ' || *str == '\t' || *str == '"' || *str == '\'') str++;
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n' || *end == '"' || *end == '\'')) {
        *end = '\0';
        end--;
    }
}

static void parse_url(const char *url) {
    if (!url) return;
    if (strncmp(url, "http://", 7) == 0) url += 7;
    else if (strncmp(url, "https://", 8) == 0) url += 8;

    char hostport[128];
    strncpy(hostport, url, sizeof(hostport) - 1);
    hostport[sizeof(hostport) - 1] = '\0';

    char *slash = strchr(hostport, '/');
    if (slash) *slash = '\0';

    char *colon = strchr(hostport, ':');
    if (colon) {
        *colon = '\0';
        g_vault_port = atoi(colon + 1);
    } else {
        g_vault_port = 8200;
    }
    strncpy(g_vault_host, hostport, sizeof(g_vault_host) - 1);
    g_vault_host[sizeof(g_vault_host) - 1] = '\0';
}

static void load_env_vault_vars(void) {
    if (g_env_loaded) return;
    g_env_loaded = 1;

    const char *e_addr = getenv("VAULT_ADDR");
    const char *e_token = getenv("VAULT_TOKEN");

    if (e_addr) parse_url(e_addr);
    if (e_token) {
        strncpy(g_vault_token, e_token, sizeof(g_vault_token) - 1);
        g_vault_token[sizeof(g_vault_token) - 1] = '\0';
    }

    if (e_addr && e_token) return;

    FILE *fp = fopen(DEFAULT_ENV_PATH, "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\r' || *p == '\n') continue;

        if (strncmp(p, "export ", 7) == 0) p += 7;

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        char *val = eq + 1;

        trim_val(key);
        trim_val(val);

        if (strcmp(key, "VAULT_ADDR") == 0 && !e_addr) {
            parse_url(val);
        } else if (strcmp(key, "VAULT_TOKEN") == 0 && !e_token) {
            strncpy(g_vault_token, val, sizeof(g_vault_token) - 1);
            g_vault_token[sizeof(g_vault_token) - 1] = '\0';
        }
    }
    fclose(fp);
}

static int http_get_vault(const char *path, char *resp_buf, size_t max_resp) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[VAULT-DB-CLIENT] Socket creation error");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(g_vault_port);

    if (inet_pton(AF_INET, g_vault_host, &serv_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(g_vault_host);
        if (he) {
            memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
        } else {
            fprintf(stderr, "[VAULT-DB-CLIENT] Invalid host IP address: %s\n", g_vault_host);
            close(sockfd);
            return -1;
        }
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "[VAULT-DB-CLIENT] Connection to Vault failed (%s:%d)\n", g_vault_host, g_vault_port);
        close(sockfd);
        return -1;
    }

    char request[2048];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "User-Agent: sd-wan-vault-client/1.0\r\n"
             "Accept: */*\r\n"
             "X-Vault-Token: %s\r\n"
             "Connection: close\r\n\r\n",
             path, g_vault_host, g_vault_port, g_vault_token);

    send(sockfd, request, strlen(request), 0);

    int total_bytes = 0;
    int bytes_read;
    while ((bytes_read = recv(sockfd, resp_buf + total_bytes, max_resp - total_bytes - 1, 0)) > 0) {
        total_bytes += bytes_read;
        if ((size_t)total_bytes >= max_resp - 1) break;
    }
    resp_buf[total_bytes] = '\0';

    close(sockfd);
    return total_bytes;
}

static int extract_json_kv(const char *json, const char *key, char *out_val, size_t max_len) {
    if (!json || !key || !out_val) return 0;
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", key);

    const char *pos = strstr(json, search_pattern);
    if (!pos) return 0;

    pos += strlen(search_pattern);
    while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;

    if (*pos == '"') {
        pos++;
        const char *end = strchr(pos, '"');
        if (end) {
            size_t len = end - pos;
            if (len >= max_len) len = max_len - 1;
            strncpy(out_val, pos, len);
            out_val[len] = '\0';
            return 1;
        }
    } else {
        const char *end = pos;
        while (*end && *end != ',' && *end != '}' && *end != ']' && *end != '\r' && *end != '\n') end++;
        size_t len = end - pos;
        if (len >= max_len) len = max_len - 1;
        strncpy(out_val, pos, len);
        out_val[len] = '\0';
        trim_val(out_val);
        return 1;
    }
    return 0;
}

int vault_db_fetch_config(char *server, size_t s_len,
                        char *port, size_t p_len,
                        char *user, size_t u_len,
                        char *dbname, size_t d_len,
                        char *password, size_t pass_len) {

    load_env_vault_vars();

    if (strlen(g_vault_token) == 0) {
        fprintf(stderr, "[VAULT-DB-CLIENT] ERROR: VAULT_TOKEN is missing or empty!\n");
        return -1;
    }

    fprintf(stderr, "[VAULT-DB-CLIENT] Connecting to Vault at %s:%d to fetch DB secrets...\n",
            g_vault_host, g_vault_port);

    char response[16384];
    // Exact Endpoint for KV v2 at mount 'kv' and secret 'secret': /v1/kv/data/secret
    int rc = http_get_vault("/v1/kv/data/secret", response, sizeof(response));

    if (rc <= 0 || strncmp(response, "HTTP/1.1 200", 12) != 0) {
        fprintf(stderr, "[VAULT-DB-CLIENT] Failed to fetch secret from /v1/kv/data/secret. Response: %.40s\n", response);
        return -1;
    }

    int found = 0;
    found += extract_json_kv(response, "POSTGRES_SERVER", server, s_len);
    found += extract_json_kv(response, "POSTGRES_PORT", port, p_len);
    found += extract_json_kv(response, "POSTGRES_USER", user, u_len);
    found += extract_json_kv(response, "POSTGRES_DB", dbname, d_len);
    found += extract_json_kv(response, "POSTGRES_PASSWORD", password, pass_len);

    if (found < 5) {
        fprintf(stderr, "[VAULT-DB-CLIENT] WARNING: Only extracted %d/5 DB parameters from Vault response!\n", found);
        return -1;
    }

    fprintf(stderr, "[VAULT-DB-CLIENT] SUCCESS: Retrieved DB config from Vault [Server: %s, Port: %s, User: %s, DB: %s]\n",
            server, port, user, dbname);
    return 0;
}
