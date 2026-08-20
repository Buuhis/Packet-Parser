#include "../inc/pqc_vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define ENV_FILE_PATH     ".env"

static char g_vault_addr[256] = "http://127.0.0.1:8200";
static char g_vault_host[128] = "127.0.0.1";
static int  g_vault_port = 8200;
static char g_vault_token[512] = "";
static char g_unseal_key1[512] = "";
static char g_unseal_key2[512] = "";
static char g_unseal_key3[512] = "";
static char g_listen_port[32]  = "";

static bool g_vault_initialized = false;

static void trim_env_val(char *val) {
    if (!val) return;
    size_t len = strlen(val);
    while (len > 0 && (val[len - 1] == '\r' || val[len - 1] == '\n' || val[len - 1] == ' ' || val[len - 1] == '\t' || val[len - 1] == '"' || val[len - 1] == '\'')) {
        val[len - 1] = '\0';
        len--;
    }
    char *p = val;
    while (*p == ' ' || *p == '\t' || *p == '"' || *p == '\'') p++;
    if (p != val) {
        memmove(val, p, strlen(p) + 1);
    }
}

static void parse_vault_url(const char *url) {
    if (!url || strlen(url) == 0) return;
    strncpy(g_vault_addr, url, sizeof(g_vault_addr) - 1);

    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
    }

    char hostport[256];
    strncpy(hostport, p, sizeof(hostport) - 1);
    hostport[sizeof(hostport) - 1] = '\0';

    char *colon = strchr(hostport, ':');
    char *slash = strchr(hostport, '/');
    if (slash) *slash = '\0';

    if (colon && (!slash || colon < slash)) {
        *colon = '\0';
        strncpy(g_vault_host, hostport, sizeof(g_vault_host) - 1);
        g_vault_port = atoi(colon + 1);
    } else {
        strncpy(g_vault_host, hostport, sizeof(g_vault_host) - 1);
        g_vault_port = 8200;
    }

    if (strcmp(g_vault_host, "localhost") == 0) {
        strcpy(g_vault_host, "127.0.0.1");
    }
}

static void load_env_file(void) {
    FILE *fp = fopen(ENV_FILE_PATH, "r");
    if (!fp) {
        const char *e_addr = getenv("VAULT_ADDR");
        const char *e_token = getenv("VAULT_TOKEN");
        const char *e_k1 = getenv("UNSEAL_KEY1");
        const char *e_k2 = getenv("UNSEAL_KEY2");
        const char *e_k3 = getenv("UNSEAL_KEY3");
        const char *e_port = getenv("LISTEN_PORT");

        if (e_addr) parse_vault_url(e_addr);
        if (e_token) strncpy(g_vault_token, e_token, sizeof(g_vault_token) - 1);
        if (e_k1) strncpy(g_unseal_key1, e_k1, sizeof(g_unseal_key1) - 1);
        if (e_k2) strncpy(g_unseal_key2, e_k2, sizeof(g_unseal_key2) - 1);
        if (e_k3) strncpy(g_unseal_key3, e_k3, sizeof(g_unseal_key3) - 1);
        if (e_port) strncpy(g_listen_port, e_port, sizeof(g_listen_port) - 1);
        return;
    }

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

        trim_env_val(key);
        trim_env_val(val);

        if (strcmp(key, "VAULT_ADDR") == 0) {
            parse_vault_url(val);
        } else if (strcmp(key, "VAULT_TOKEN") == 0) {
            strncpy(g_vault_token, val, sizeof(g_vault_token) - 1);
        } else if (strcmp(key, "UNSEAL_KEY1") == 0) {
            strncpy(g_unseal_key1, val, sizeof(g_unseal_key1) - 1);
        } else if (strcmp(key, "UNSEAL_KEY2") == 0) {
            strncpy(g_unseal_key2, val, sizeof(g_unseal_key2) - 1);
        } else if (strcmp(key, "UNSEAL_KEY3") == 0) {
            strncpy(g_unseal_key3, val, sizeof(g_unseal_key3) - 1);
        } else if (strcmp(key, "LISTEN_PORT") == 0) {
            strncpy(g_listen_port, val, sizeof(g_listen_port) - 1);
        }
    }
    fclose(fp);
}

static int http_request(const char *method, const char *path, const char *body, char *resp_buf, size_t max_resp) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[PQC-VAULT] Socket creation error");
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
        if (!he) {
            fprintf(stderr, "[PQC-VAULT] Cannot resolve host: %s\n", g_vault_host);
            close(sockfd);
            return -1;
        }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "[PQC-VAULT] Connection failed to %s:%d - %s\n", g_vault_host, g_vault_port, strerror(errno));
        close(sockfd);
        return -1;
    }

    char req[16384];
    int body_len = body ? (int)strlen(body) : 0;

    int req_len = snprintf(req, sizeof(req),
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: sd-wan-pqc\r\n"
        "Accept: */*\r\n"
        "Content-Type: application/json\r\n"
        "X-Vault-Token: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
        "%s",
        method, path, g_vault_host, g_vault_port,
        g_vault_token, body_len, body ? body : "");

    if (send(sockfd, req, req_len, 0) < 0) {
        perror("[PQC-VAULT] Send HTTP request failed");
        close(sockfd);
        return -1;
    }

    memset(resp_buf, 0, max_resp);
    int total_recv = 0;
    int n = 0;
    while ((n = recv(sockfd, resp_buf + total_recv, (int)max_resp - 1 - total_recv, 0)) > 0) {
        total_recv += n;
        if (total_recv >= (int)max_resp - 1) break;
    }
    close(sockfd);
    resp_buf[total_recv] = '\0';

    return total_recv;
}

static bool parse_json_sealed_status(const char *json) {
    if (!json) return true;
    const char *p = strstr(json, "\"sealed\"");
    if (!p) return true;
    p += 8;
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (strncmp(p, "false", 5) == 0) return false;
    return true;
}

static int send_unseal_key(const char *key) {
    if (!key || strlen(key) == 0) return -1;
    char payload[1024];
    snprintf(payload, sizeof(payload), "{\"key\":\"%s\"}", key);

    char response[8192];
    int rc = http_request("POST", "/v1/sys/unseal", payload, response, sizeof(response));
    if (rc < 0) return -1;

    bool sealed = parse_json_sealed_status(response);
    return sealed ? 1 : 0;
}

int sig_pqc_vault_ensure_unsealed(void) {
    char response[8192];
    int rc = http_request("GET", "/v1/sys/seal-status", NULL, response, sizeof(response));
    if (rc < 0) {
        fprintf(stderr, "[PQC-VAULT] Error checking Vault seal status.\n");
        return -1;
    }

    bool sealed = parse_json_sealed_status(response);
    if (!sealed) {
        fprintf(stderr, "[PQC-VAULT] Vault is UNSEALED and ready.\n");
        return 0;
    }

    fprintf(stderr, "[PQC-VAULT] Vault is SEALED. Attempting automatic unseal using configured keys...\n");
    if (strlen(g_unseal_key1) > 0) {
        fprintf(stderr, "[PQC-VAULT] Sending Unseal Key 1...\n");
        send_unseal_key(g_unseal_key1);
    }
    if (strlen(g_unseal_key2) > 0) {
        fprintf(stderr, "[PQC-VAULT] Sending Unseal Key 2...\n");
        send_unseal_key(g_unseal_key2);
    }
    if (strlen(g_unseal_key3) > 0) {
        fprintf(stderr, "[PQC-VAULT] Sending Unseal Key 3...\n");
        send_unseal_key(g_unseal_key3);
    }

    rc = http_request("GET", "/v1/sys/seal-status", NULL, response, sizeof(response));
    if (rc >= 0 && !parse_json_sealed_status(response)) {
        fprintf(stderr, "[PQC-VAULT] SUCCESS: Vault has been UNSEALED!\n");
        return 0;
    }

    fprintf(stderr, "[PQC-VAULT] ERROR: Vault is still SEALED after submitting unseal keys.\n");
    return -1;
}

int sig_pqc_init_vault(void) {
    if (g_vault_initialized) return 0;

    load_env_file();

    if (sig_pqc_vault_ensure_unsealed() != 0) {
        fprintf(stderr, "[PQC-VAULT] WARNING: Vault server is not ready/unsealed.\n");
    }

    g_vault_initialized = true;
    return 0;
}

static bool extract_json_value(const char *json, const char *key_name, char *out_val, size_t max_len) {
    if (!json || !key_name || !out_val) return false;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key_name);

    const char *p = strstr(json, pattern);
    if (!p) return false;

    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    if (*p == '"') {
        p++; // Skip opening quote
        size_t idx = 0;
        while (*p && *p != '"' && idx < max_len - 1) {
            if (*p == '\\' && *(p + 1) == '"') {
                p++;
            }
            out_val[idx++] = *p++;
        }
        out_val[idx] = '\0';
        return true;
    }
    return false;
}

int sig_pqc_vault_read_key(const char *path_type, const char *fingerprint_filename, char *out_key_buf, size_t max_len) {
    if (!path_type || !fingerprint_filename || !out_key_buf) return -1;
    if (!g_vault_initialized) sig_pqc_init_vault();

    char clean_filename[128];
    strncpy(clean_filename, fingerprint_filename, sizeof(clean_filename) - 1);
    clean_filename[sizeof(clean_filename) - 1] = '\0';

    char url_path[512];
    // Support KV v2 endpoint structure: /v1/kv/data/PQC-Key/<path_type>/<filename>
    snprintf(url_path, sizeof(url_path), "/v1/kv/data/PQC-Key/%s/%s", path_type, clean_filename);

    char response[16384];
    int rc = http_request("GET", url_path, NULL, response, sizeof(response));

    // Fallback to KV v1 endpoint if KV v2 returned 404
    if (rc <= 0 || strncmp(response, "HTTP/1.1 404", 12) == 0) {
        snprintf(url_path, sizeof(url_path), "/v1/kv/PQC-Key/%s/%s", path_type, clean_filename);
        rc = http_request("GET", url_path, NULL, response, sizeof(response));
    }

    if (rc <= 0 || (strncmp(response, "HTTP/1.1 200", 12) != 0)) {
        fprintf(stderr, "[PQC-VAULT] Read key failed from Vault for [%s/%s]. Response code not 200.\n",
                path_type, clean_filename);
        return -1;
    }

    // Extract the "key" value from the JSON payload
    if (extract_json_value(response, "key", out_key_buf, max_len) ||
        extract_json_value(response, "value", out_key_buf, max_len)) {
        fprintf(stderr, "[PQC-VAULT-LOG] SUCCESS: Key [%s/%s] retrieved 100%% directly from HashiCorp Vault (REST Endpoint: %s%s)\n",
                path_type, clean_filename, g_vault_addr, url_path);
        return 0;
    }

    fprintf(stderr, "[PQC-VAULT] Error parsing JSON key from Vault response for [%s/%s]\n",
            path_type, clean_filename);
    return -1;
}

int sig_pqc_vault_write_key(const char *path_type, const char *fingerprint_filename, const char *key_content) {
    if (!path_type || !fingerprint_filename || !key_content) return -1;
    if (!g_vault_initialized) sig_pqc_init_vault();

    char clean_filename[128];
    strncpy(clean_filename, fingerprint_filename, sizeof(clean_filename) - 1);
    clean_filename[sizeof(clean_filename) - 1] = '\0';

    char url_path[512];
    snprintf(url_path, sizeof(url_path), "/v1/kv/data/PQC-Key/%s/%s", path_type, clean_filename);

    char body[16384];
    snprintf(body, sizeof(body), "{\"data\":{\"key\":\"%s\",\"fingerprint\":\"%s\"}}", key_content, clean_filename);

    char response[8192];
    int rc = http_request("POST", url_path, body, response, sizeof(response));

    if (rc <= 0 || (strncmp(response, "HTTP/1.1 200", 12) != 0 && strncmp(response, "HTTP/1.1 204", 12) != 0)) {
        snprintf(url_path, sizeof(url_path), "/v1/kv/PQC-Key/%s/%s", path_type, clean_filename);
        snprintf(body, sizeof(body), "{\"key\":\"%s\",\"fingerprint\":\"%s\"}", key_content, clean_filename);
        rc = http_request("POST", url_path, body, response, sizeof(response));
    }

    if (rc > 0 && (strncmp(response, "HTTP/1.1 200", 12) == 0 || strncmp(response, "HTTP/1.1 204", 12) == 0)) {
        fprintf(stderr, "[PQC-VAULT] Successfully wrote key to Vault: [kv/PQC-Key/%s/%s]\n", path_type, clean_filename);
        return 0;
    }

    char status_line[128] = "";
    const char *line_end = strchr(response, '\r');
    if (!line_end) line_end = strchr(response, '\n');
    if (line_end) {
        size_t slen = line_end - response;
        if (slen >= sizeof(status_line)) slen = sizeof(status_line) - 1;
        strncpy(status_line, response, slen);
        status_line[slen] = '\0';
    } else {
        snprintf(status_line, sizeof(status_line), "%.127s", response);
    }

    fprintf(stderr, "[PQC-VAULT] ERROR: Failed to write key to Vault: [kv/PQC-Key/%s/%s] - Response: %s\n",
            path_type, clean_filename, status_line[0] ? status_line : "No response from server");
    return -1;
}
