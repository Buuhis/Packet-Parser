#include "../inc/pqc_handshake.h"
#include "../inc/traffic_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>

static uint8_t  g_traffic_key[PQC_TRAFFIC_KEY_SZ];
static bool g_key_ready = false;
static bool g_hs_started = false;
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static char *g_peer_id_pub = NULL;

#define MAX_IDENTITY_REGISTRY 10

typedef struct {
    char fingerprint[16];
    char *priv_key;
    char *pub_key;
} identity_entry_t;

static identity_entry_t g_identity_registry[MAX_IDENTITY_REGISTRY];
static int g_registry_count = 0;

typedef struct {
    int profile_id;
    char *local_priv;
    char *local_pub;
    char *peer_pub;
} profile_key_binding_t;

static profile_key_binding_t g_profile_bindings[MAX_IDENTITY_REGISTRY];
static int g_profile_bindings_count = 0;

typedef struct {
    bool is_initiator;
    char peer_ip[64];
    char local_fingerprint[16];
    char wan_ifname[64];
} hs_config_t;

static hs_config_t g_hs_cfg;

// Helper to calculate SHA256 hash
static void derive_traffic_key(const uint8_t *shared_secret, int ss_len, uint8_t *out_key) {
    uint8_t hash[64]; // Enough for SHA512
    trf_calculate_digest(DIGEST_TYPE_SHA256, shared_secret, ss_len, hash);
    memcpy(out_key, hash, PQC_TRAFFIC_KEY_SZ);
}

// Helper to calculate HMAC-SHA256 for authentication
static void calculate_auth_tag(const char *key_str, const uint8_t *data, int len, uint8_t *out_tag) {
    if (!key_str || key_str[0] == '\0') {
        memset(out_tag, 0, PQC_AUTH_TAG_SZ);
        return;
    }
    trf_calculate_hmac(DIGEST_TYPE_SHA256, (const uint8_t *)key_str, (int)strlen(key_str), data, len, out_tag);
}

static int get_interface_mac(const char *ifname, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static void* pqc_handshake_thread(void* arg) {
    int sockfd;
    struct sockaddr_in servaddr, peeraddr;
    uint8_t buffer[PQC_HS_MSG_MAX_SZ];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[PQC-HS] Socket creation failed");
        return NULL;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PQC_HS_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("[PQC-HS] Bind failed (Port 7090)");
        close(sockfd);
        return NULL;
    }

    memset(&peeraddr, 0, sizeof(peeraddr));
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_port = htons(PQC_HS_PORT);

    // Parse peer IP
    pthread_mutex_lock(&g_key_mutex);
    char current_peer_ip[64];
    strncpy(current_peer_ip, g_hs_cfg.peer_ip, 63);
    pthread_mutex_unlock(&g_key_mutex);
    inet_pton(AF_INET, current_peer_ip, &peeraddr.sin_addr);

    // ----- STAGE 1: AUTOMATED ROLE DISCOVERY VIA MAC EXCHANGE -----
    uint8_t local_mac[6] = {0};
    uint8_t peer_mac[6] = {0};
    bool role_settled = false;

    if (get_interface_mac(g_hs_cfg.wan_ifname, local_mac) < 0) {
        fprintf(stderr, "[PQC-DISCO] WARNING: Failed to get MAC for interface %s. Using fallback.\n", g_hs_cfg.wan_ifname);
        local_mac[0] = 0x02;
        local_mac[5] = 0x01;
    }

    fprintf(stderr, "[PQC-DISCO] Local WAN Interface %s MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           g_hs_cfg.wan_ifname,
           local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);

    // Set socket receive timeout to 500ms for active discovery
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    #define PQC_DISCO_MAGIC 0x50514344
    struct pqc_disco_msg {
        uint32_t magic;
        uint8_t mac[6];
    } __attribute__((packed));

    struct pqc_disco_msg disco_send, disco_recv;
    disco_send.magic = htonl(PQC_DISCO_MAGIC);
    memcpy(disco_send.mac, local_mac, 6);

    fprintf(stderr, "[PQC-DISCO] Exchanging MAC addresses with peer %s on UDP port %d...\n", current_peer_ip, PQC_HS_PORT);
    fflush(stdout);

    int retries = 0;
    while (!role_settled) {
        // Send local MAC
        sendto(sockfd, &disco_send, sizeof(disco_send), 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr));

        // Receive peer MAC
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        int recv_sz = recvfrom(sockfd, &disco_recv, sizeof(disco_recv), 0, (struct sockaddr *)&from_addr, &from_len);

        if (recv_sz == sizeof(struct pqc_disco_msg) && ntohl(disco_recv.magic) == PQC_DISCO_MAGIC) {
            memcpy(peer_mac, disco_recv.mac, 6);
            role_settled = true;
            fprintf(stderr, "[PQC-DISCO] Received Peer MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3], peer_mac[4], peer_mac[5]);
            break;
        }

        retries++;
        if (retries % 10 == 0) {
            fprintf(stderr, "[PQC-DISCO] Waiting for peer MAC... (elapsed %d seconds)\n", retries / 2);
            fflush(stdout);
        }
    }

    // Restore standard longer receive timeout (5 seconds) for main handshake
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Compare MACs to settle roles (Larger MAC = Initiator)
    pthread_mutex_lock(&g_key_mutex);
    int comp = memcmp(local_mac, peer_mac, 6);
    if (comp > 0) {
        g_hs_cfg.is_initiator = true;
    } else if (comp < 0) {
        g_hs_cfg.is_initiator = false;
    } else {
        g_hs_cfg.is_initiator = (strcmp(g_hs_cfg.peer_ip, "192.168.1.1") == 0);
    }
    pthread_mutex_unlock(&g_key_mutex);

    fprintf(stderr, "[PQC-DISCO] ROLE SETTLED: Local MAC [%02x:%02x:%02x:%02x:%02x:%02x] %s Peer MAC [%02x:%02x:%02x:%02x:%02x:%02x] -> Role: %s\n",
           local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5],
           g_hs_cfg.is_initiator ? ">" : "<",
           peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3], peer_mac[4], peer_mac[5],
           g_hs_cfg.is_initiator ? "INITIATOR" : "RESPONDER");
    fflush(stdout);

    // ----- STAGE 2: MAIN ML-KEM/ML-DSA HANDSHAKE -----
    while (!g_key_ready) {
        // 1. Wait for keys to be ready in RAM/DB
        pthread_mutex_lock(&g_key_mutex);
        char *my_priv = NULL;
        for (int i = 0; i < g_registry_count; i++) {
            if (strcmp(g_identity_registry[i].fingerprint, g_hs_cfg.local_fingerprint) == 0) {
                my_priv = g_identity_registry[i].priv_key;
                break;
            }
        }
        bool has_keys = (my_priv != NULL && g_peer_id_pub != NULL);
        char current_peer_ip[64];
        strncpy(current_peer_ip, g_hs_cfg.peer_ip, 63);
        pthread_mutex_unlock(&g_key_mutex);

        if (!has_keys) {
            sleep(2);
            continue;
        }

        inet_pton(AF_INET, current_peer_ip, &peeraddr.sin_addr);
        uint8_t pk[2048], sk[4096], ct[2048], ss[128];
        int pk_sz, sk_sz, ct_sz;

        if (g_hs_cfg.is_initiator) {
            // --- INITIATOR FLOW ---
            trf_kem_generate_keys(pk, &pk_sz, sk, &sk_sz);
            struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
            msg->magic = PQC_HS_MAGIC;
            msg->msg_type = PQC_HS_MSG_HELLO;
            msg->session_id = 123; 
            msg->data_len = (uint16_t)pk_sz;
            memcpy(msg->data, pk, pk_sz);
            
            pthread_mutex_lock(&g_key_mutex);
            calculate_auth_tag(my_priv, msg->data, pk_sz, msg->auth_tag);
            pthread_mutex_unlock(&g_key_mutex);

            while (!g_key_ready) {
                sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + pk_sz, 0,
                       (const struct sockaddr *)&peeraddr, sizeof(peeraddr));
                
                struct timeval tv = {2, 0};
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                socklen_t len = sizeof(peeraddr);
                int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peeraddr, &len);
                if (n > 0) {
                    struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                    if (resp->magic == PQC_HS_MAGIC && resp->msg_type == PQC_HS_MSG_RESP) {
                        uint8_t expected_tag[PQC_AUTH_TAG_SZ];
                        calculate_auth_tag(g_peer_id_pub, resp->data, resp->data_len, expected_tag);
                        
                        if (memcmp(resp->auth_tag, expected_tag, PQC_AUTH_TAG_SZ) == 0) {
                            if (trf_kem_decapsulate(sk, sk_sz, resp->data, resp->data_len, ss) == TRF_PQC_OK) {
                                pthread_mutex_lock(&g_key_mutex);
                                derive_traffic_key(ss, 32, g_traffic_key);
                                g_key_ready = true;
                                pthread_mutex_unlock(&g_key_mutex);
                                fprintf(stderr, "[PQC-HS] Handshake SUCCESS!\n");
                                break;
                            }
                        }
                    } else if (n == sizeof(struct pqc_disco_msg)) {
                        struct pqc_disco_msg *disco = (struct pqc_disco_msg *)buffer;
                        if (ntohl(disco->magic) == PQC_DISCO_MAGIC) {
                            sendto(sockfd, &disco_send, sizeof(disco_send), 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr));
                        }
                    }
                }
                fprintf(stderr, "[PQC-HS] Initiator retrying HELLO...\n");
            }
        } else {
            // --- RESPONDER FLOW ---
            struct timeval tv = {1, 0};
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            socklen_t len = sizeof(peeraddr);
            int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peeraddr, &len);
            if (n > 0) {
                struct pqc_hs_msg *msg = (struct pqc_hs_msg *)buffer;
                if (msg->magic == PQC_HS_MAGIC && msg->msg_type == PQC_HS_MSG_HELLO) {
                    uint8_t expected_tag[PQC_AUTH_TAG_SZ];
                    calculate_auth_tag(g_peer_id_pub, msg->data, msg->data_len, expected_tag);
                    
                    if (memcmp(msg->auth_tag, expected_tag, PQC_AUTH_TAG_SZ) == 0) {
                        if (trf_kem_encapsulate(msg->data, msg->data_len, ct, &ct_sz, ss) == TRF_PQC_OK) {
                            struct pqc_hs_msg *resp = (struct pqc_hs_msg *)buffer;
                            resp->msg_type = PQC_HS_MSG_RESP;
                            resp->data_len = (uint16_t)ct_sz;
                            memcpy(resp->data, ct, ct_sz);
                            
                            pthread_mutex_lock(&g_key_mutex);
                            calculate_auth_tag(my_priv, resp->data, ct_sz, resp->auth_tag);
                            pthread_mutex_unlock(&g_key_mutex);

                            sendto(sockfd, buffer, sizeof(struct pqc_hs_msg) + ct_sz, 0,
                                   (const struct sockaddr *)&peeraddr, sizeof(peeraddr));

                            pthread_mutex_lock(&g_key_mutex);
                            derive_traffic_key(ss, 32, g_traffic_key);
                            g_key_ready = true;
                            pthread_mutex_unlock(&g_key_mutex);
                            fprintf(stderr, "[PQC-HS] Responder Handshake SUCCESS!\n");
                        }
                    }
                } else if (n == sizeof(struct pqc_disco_msg)) {
                    struct pqc_disco_msg *disco = (struct pqc_disco_msg *)buffer;
                    if (ntohl(disco->magic) == PQC_DISCO_MAGIC) {
                        sendto(sockfd, &disco_send, sizeof(disco_send), 0, (struct sockaddr *)&peeraddr, sizeof(peeraddr));
                    }
                }
            }
        }
    }

    close(sockfd);
    return NULL;
}

int sig_pqc_handshake_start(const char *wan_ifname, const char *peer_ip) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_hs_started) {
        pthread_mutex_unlock(&g_key_mutex);
        return 0;
    }
    g_hs_started = true;
    pthread_mutex_unlock(&g_key_mutex);

    if (wan_ifname) strncpy(g_hs_cfg.wan_ifname, wan_ifname, 63);
    strncpy(g_hs_cfg.peer_ip, peer_ip, 63);

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, pqc_handshake_thread, NULL) != 0) {
        pthread_mutex_lock(&g_key_mutex);
        g_hs_started = false;
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }
    pthread_detach(thread_id);
    return 0;
}

bool sig_pqc_is_key_ready(void) {
    pthread_mutex_lock(&g_key_mutex);
    bool ready = g_key_ready;
    pthread_mutex_unlock(&g_key_mutex);
    return ready;
}

int sig_pqc_get_traffic_key(uint8_t out_key[PQC_TRAFFIC_KEY_SZ]) {
    pthread_mutex_lock(&g_key_mutex);
    if (!g_key_ready) {
        pthread_mutex_unlock(&g_key_mutex);
        return -1;
    }
    memcpy(out_key, g_traffic_key, PQC_TRAFFIC_KEY_SZ);
    pthread_mutex_unlock(&g_key_mutex);
    return 0;
}

void sig_pqc_add_to_registry(const char *fingerprint, const char *priv, const char *pub) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_registry_count >= MAX_IDENTITY_REGISTRY) {
        fprintf(stderr, "[PQC-REG] Registry full!\n");
        pthread_mutex_unlock(&g_key_mutex);
        return;
    }
    
    // Check if already exists
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, fingerprint) == 0) {
            free(g_identity_registry[i].priv_key);
            free(g_identity_registry[i].pub_key);
            g_identity_registry[i].priv_key = strdup(priv);
            g_identity_registry[i].pub_key = strdup(pub);
            pthread_mutex_unlock(&g_key_mutex);
            return;
        }
    }

    identity_entry_t *entry = &g_identity_registry[g_registry_count++];
    strncpy(entry->fingerprint, fingerprint, 15);
    entry->priv_key = strdup(priv);
    entry->pub_key = strdup(pub);
    
    fprintf(stderr, "[PQC-REG] Added identity fingerprint: %s to RAM Registry.\n", fingerprint);
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_set_handshake_config(bool is_initiator, const char *peer_ip, const char *local_fingerprint, const char *wan_ifname) {
    pthread_mutex_lock(&g_key_mutex);
    g_hs_cfg.is_initiator = is_initiator;
    strncpy(g_hs_cfg.peer_ip, peer_ip, 63);
    if (local_fingerprint) strncpy(g_hs_cfg.local_fingerprint, local_fingerprint, 15);
    if (wan_ifname) strncpy(g_hs_cfg.wan_ifname, wan_ifname, 63);
    pthread_mutex_unlock(&g_key_mutex);
}

void sig_pqc_set_peer_identity(const char *pub) {
    pthread_mutex_lock(&g_key_mutex);
    if (g_peer_id_pub) free(g_peer_id_pub);
    g_peer_id_pub = pub ? strdup(pub) : NULL;
    pthread_mutex_unlock(&g_key_mutex);
    if (pub) fprintf(stderr, "[PQC-HS] Peer identity key loaded from DB. Ready for Handshake.\n");
}

bool sig_pqc_has_identity(const char *fingerprint) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, fingerprint) == 0) {
            pthread_mutex_unlock(&g_key_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    return false;
}

void sig_pqc_bind_profile_keys(int profile_id, const char *local_priv, const char *local_pub, const char *peer_pub) {
    pthread_mutex_lock(&g_key_mutex);
    
    // Check if already bound
    for (int i = 0; i < g_profile_bindings_count; i++) {
        if (g_profile_bindings[i].profile_id == profile_id) {
            if (g_profile_bindings[i].local_priv) free(g_profile_bindings[i].local_priv);
            if (g_profile_bindings[i].local_pub) free(g_profile_bindings[i].local_pub);
            if (g_profile_bindings[i].peer_pub) free(g_profile_bindings[i].peer_pub);
            
            g_profile_bindings[i].local_priv = local_priv ? strdup(local_priv) : NULL;
            g_profile_bindings[i].local_pub = local_pub ? strdup(local_pub) : NULL;
            g_profile_bindings[i].peer_pub = peer_pub ? strdup(peer_pub) : NULL;
            
            pthread_mutex_unlock(&g_key_mutex);
            return;
        }
    }
    
    if (g_profile_bindings_count < MAX_IDENTITY_REGISTRY) {
        profile_key_binding_t *b = &g_profile_bindings[g_profile_bindings_count++];
        b->profile_id = profile_id;
        b->local_priv = local_priv ? strdup(local_priv) : NULL;
        b->local_pub = local_pub ? strdup(local_pub) : NULL;
        b->peer_pub = peer_pub ? strdup(peer_pub) : NULL;
        fprintf(stderr, "[PQC-BIND] Profile %d bound to Local/Peer keys in RAM.\n", profile_id);
    }
    
    pthread_mutex_unlock(&g_key_mutex);
}

int sig_pqc_get_profile_keys(int profile_id, char **out_local_priv, char **out_local_pub, char **out_peer_pub) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_profile_bindings_count; i++) {
        if (g_profile_bindings[i].profile_id == profile_id) {
            if (out_local_priv) *out_local_priv = g_profile_bindings[i].local_priv;
            if (out_local_pub) *out_local_pub = g_profile_bindings[i].local_pub;
            if (out_peer_pub) *out_peer_pub = g_profile_bindings[i].peer_pub;
            pthread_mutex_unlock(&g_key_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    return -1;
}

int sig_pqc_find_identity(const char *fingerprint, char **out_priv, char **out_pub) {
    pthread_mutex_lock(&g_key_mutex);
    for (int i = 0; i < g_registry_count; i++) {
        if (strcmp(g_identity_registry[i].fingerprint, fingerprint) == 0) {
            if (out_priv) *out_priv = g_identity_registry[i].priv_key;
            if (out_pub) *out_pub = g_identity_registry[i].pub_key;
            pthread_mutex_unlock(&g_key_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_key_mutex);
    return -1;
}

void sig_pqc_load_keys_from_disk(void) {
    DIR *dir = opendir("/dev/shm/.enc_config");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "identity_", 9) == 0 && strstr(entry->d_name, "_priv.key") != NULL) {
            char fingerprint[16];
            memset(fingerprint, 0, sizeof(fingerprint));
            strncpy(fingerprint, entry->d_name + 9, 8);

            char priv_path[512];
            char pub_path[512];
            snprintf(priv_path, sizeof(priv_path), "/dev/shm/.enc_config/%s", entry->d_name);
            snprintf(pub_path, sizeof(pub_path), "/etc/.enc_config/identity_%s_pub.key", fingerprint);

            FILE *fp_priv = fopen(priv_path, "r");
            if (!fp_priv) continue;
            char obf_priv[8192];
            memset(obf_priv, 0, sizeof(obf_priv));
            if (fgets(obf_priv, sizeof(obf_priv) - 1, fp_priv) == NULL) {
                fclose(fp_priv);
                continue;
            }
            fclose(fp_priv);
            obf_priv[strcspn(obf_priv, "\r\n")] = '\0';

            FILE *fp_pub = fopen(pub_path, "r");
            if (!fp_pub) continue;
            char obf_pub[4096];
            memset(obf_pub, 0, sizeof(obf_pub));
            if (fgets(obf_pub, sizeof(obf_pub) - 1, fp_pub) == NULL) {
                fclose(fp_pub);
                continue;
            }
            fclose(fp_pub);
            obf_pub[strcspn(obf_pub, "\r\n")] = '\0';

            unsigned char raw_priv[4096];
            size_t raw_priv_len = 0;
            trf_base64_decode_obfuscated(obf_priv, fingerprint, raw_priv, &raw_priv_len);

            char plain_b64_priv[8192];
            memset(plain_b64_priv, 0, sizeof(plain_b64_priv));
            trf_base64_encode(raw_priv, raw_priv_len, plain_b64_priv);

            sig_pqc_add_to_registry(fingerprint, plain_b64_priv, obf_pub);
            fprintf(stderr, "[PQC-LOAD] Loaded Local Identity Fingerprint [%s] from secure RAM-disk (/dev/shm) into RAM.\n", fingerprint);
        }
    }
    closedir(dir);
}
