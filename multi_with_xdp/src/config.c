#include "../inc/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

int parse_mac(const char *str, uint8_t *mac) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return 0;
}

static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    char ip_str[32];
    int prefix_len;

    if (sscanf(str, "%31[^/]/%d", ip_str, &prefix_len) != 2)
        return -1;

    if (prefix_len < 0 || prefix_len > 32)
        return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1)
        return -1;

    *ip = addr.s_addr;

    if (prefix_len == 0)
        *netmask = 0;
    else
        *netmask = htonl(0xFFFFFFFF << (32 - prefix_len));

    if (network)
        *network = *ip & *netmask;

    return 0;
}

static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static const char *ip_to_str(uint32_t ip, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, len);
    return buf;
}

static const char *mac_to_str(const uint8_t *mac, char *buf, size_t len) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

enum section_type {
    SECTION_NONE,
    SECTION_GLOBAL,
    SECTION_LOCAL,
    SECTION_WAN,
    SECTION_PIPELINE,
};

int config_load(struct app_config *cfg, const char *filename) {
    FILE *fp;
    char line[512];
    enum section_type current_section = SECTION_NONE;

    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->bpf_file, "bpf/xdp_redirect.o", sizeof(cfg->bpf_file) - 1);

    printf("[CONFIG] Loading: %s\n", filename);

    fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen config");
        return -1;
    }

    struct local_config *current_local = NULL;
    struct wan_config *current_wan = NULL;
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);

        if (trimmed[0] == '#' || trimmed[0] == '\0')
            continue;

        if (trimmed[0] == '[') {
            if (strcmp(trimmed, "[GLOBAL]") == 0) {
                current_section = SECTION_GLOBAL;
            }

            else if (strcmp(trimmed, "[LOCAL]") == 0) {
                current_section = SECTION_LOCAL;
                if (cfg->local_count >= MAX_INTERFACES) {
                    fprintf(stderr, "Too many LOCAL interfaces\n");
                    fclose(fp);
                    return -1;
                }
                current_local = &cfg->locals[cfg->local_count];
                memset(current_local, 0, sizeof(*current_local));
                current_local->frame_size = cfg->global_frame_size;
                current_local->batch_size = cfg->global_batch_size;
                cfg->local_count++;
            }

            else if (strcmp(trimmed, "[WAN]") == 0) {
                current_section = SECTION_WAN;
                if (cfg->wan_count >= MAX_INTERFACES) {
                    fprintf(stderr, "Too many WAN interfaces\n");
                    fclose(fp);
                    return -1;
                }
                current_wan = &cfg->wans[cfg->wan_count];
                memset(current_wan, 0, sizeof(*current_wan));
                current_wan->frame_size = cfg->global_frame_size;
                current_wan->batch_size = cfg->global_batch_size;
                cfg->wan_count++;
            }

            else if (strcmp(trimmed, "[PIPELINE]") == 0) {
                current_section = SECTION_PIPELINE;
            }

            continue;
        }

        char key[64], value[256];
        if (sscanf(trimmed, "%63s %255[^\n]", key, value) != 2)
            continue;

        switch (current_section) {
        case SECTION_GLOBAL:
            if (strcmp(key, "frame_size") == 0) {
                cfg->global_frame_size = atoi(value);
            } else if (strcmp(key, "batch_size") == 0) {
                cfg->global_batch_size = atoi(value);
            }
            break;

        case SECTION_LOCAL:
            if (!current_local) break;
            if (strcmp(key, "interface") == 0) {
                strncpy(current_local->ifname, value, IF_NAMESIZE - 1);
            }

            else if (strcmp(key, "network") == 0) {
                if (parse_ip_cidr(value, &current_local->ip, &current_local->netmask, &current_local->network) != 0) {
                    fprintf(stderr, "Invalid LOCAL network: %s\n", value);
                    fclose(fp);
                    return -1;
                }
            }

            else if (strcmp(key, "src_mac") == 0) {
                if (parse_mac(value, current_local->src_mac) != 0) {
                    fprintf(stderr, "Invalid LOCAL src_mac: %s\n", value);
                    fclose(fp);
                    return -1;
                }
            }

            else if (strcmp(key, "dst_mac") == 0) {
                if (parse_mac(value, current_local->dst_mac) != 0) {
                    fprintf(stderr, "Invalid LOCAL dst_mac: %s\n", value);
                    fclose(fp);
                    return -1;
                }
            }

            else if (strcmp(key, "umem_mb") == 0) {
                current_local->umem_mb = atoi(value);
            }

            else if (strcmp(key, "ring_size") == 0) {
                current_local->ring_size = atoi(value);
            }

            else if (strcmp(key, "frame_size") == 0) {
                current_local->frame_size = atoi(value);
            }

            else if (strcmp(key, "batch_size") == 0) {
                current_local->batch_size = atoi(value);
            }
            break;

        case SECTION_WAN:
            if (!current_wan) break;

            if (strcmp(key, "interface") == 0) {
                strncpy(current_wan->ifname, value, IF_NAMESIZE - 1);
            }

            else if (strcmp(key, "src_mac") == 0) {
                if (parse_mac(value, current_wan->src_mac) != 0) {
                    fprintf(stderr, "Invalid WAN src_mac: %s\n", value);
                    fclose(fp);
                    return -1;
                }
            }

            else if (strcmp(key, "dst_mac") == 0) {
                if (parse_mac(value, current_wan->dst_mac) != 0) {
                    fprintf(stderr, "Invalid WAN dst_mac: %s\n", value);
                    fclose(fp);
                    return -1;
                }
            }

            else if (strcmp(key, "window_kb") == 0) {
                current_wan->window_size = atoi(value) * 1024;
            }

            else if (strcmp(key, "umem_mb") == 0) {
                current_wan->umem_mb = atoi(value);
            }

            else if (strcmp(key, "ring_size") == 0) {
                current_wan->ring_size = atoi(value);
            }

            else if (strcmp(key, "frame_size") == 0) {
                current_wan->frame_size = atoi(value);
            }

            else if (strcmp(key, "batch_size") == 0) {
                current_wan->batch_size = atoi(value);
            }
            break;

        case SECTION_PIPELINE:
            if (strcmp(key, "outbound_workers") == 0) {
                cfg->num_outbound_workers = atoi(value);
            } else if (strcmp(key, "inbound_workers") == 0) {
                cfg->num_inbound_workers = atoi(value);
            } else if (strcmp(key, "ring_size") == 0) {
                cfg->pipeline_ring_size = atoi(value);
            } else if (strcmp(key, "pool_size") == 0) {
                cfg->pipeline_pool_size = atoi(value);
            }
            break;

        default:
            break;
        }
    }

    fclose(fp);

    if (cfg->local_count == 0) {
        fprintf(stderr, "No LOCAL interface defined\n");
        return -1;
    }
    if (cfg->wan_count == 0) {
        fprintf(stderr, "No WAN interface defined\n");
        return -1;
    }

    return config_validate(cfg);
}

int config_validate(struct app_config *cfg) {
    if (cfg->global_frame_size == 0) {
        fprintf(stderr, "[GLOBAL] frame_size not specified\n");
        return -1;
    }

    if (cfg->global_batch_size == 0) {
        fprintf(stderr, "[GLOBAL] batch_size not specified\n");
        return -1;
    }

    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];

        if (local->ifname[0] == '\0') {
            fprintf(stderr, "LOCAL[%d]: interface not specified\n", i);
            return -1;
        }
        if (local->umem_mb == 0) {
            fprintf(stderr, "LOCAL %s: umem_mb not specified\n", local->ifname);
            return -1;
        }
        if (local->ring_size == 0) {
            fprintf(stderr, "LOCAL %s: ring_size not specified\n", local->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (local->ring_size * 2 * local->frame_size) / (1024 * 1024);
        if (local->umem_mb < min_umem_mb) {
            fprintf(stderr, "LOCAL %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    local->ifname, local->umem_mb, local->ring_size, min_umem_mb);
            return -1;
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];

        if (wan->ifname[0] == '\0') {
            fprintf(stderr, "WAN[%d]: interface not specified\n", i);
            return -1;
        }

        if (wan->umem_mb == 0) {
            fprintf(stderr, "WAN %s: umem_mb not specified\n", wan->ifname);
            return -1;
        }

        if (wan->ring_size == 0) {
            fprintf(stderr, "WAN %s: ring_size not specified\n", wan->ifname);
            return -1;
        }

        if (wan->window_size == 0) {
            fprintf(stderr, "WAN %s: window_kb not specified\n", wan->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (wan->ring_size * 2 * wan->frame_size) / (1024 * 1024);
        if (wan->umem_mb < min_umem_mb) {
            fprintf(stderr, "WAN %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    wan->ifname, wan->umem_mb, wan->ring_size, min_umem_mb);
            return -1;
        }
    }

    return 0;
}

int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip) {
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        if ((dest_ip & local->netmask) == local->network) {
            return i;
        }
    }
    return -1;
}

void config_print(struct app_config *cfg) {
    char ip_buf[INET_ADDRSTRLEN], ip_buf2[INET_ADDRSTRLEN];
    char mac_buf[32], mac_buf2[32];

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    XDP FORWARDER CONFIG                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    printf("║ [GLOBAL]                                                     ║\n");
    printf("║   frame_size: %-48d ║\n", cfg->global_frame_size);
    printf("║   batch_size: %-48d ║\n", cfg->global_batch_size);

    printf("╠══════════════════════════════════════════════════════════════╣\n");

    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        printf("║ [LOCAL] %-54s ║\n", local->ifname);
        printf("║   network:   %-52s ║\n", ip_to_str(local->network, ip_buf, sizeof(ip_buf)));
        printf("║   netmask:   %-52s ║\n", ip_to_str(local->netmask, ip_buf2, sizeof(ip_buf2)));
        printf("║   src_mac:   %-52s ║\n", mac_to_str(local->src_mac, mac_buf, sizeof(mac_buf)));
        printf("║   dst_mac:   %-52s ║\n", mac_to_str(local->dst_mac, mac_buf2, sizeof(mac_buf2)));
        printf("║   umem_mb:   %-3d  ring_size: %-6d  frame_size: %-5d    ║\n",
               local->umem_mb, local->ring_size, local->frame_size);
        printf("╟──────────────────────────────────────────────────────────────╢\n");
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];
        printf("║ [WAN] %-56s ║\n", wan->ifname);
        printf("║   src_mac:   %-52s ║\n", mac_to_str(wan->src_mac, mac_buf, sizeof(mac_buf)));
        printf("║   dst_mac:   %-52s ║\n", mac_to_str(wan->dst_mac, mac_buf2, sizeof(mac_buf2)));
        printf("║   window_kb: %-52d ║\n", wan->window_size / 1024);
        printf("║   umem_mb:   %-3d  ring_size: %-6d  frame_size: %-5d    ║\n",
               wan->umem_mb, wan->ring_size, wan->frame_size);
        printf("╟──────────────────────────────────────────────────────────────╢\n");
    }

    if (cfg->num_outbound_workers || cfg->num_inbound_workers) {
        printf("║ [PIPELINE]                                                   ║\n");
        printf("║   outbound_workers: %-42d ║\n", cfg->num_outbound_workers);
        printf("║   inbound_workers:  %-42d ║\n", cfg->num_inbound_workers);
        printf("║   ring_size:        %-42d ║\n",
               cfg->pipeline_ring_size ? cfg->pipeline_ring_size : 8192);
        printf("║   pool_size:        %-42d ║\n",
               cfg->pipeline_pool_size ? cfg->pipeline_pool_size : 16384);
        printf("╟──────────────────────────────────────────────────────────────╢\n");
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}
