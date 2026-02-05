#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6
#define MAX_BATCH_SIZE  1024

struct local_config {
    char ifname[IF_NAMESIZE];
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
};

struct wan_config {
    char ifname[IF_NAMESIZE];
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint32_t window_size;
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
};

struct app_config {
    uint32_t global_frame_size;
    uint32_t global_batch_size;

    struct local_config locals[MAX_INTERFACES];
    int local_count;

    struct wan_config wans[MAX_INTERFACES];
    int wan_count;

    char bpf_file[256];
};

int config_load(struct app_config *cfg, const char *filename);
void config_print(struct app_config *cfg);
int parse_mac(const char *str, uint8_t *mac);
int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip);
int config_validate(struct app_config *cfg);

#endif
