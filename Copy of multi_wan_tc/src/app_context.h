#ifndef APP_CONTEXT_H
#define APP_CONTEXT_H

#include <stddef.h>

#define MAX_WANS       8
#define MAX_NE_TUNNELS 8


typedef struct {
    char name[16];
    char ifname[16];
    char gateway[32];
    int  weight;
    unsigned char dst_mac[6];
} wan_cfg_t;

typedef struct {
    char name[16];
    char ifname[16];
    char gateway[32];
    int  port;
    int  weight;
} ne_tunnel_cfg_t;

// typedef struct {
//     char veth_in[16];
//     char veth_out[16];
//     int  mtu;
// } dataplane_cfg_t;

typedef struct {
    int  node_id;
    char role[16];

    char local_if[16];
    char remote_cidr[32];


    size_t wan_count;
    wan_cfg_t wans[MAX_WANS];

    size_t ne_tunnel_count;
    ne_tunnel_cfg_t ne_tunnels[MAX_NE_TUNNELS];

    // dataplane_cfg_t dataplane;

} app_config_t;

typedef struct {
    app_config_t cfg;
} app_context_t;

void app_context_dump(const app_context_t *ctx);

#endif

