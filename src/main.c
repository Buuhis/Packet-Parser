#include "../inc/packet_parser.h"
#include "../util/inc/logger.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    if (init_logger("output.txt") != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    // Open network interface in promiscuous mode for packet capture
    // BUFSIZ: capture buffer size, 1: promiscuous mode enabled, 1000ms: timeout
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        close_logger();  // Clean up logger before exit
        return 2;
    }

    int link_type = pcap_datalink(handle);
    printf("Listening on interface: %s\n", argv[1]);
    printf("Link-layer: %s (DLT=%d)\n",
           (link_type == DLT_EN10MB) ? "Ethernet" :
           (link_type == DLT_IEEE802_11) ? "802.11" :
           (link_type == DLT_IEEE802_11_RADIO) ? "Radiotap + 802.11" :
           "Unknown",
           link_type);

    // Start packet capture loop - 0 means capture indefinitely
    // packet_handler function will be called for each captured packet
    pcap_loop(handle, 0, packet_handler, (u_char *)&link_type);

    pcap_close(handle);

    close_logger();
    return 0;
}

