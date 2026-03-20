#include "forwarder.h"
#include <linux/kernel.h>

unsigned int packet_handler_logic(struct sk_buff *skb) {
    struct iphdr *ip_header;

    if (!skb) return NF_ACCEPT;

    // Lấy IP Header từ gói tin
    ip_header = ip_hdr(skb);

    if (ip_header) {
        // In ra IP nguồn của gói tin đang bị "tóm" tại điểm FORWARD
        // %pI4 là định dạng đặc biệt của Kernel để in địa chỉ IPv4
        printk(KERN_INFO "[K-Forwarder] Intercepted packet from: %pI4 to %pI4\n", 
               &ip_header->saddr, &ip_header->daddr);
        
        // Tại đây, nếu muốn forward đi chỗ khác, bạn sẽ sửa ip_header->daddr
        // và cập nhật lại checksum.
    }

    return NF_ACCEPT; // Cho phép gói tin đi tiếp bình thường
}