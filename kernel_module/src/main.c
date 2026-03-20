#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "forwarder.h"

static struct nf_hook_ops nfho; // Cấu trúc lưu trữ thông tin Hook

// Hàm Callback mà Kernel sẽ gọi mỗi khi có gói tin cần Forward
static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    return packet_handler_logic(skb);
}

// Hàm chạy khi bạn gõ 'insmod'
static int __init my_module_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_FORWARD;  // Điểm hook: Forwarding
    nfho.pf = PF_INET;               // Giao thức: IPv4
    nfho.priority = NF_IP_PRI_FIRST; // Độ ưu tiên cao nhất

    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[K-Forwarder] Module loaded successfully!\n");
    return 0;
}

// Hàm chạy khi bạn gõ 'rmmod'
static void __exit my_module_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[K-Forwarder] Module unloaded. Goodbye!\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hoang Buu");
MODULE_DESCRIPTION("A simple Kernel Packet Forwarder");