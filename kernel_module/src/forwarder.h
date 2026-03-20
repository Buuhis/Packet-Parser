#ifndef FORWARDER_H
#define FORWARDER_H

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/ip.h>

// Khai báo hàm xử lý chính
unsigned int packet_handler_logic(struct sk_buff *skb);

#endif