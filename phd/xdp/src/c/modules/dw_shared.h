// SPDX-License-Identifier: GPL-2.0
#ifndef __DW_SHARED_H__
#define __DW_SHARED_H__

#include <linux/types.h>

struct dw_pkt_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 ip_id;
	__u16 udp_len;
	__u8  proto;
	__u8  pad1;
	__u16 pad2;
} __attribute__((packed));

#endif
