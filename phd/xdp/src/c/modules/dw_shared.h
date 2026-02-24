// SPDX-License-Identifier: GPL-2.0
#ifndef __DW_SHARED_H__
#define __DW_SHARED_H__

// #include <linux/types.h>

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

enum {
	DW_REQ_A1    = 1u << 0,
	DW_REQ_A2    = 1u << 1,
	DW_REQ_A3    = 1u << 2,
	DW_REQ_MASK_3 = DW_REQ_A1 | DW_REQ_A2 | DW_REQ_A3,
};

#define DW_XDP_SNAPSHOT_MAX 4096u

enum {
	DW_VERDICT_UNKNOWN = 0,
	DW_VERDICT_PASS    = 1,
	DW_VERDICT_DROP    = 2,
};

#endif
