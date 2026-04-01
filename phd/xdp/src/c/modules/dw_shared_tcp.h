// SPDX-License-Identifier: GPL-2.0
#ifndef __DW_SHARED_TCP_H__
#define __DW_SHARED_TCP_H__

struct dw_tcp_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  proto;
	__u8  pad1;
	__u16 pad2;
} __attribute__((packed));

struct dw_tcp_pkt_key {
	struct dw_tcp_flow_key flow;
	__u32 seq;
	__u32 ack;
	__u16 win;
	__u8  flags;
	__u8  doff_words;
} __attribute__((packed));

#endif
