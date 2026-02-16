// SPDX-License-Identifier: GPL-2.0
#ifndef __DEFERRED_WORK_H__
#define __DEFERRED_WORK_H__

#include <linux/types.h>
#include <linux/skbuff.h>
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
};

/* API used by Netfilter module */
bool dw_is_bypass_skb(struct sk_buff *skb);

u32  dw_get_done_mask(u32 pkt_id);
bool dw_are_done(u32 pkt_id, u32 req_mask, u32 *done_out);

int  dw_buffer_marked_skb(struct sk_buff *skb, u32 pkt_id, u32 req_mask, u32 mark_dummy);

/* correlation store */
bool dw_meta_get_and_del(struct dw_pkt_key *key, u32 *pkt_id_out, u32 *req_mask_out);

#endif
