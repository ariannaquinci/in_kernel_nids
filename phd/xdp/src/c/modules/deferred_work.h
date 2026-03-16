// SPDX-License-Identifier: GPL-2.0
#ifndef __DEFERRED_WORK_H__
#define __DEFERRED_WORK_H__

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_queue.h>
#include "dw_shared.h"

#define DW_NFQ_BUFFERED 1
#define DW_NFQ_DROPPED  0

/* stato completamento */
u32  dw_get_done_mask(u32 pkt_id);
bool dw_are_done(u32 pkt_id, u32 req_mask, u32 *done_out);

/* verdict: 0=UNKNOWN, 1=PASS, 2=DROP */
int  dw_get_verdict(u32 pkt_id);
void dw_note_payload_signature(u32 pkt_id, u32 req_mask, bool is_malicious);

/* bufferizzazione via NFQUEUE: 1 buffered, 0 dropped immediately */
int  dw_buffer_nfqueue_entry(struct nf_queue_entry *entry, u32 pkt_id, u32 req_mask);

/* correlazione XDP->skb */
bool dw_meta_get_and_del(struct dw_pkt_key *key, u32 *pkt_id_out, u32 *req_mask_out);

#endif
