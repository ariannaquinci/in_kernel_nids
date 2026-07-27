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
bool dw_analysis_done(u32 pkt_id);

/* verdict: 0=UNKNOWN, 1=PASS, 2=DROP */
int  dw_get_verdict(u32 pkt_id);
void dw_note_payload_signature(u32 pkt_id, bool is_malicious);

bool dw_nfqueue_is_stopping(void);
void dw_begin_nfqueue_stop(void);
bool dw_udp_inline_analysis_enabled(void);
bool dw_udp_single_worker_enabled(void);
bool dw_udp_try_fast_accept_done(struct sk_buff *skb, u32 pkt_id);
void dw_udp_cleanup_packet(u32 pkt_id);

/* fallback Netfilter per pacchetti IPv4/UDP arrivati da defrag */
int  dw_schedule_skb_deferred(struct sk_buff *skb, u32 *pkt_id_out);

/* XDP/meta path: run UDP analysis synchronously in the current networking context */
int  dw_analyze_pkt_inline(u32 pkt_id);

/* producer skb-side: correlation + deferred analysis without packet copy */
int  dw_schedule_skb_ref_deferred(struct sk_buff *skb, struct dw_pkt_key *key,
				  u32 *pkt_id_out);

/* fallback Netfilter: deferred analysis without packet copy and without meta publish */
int  dw_schedule_skb_ref_deferred_nometa(struct sk_buff *skb, u32 *pkt_id_out);

/* bufferizzazione via NFQUEUE: 1 buffered, 0 dropped immediately */
int  dw_buffer_nfqueue_entry(struct nf_queue_entry *entry, u32 pkt_id);
void dw_quiesce_nfqueue(void);

/* correlazione XDP->skb */
bool dw_meta_get_and_del(struct dw_pkt_key *key, u32 *pkt_id_out);

#endif
