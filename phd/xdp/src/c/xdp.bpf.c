// // #include "vmlinux.h"
// // #include <bpf/bpf_tracing.h>
// // #include <bpf/bpf_helpers.h>
// // #include <bpf/bpf_endian.h>
// // #define ETH_P_IP        0x0800 /* Internet Protocol v4 */


// // /* kfunc */
// // //int xdp_dummy_deferred_work(void) __ksym;

// // int xdp_schedule_analysis(int analysis_id) __ksym;
// // char LICENSE[] SEC("license") = "GPL";
// // struct conn_key {
// //     u32 saddr;
// //     u32 daddr;
// //     u16 sport;
// //     u16 dport;
// //     u32 seq; 
// // };


// // SEC("xdp")
// // int xdp_ipv4_interceptor(struct xdp_md *ctx)
// // {
// //     void *data_end = (void *)(long)ctx->data_end;
// //     void *data = (void *)(long)ctx->data;
// //     struct ethhdr *eth = data;
// //     struct iphdr *ip;
    
// //     if (data + sizeof(*eth) > data_end)
// //         return XDP_PASS;
    
// //     if (eth->h_proto != bpf_htons(ETH_P_IP))
// //         return XDP_PASS;
    
// //     ip = data + sizeof(*eth);
// //     if ((void *)ip + sizeof(*ip) > data_end)
// //         return XDP_PASS;
    
// //     bpf_printk("IPv4 packet: %pI4h -> %pI4h (proto=%d)", 
// //                &ip->saddr, &ip->daddr, ip->protocol);
    
// //     //xdp_dummy_deferred_work();
// //     // Schedula le analisi 1, 2, 3 su ogni pacchetto
// //     xdp_schedule_analysis(1);
// //     xdp_schedule_analysis(2);
// //     xdp_schedule_analysis(3);
    
// //     return XDP_PASS;
// // }

// // xdp.bpf.c
// // SPDX-License-Identifier: GPL-2.0
// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>

// #define ETH_P_IP 0x0800

// /*
//  * mark format (32 bit):
//  * bit31        : magic (1)
//  * bits[30:24]  : req_mask (bit0..2 => analysis 1..3)
//  * bits[23:0]   : pkt_id (per-cpu counter, wrap ok)
//  */
// #define MARK_MAGIC        0x80000000u
// #define MARK_REQ_SHIFT    24
// #define MARK_ID_MASK      0x00FFFFFFu
// #define REQ_MASK_3ANALYSES 0x07u
// /* xdp.bpf.c (estratto) */

// #define META_MAGIC 0x4D455441u /* "META" */
// #define META_REQ_3 (0x7u)      /* analisi 1..3 */

// /* metadata che XDP scrive e TC legge */
// struct meta {
// 	__u32 magic;
// 	__u8  req_mask;   /* bit0..2 */
// 	__u8  ip_proto;
// 	__be16 dport;
// 	__u32 pkt_id;
// } __attribute__((aligned(4)));

// static __always_inline struct meta *get_meta(struct xdp_md *ctx)
// {
// 	return (struct meta *)(long)ctx->data_meta;
// }

// /* per-packet id semplice (per-cpu counter) */
// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, __u32);
// 	__type(value, __u32);
// } seq_map SEC(".maps");

// static __always_inline __u32 next_pkt_id(void)
// {
// 	__u32 k = 0;
// 	__u32 *v = bpf_map_lookup_elem(&seq_map, &k);
// 	if (!v)
// 		return 0;
// 	*v = *v + 1;
// 	return *v;
// }
// struct hdr_cursor {
//     void *pos;
// };
// static __always_inline 
// int prepare_metadata(struct xdp_md *ctx)
// {
//     void *data     = (void *)(long)ctx->data;

//     int need = -(int)sizeof(struct meta);
//     if (bpf_xdp_adjust_meta(ctx, need) < 0)
//         return XDP_ABORTED;

//     /* Recompute pointers after adjust_meta */
//     void *data_meta = (void *)(long)ctx->data_meta;

//     /* Bounds check: metadata must fit entirely before L2 header */
//     if (data_meta + sizeof(struct meta) > data)
//         return XDP_ABORTED;

//     return 1;
// }

// SEC("xdp")
// int xdp_prog(struct xdp_md *ctx)
// {
//     void *data_end = (void *)(long)ctx->data_end;
//     void *data = (void *)(long)ctx->data;

//     struct hdr_cursor cur;
//     cur.pos = data;

//     if (!prepare_metadata(ctx))
//         return XDP_ABORTED;

//     data_end = (void *)(long)ctx->data_end;
//     data = (void *)(long)ctx->data;
//     cur.pos = data;

//     struct ethhdr *eth;
//     int eth_type = parse_ethhdr(&cur, data_end, &eth);
//     if (unlikely(eth_type < 0)) {
//         bpf_printk("parse_ethhdr failed");
//         return XDP_PASS;
//     }

//     cur_reset_network_header(&cur);

//     __be16 proto = bpf_htons(ETH_P_IP);
//     if (proto != (__be16)eth_type) {
//         bpf_printk("not IP");
//         return XDP_PASS;
//     }

//     struct iphdr *iph;
//     int ip_type = parse_iphdr(&cur, data_end, &iph);
//     if (unlikely(ip_type < 0)) {
//         bpf_printk("parse_iphdr failed");
//         return XDP_PASS;
//     }

//     if (iph->protocol != IPPROTO_UDP) {
//         bpf_printk("not UDP");
//         return XDP_PASS;
//     }

//     struct udphdr *uh;
//     if (parse_udphdr(&cur, data_end, &uh) < 0) {
//         bpf_printk("parse_udphdr failed");
//         return XDP_PASS;
//     }

//     struct meta *md = get_meta(ctx);

//     md->magic    = META_MAGIC;
//     md->req_mask = META_REQ_3;
//     md->ip_proto = iph->protocol;
//     md->dport    = uh->dest;
//     md->pkt_id   = next_pkt_id();

//     return XDP_PASS;
// }

/* xdp.bpf.c - Kernel-level NIDS XDP + Metadata marking */
// #include "vmlinux.h"
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>
// #define ETH_P_IP        0x0800 /* Internet Protocol v4 */


// #define META_MAGIC 0x4D455441u
// #define META_REQ_3 0x7u

// struct meta {
//     __u32 magic;
//     __u8  req_mask;
//     __u8  ip_proto;
//     __be16 dport;
//     __u32 pkt_id;
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, __u32);
// } seq_map SEC(".maps");

// static __always_inline __u32 next_pkt_id(void)
// {
//     __u32 key = 0, *valp, id = 0;
//     valp = bpf_map_lookup_elem(&seq_map, &key);
//     if (valp) {
//         id = *valp + 1;
//         *valp = id;
//     }
//     return id;
// }

// SEC("xdp")
// int xdp_prog(struct xdp_md *ctx)
// {
//     struct meta *meta;
//     void *data_end, *data;
//     int ret;

//     /* Reserve metadata space */
//     ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
//     if (ret < 0)
//         return XDP_ABORTED;

//     /* MUST reload ctx fields after adjust_meta */
//     data_end = (void *)(long)ctx->data_end;
//     data     = (void *)(long)ctx->data;

//     /* Check data_meta bounds vs data */
//     meta = (void *)(long)ctx->data_meta;
//     if (meta + 1 > data)
//         return XDP_PASS;

//     /* Parse Ethernet */
//     struct ethhdr *eth = data;
//     if ((void *)(eth + 1) > data_end)
//         return XDP_PASS;

//     if (eth->h_proto != bpf_htons(ETH_P_IP))
//         return XDP_PASS;

//     /* Parse IPv4 */
//     struct iphdr *iph = (void *)(eth + 1);
//     if ((void *)(iph + 1) > data_end)
//         return XDP_PASS;

//     if (iph->protocol != IPPROTO_UDP)
//         return XDP_PASS;

//     /* Parse UDP */
//     void *l4 = (void *)iph + (iph->ihl * 4);
//     struct udphdr *uh = l4;
//     if ((void *)(uh + 1) > data_end)
//         return XDP_PASS;

//     /* MARK UDP packet */
//     meta->magic    = META_MAGIC;
//     meta->req_mask = META_REQ_3;
//     meta->ip_proto = iph->protocol;
//     meta->dport    = uh->dest;
//     meta->pkt_id   = next_pkt_id();
//     bpf_printk("modified metadata magic number: %d", meta->magic);
//     //scheduling deferred work

//     return XDP_PASS;
// }

// char _license[] SEC("license") = "GPL";


// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "modules/deferred_work.h"


#define ETH_P_IP 0x0800

#define META_MAGIC 0x4D455441u /* "META" */
#define META_REQ_3 0x7u        /* analisi 1..3 */

struct meta {
	__u32 magic;
	__u8  req_mask;   /* bit0..2 */
	__u8  ip_proto;
	__be16 dport;
	__u32 pkt_id;
} __attribute__((aligned(4)));

/* kfunc exported by deferred_work.ko */
extern int dw_register_and_schedule(__u32 pkt_id, __u32 req_mask) __ksym;

/* per-packet id: per-CPU counter */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} seq_map SEC(".maps");

static __always_inline __u32 next_pkt_id(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&seq_map, &k);
	if (!v)
		return 0;
	*v = *v + 1;
	return *v;
}

SEC("xdp")
int xdp_udp_mark_and_schedule(struct xdp_md *ctx)
{
	void *data_end, *data;
	struct meta *md;
	int ret;

	/* Reserve metadata */
	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*md));
	if (ret < 0)
		return XDP_PASS;

	/* reload pointers after adjust_meta */
	data_end = (void *)(long)ctx->data_end;
	data     = (void *)(long)ctx->data;
	md       = (void *)(long)ctx->data_meta;

	if ((void *)(md + 1) > data)
		return XDP_PASS;

	/* Parse Ethernet */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* Parse IPv4 */
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->version != 4)
		return XDP_PASS;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Parse UDP */
	void *l4 = (void *)iph + (iph->ihl * 4);
	struct udphdr *uh = l4;
	if ((void *)(uh + 1) > data_end)
		return XDP_PASS;

	/* Fill metadata */
	__u32 id = next_pkt_id();

	md->magic    = META_MAGIC;
	md->req_mask = META_REQ_3;
	md->ip_proto = iph->protocol;
	md->dport    = uh->dest;
	md->pkt_id   = id;

	/* Schedule analyses in kernel module */
	dw_register_and_schedule(id, META_REQ_3);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
