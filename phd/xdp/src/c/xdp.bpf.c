// // char _license[] SEC("license") = "GPL";

// // SPDX-License-Identifier: GPL-2.0
// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/udp.h>

// #include "modules/deferred_work.h"

// #define META_REQ_3 0x7u

// /* kfunc exported by deferred_analysis.ko */
// extern int dw_register_and_schedule(__u32 pkt_id, __u32 req_mask) __ksym;
// extern int dw_meta_put(const struct dw_pkt_key *key, __u32 pkt_id, __u32 req_mask) __ksym;

// /* per-CPU counter */
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

// SEC("xdp")
// int xdp_udp_schedule_and_correlate(struct xdp_md *ctx)
// {
// 	void *data_end = (void *)(long)ctx->data_end;
// 	void *data     = (void *)(long)ctx->data;

// 	struct ethhdr *eth = data;
// 	if ((void *)(eth + 1) > data_end)
// 		return XDP_PASS;

// 	if (eth->h_proto != bpf_htons(ETH_P_IP))
// 		return XDP_PASS;

// 	struct iphdr *iph = (void *)(eth + 1);
// 	if ((void *)(iph + 1) > data_end)
// 		return XDP_PASS;

// 	if (iph->version != 4)
// 		return XDP_PASS;

// 	if (iph->protocol != IPPROTO_UDP)
// 		return XDP_PASS;

// 	void *l4 = (void *)iph + (iph->ihl * 4);
// 	struct udphdr *uh = l4;
// 	if ((void *)(uh + 1) > data_end)
// 		return XDP_PASS;

// 	/* build key (fingerprint) */
// 	struct dw_pkt_key key = {};
// 	key.saddr   = iph->saddr;
// 	key.daddr   = iph->daddr;
// 	key.sport   = uh->source;
// 	key.dport   = uh->dest;
// 	key.ip_id   = iph->id;       /* network-endian ok if consistent */
// 	key.udp_len = uh->len;       /* network-endian ok if consistent */
// 	key.proto   = iph->protocol;

// 	__u32 pkt_id  = next_pkt_id();
// 	__u32 req_mask = META_REQ_3;

// 	/* schedule analyses */
// 	dw_register_and_schedule(pkt_id, req_mask);

// 	/* store correlation for later (Netfilter will consume) */
// 	dw_meta_put(&key, pkt_id, req_mask);

// 	return XDP_PASS;
// }

// char _license[] SEC("license") = "GPL";


// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "modules/dw_shared.h"

#define ETH_P_IP 0x0800

/* kfunc esportate dal modulo kernel */
extern int dw_meta_put(struct dw_pkt_key *key, __u32 pkt_id, __u32 req_mask) __ksym;
extern int dw_register_and_schedule(__u32 pkt_id, __u32 req_mask) __ksym;

/* per-cpu pkt_id counter */
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
int xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	void *l4 = (void *)iph + (iph->ihl * 4);
	struct udphdr *uh = l4;
	if ((void *)(uh + 1) > data_end)
		return XDP_PASS;

	struct dw_pkt_key key = {};
	key.saddr   = iph->saddr;
	key.daddr   = iph->daddr;
	key.sport   = uh->source;
	key.dport   = uh->dest;
	key.ip_id   = iph->id;
	key.udp_len = uh->len;
	key.proto   = iph->protocol;

	bpf_printk("key: 0x%x, 0x%x,0x%x,0x%x,0x%x, %d, 0x%x", key.saddr, key.daddr, key.sport, key.dport, key.ip_id, key.udp_len, key.proto);
	__u32 pkt_id = next_pkt_id();
	if (!pkt_id)
		return XDP_PASS;

	/* 1) registra correlazione */
	dw_meta_put(&key, pkt_id, DW_REQ_MASK_3);

	/* 2) schedule analisi */
	dw_register_and_schedule(pkt_id, DW_REQ_MASK_3);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
