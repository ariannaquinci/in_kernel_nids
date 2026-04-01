// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "modules/dw_policy.h"
#include "modules/dw_shared_udp.h"
#include "modules/dw_shared_tcp.h"
#include "workload_shared.h"

#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#ifdef DW_XDP_TCP_ONLY
#define DW_XDP_DEFAULT_MONITOR_MASK DW_MON_TCP
#else
#define DW_XDP_DEFAULT_MONITOR_MASK DW_MON_UDP
#endif

struct dw_vlan_hdr {
	__be16 tci;
	__be16 enc_proto;
};

/* kfuncs exported by the kernel module */
#ifndef DW_XDP_TCP_ONLY
extern int dw_meta_put(struct dw_pkt_key *key, __u32 pkt_id, __u32 req_mask) __ksym;
extern int dw_pkt_snapshot_put(const __u8 *data, __u32 len, __u32 pkt_id) __ksym;
extern int dw_register_and_schedule(__u32 pkt_id, __u32 req_mask) __ksym;
#endif

/* Per-CPU sequence used to build pkt_id without XADD return usage. */
#ifndef DW_XDP_TCP_ONLY
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} seq_map SEC(".maps");

/* Per-CPU counter for failed kernel kfunc correlation inserts. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} meta_put_fail_map SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct workload_state);
} workload_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dw_monitor_policy);
} monitor_policy_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} tcp_candidate_counter_map SEC(".maps");

#ifndef DW_XDP_TCP_ONLY
static __always_inline __u32 next_pkt_id(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&seq_map, &k);
	__u32 seq;
	__u32 cpu;
	__u32 id;

	if (!v)
		return 0;

	/*
	 * Avoid XADD return-value usage, which some BPF backends reject.
	 * Compose pkt_id as [cpu_id:8 | per_cpu_seq:24].
	 */
	seq = ++(*v);
	if (!seq)
		seq = ++(*v);

	cpu = bpf_get_smp_processor_id() & 0xff;
	id = (cpu << 24) | (seq & 0x00ffffff);

	return id;
}

static __always_inline void count_meta_put_fail(int rc)
{
	__u32 k = 0;
	__u64 *v;

	if (rc >= 0)
		return;

	v = bpf_map_lookup_elem(&meta_put_fail_map, &k);
	if (v)
		*v = *v + 1;

	bpf_printk("dw_meta_put failed rc=%d", rc);
}
#endif

static __always_inline __u32 monitor_mask_for_packet(void)
{
	__u32 k = DW_POLICY_MAP_KEY;
	struct dw_monitor_policy *policy;

	policy = bpf_map_lookup_elem(&monitor_policy_map, &k);
	if (!policy)
		return DW_XDP_DEFAULT_MONITOR_MASK;

	return dw_policy_sanitize_mask(policy->monitor_mask);
}

static __always_inline void note_tcp_candidate(void)
{
	__u32 k = 0;
	__u64 *v;

	v = bpf_map_lookup_elem(&tcp_candidate_counter_map, &k);
	if (v)
		*v = *v + 1;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	void *nh;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *uh;
	struct tcphdr *th;
	__be16 h_proto;
	int i;
#ifndef DW_XDP_TCP_ONLY
	int rc;
	__u32 frame_len;
	__u32 req_mask = DW_REQ_MASK_3;
	__u32 budget_key = DW_WORKLOAD_MAP_KEY;
#endif
	__u32 monitor_mask;
#ifndef DW_XDP_TCP_ONLY
	struct workload_state *ws;
#endif

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	nh = (void *)(eth + 1);
	h_proto = eth->h_proto;

#pragma unroll
	for (i = 0; i < 2; i++) {
		struct dw_vlan_hdr *vh;

		if (h_proto != bpf_htons(ETH_P_8021Q) &&
		    h_proto != bpf_htons(ETH_P_8021AD))
			break;

		vh = nh;
		if ((void *)(vh + 1) > data_end)
			return XDP_PASS;

		h_proto = vh->enc_proto;
		nh = (void *)(vh + 1);
	}

	if (h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = nh;
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->version != 4)
		return XDP_PASS;

	monitor_mask = monitor_mask_for_packet();

	if (iph->protocol == IPPROTO_TCP) {
		if (!(monitor_mask & DW_MON_TCP))
			return XDP_PASS;

		th = (void *)iph + (iph->ihl * 4);
		if ((void *)(th + 1) > data_end)
			return XDP_PASS;

		/*
		 * TCP handling stays in dedicated backend modules.
		 * XDP is the shared front-end classifier and records visibility
		 * for TCP packets only when that monitoring class is enabled.
		 */
		note_tcp_candidate();
		return XDP_PASS;
	}

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	if (!(monitor_mask & DW_MON_UDP))
		return XDP_PASS;

#ifdef DW_XDP_TCP_ONLY
	return XDP_PASS;
#else
	uh = (void *)iph + (iph->ihl * 4);
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

	__u32 pkt_id = next_pkt_id();
	if (!pkt_id)
		return XDP_PASS;

	frame_len = (__u32)((long)data_end - (long)data);
	rc = dw_pkt_snapshot_put(data, frame_len, pkt_id);
	if (rc < 0)
		bpf_printk("dw_pkt_snapshot_put failed rc=%d pkt_id=%u", rc, pkt_id);

	ws = bpf_map_lookup_elem(&workload_state_map, &budget_key);
	if (ws)
		req_mask = dw_apply_deferred_budget(req_mask, ws->deferred_budget);
	else
		req_mask = dw_apply_deferred_budget(req_mask, DW_WORKLOAD_DEFAULT_BUDGET);

	/* Step 1: register correlation for the UDP backend. */
	rc = dw_meta_put(&key, pkt_id, req_mask);
	count_meta_put_fail(rc);
	if (rc < 0)
		return XDP_PASS;

	/* Step 2: schedule deferred analyses for the UDP backend. */
	dw_register_and_schedule(pkt_id, req_mask);

	return XDP_PASS;
#endif
}

char _license[] SEC("license") = "GPL";
