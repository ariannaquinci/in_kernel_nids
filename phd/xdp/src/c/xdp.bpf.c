// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "modules/dw_shared.h"
#include "workload_shared.h"

#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

struct dw_vlan_hdr {
	__be16 tci;
	__be16 enc_proto;
};

/* kfunc esportate dal modulo kernel */
extern int dw_meta_put(struct dw_pkt_key *key, __u32 pkt_id, __u32 req_mask) __ksym;
extern int dw_pkt_snapshot_put(const __u8 *data, __u32 len, __u32 pkt_id) __ksym;
extern int dw_register_and_schedule(__u32 pkt_id, __u32 req_mask) __ksym;

/* per-cpu sequence used to build pkt_id without XADD return usage */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} seq_map SEC(".maps");

/* per-cpu counter for failed kernel kfunc correlation inserts */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} meta_put_fail_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct workload_state);
} workload_state_map SEC(".maps");

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
	 * Avoid XADD return-value usage (rejected by some BPF backends).
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

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	void *nh;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *uh;
	__be16 h_proto;
	int i;
	int rc;
	__u32 frame_len;
	__u32 req_mask = DW_REQ_MASK_3;
	__u32 budget_key = DW_WORKLOAD_MAP_KEY;
	struct workload_state *ws;

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

	if (iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

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

	bpf_printk("key: 0x%x, 0x%x,0x%x,0x%x,0x%x, %d, 0x%x", key.saddr, key.daddr, key.sport, key.dport, key.ip_id, key.udp_len, key.proto);
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

	/* 1) registra correlazione */
	rc = dw_meta_put(&key, pkt_id, req_mask);
	count_meta_put_fail(rc);
	if (rc < 0)
		return XDP_PASS;

	/* 2) schedule analisi */
	dw_register_and_schedule(pkt_id, req_mask);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
