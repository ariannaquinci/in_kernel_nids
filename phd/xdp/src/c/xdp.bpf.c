// // // SPDX-License-Identifier: GPL-2.0
// // #include "vmlinux.h"
// // #include <bpf/bpf_helpers.h>
// // #include <bpf/bpf_endian.h>
// // #include "modules/dw_policy.h"
// // #include "modules/dw_shared_udp.h"
// // #include "modules/dw_shared_tcp.h"
// // #include "workload_shared.h"

// // #define ETH_P_IP 0x0800
// // #define ETH_P_8021Q 0x8100
// // #define ETH_P_8021AD 0x88A8
// // #define DW_IP_MF 0x2000
// // #define DW_IP_OFFSET 0x1fff

// // #ifdef DW_XDP_TCP_ONLY
// // #define DW_XDP_DEFAULT_MONITOR_MASK DW_MON_TCP
// // #else
// // #define DW_XDP_DEFAULT_MONITOR_MASK DW_MON_UDP
// // #endif

// // struct dw_vlan_hdr {
// // 	__be16 tci;
// // 	__be16 enc_proto;
// // };

// // /* kfuncs exported by the kernel module */
// // #ifndef DW_XDP_TCP_ONLY
// // extern int dw_state_init(__u32 pkt_id, __u32 req_mask) __ksym;
// // extern int dw_meta_put(struct dw_pkt_key *key, __u32 pkt_id, __u32 req_mask) __ksym;
// // extern int dw_pkt_snapshot_put(const __u8 *data, __u32 len, __u32 pkt_id) __ksym;
// // extern int dw_register_and_schedule(__u32 pkt_id, __u32 req_mask) __ksym;
// // #endif

// // /* Per-CPU sequence used to build pkt_id without XADD return usage. */
// // #ifndef DW_XDP_TCP_ONLY
// // struct {
// // 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// // 	__uint(max_entries, 1);
// // 	__type(key, __u32);
// // 	__type(value, __u32);
// // } seq_map SEC(".maps");

// // /* Per-CPU counter for failed kernel kfunc correlation inserts. */
// // struct {
// // 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// // 	__uint(max_entries, 1);
// // 	__type(key, __u32);
// // 	__type(value, __u64);
// // } meta_put_fail_map SEC(".maps");
// // #endif

// // struct {
// // 	__uint(type, BPF_MAP_TYPE_ARRAY);
// // 	__uint(max_entries, 1);
// // 	__type(key, __u32);
// // 	__type(value, struct workload_state);
// // } workload_state_map SEC(".maps");

// // struct {
// // 	__uint(type, BPF_MAP_TYPE_ARRAY);
// // 	__uint(max_entries, 1);
// // 	__type(key, __u32);
// // 	__type(value, struct dw_monitor_policy);
// // } monitor_policy_map SEC(".maps");

// // struct {
// // 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// // 	__uint(max_entries, 1);
// // 	__type(key, __u32);
// // 	__type(value, __u64);
// // } tcp_candidate_counter_map SEC(".maps");

// // #ifndef DW_XDP_TCP_ONLY
// // static __always_inline __u32 next_pkt_id(void)
// // {
// // 	__u32 k = 0;
// // 	__u32 *v = bpf_map_lookup_elem(&seq_map, &k);
// // 	__u32 seq;
// // 	__u32 cpu;
// // 	__u32 id;

// // 	if (!v)
// // 		return 0;

// // 	/*
// // 	 * Avoid XADD return-value usage, which some BPF backends reject.
// // 	 * Compose pkt_id as [cpu_id:8 | per_cpu_seq:24].
// // 	 */
// // 	seq = ++(*v);
// // 	if (!seq)
// // 		seq = ++(*v);

// // 	cpu = bpf_get_smp_processor_id() & 0xff;
// // 	id = (cpu << 24) | (seq & 0x00ffffff);

// // 	return id;
// // }

// // static __always_inline void count_meta_put_fail(int rc)
// // {
// // 	__u32 k = 0;
// // 	__u64 *v;

// // 	if (rc >= 0)
// // 		return;

// // 	v = bpf_map_lookup_elem(&meta_put_fail_map, &k);
// // 	if (v)
// // 		*v = *v + 1;

// // 	bpf_printk("dw_meta_put failed rc=%d", rc);
// // }
// // #endif

// // static __always_inline __u32 monitor_mask_for_packet(void)
// // {
// // 	__u32 k = DW_POLICY_MAP_KEY;
// // 	struct dw_monitor_policy *policy;

// // 	policy = bpf_map_lookup_elem(&monitor_policy_map, &k);
// // 	if (!policy)
// // 		return DW_XDP_DEFAULT_MONITOR_MASK;

// // 	return dw_policy_sanitize_mask(policy->monitor_mask);
// // }

// // static __always_inline void note_tcp_candidate(void)
// // {
// // 	__u32 k = 0;
// // 	__u64 *v;

// // 	v = bpf_map_lookup_elem(&tcp_candidate_counter_map, &k);
// // 	if (v)
// // 		*v = *v + 1;
// // }

// // SEC("xdp")
// // int xdp_prog(struct xdp_md *ctx)
// // {
// // 	void *data_end = (void *)(long)ctx->data_end;
// // 	void *data     = (void *)(long)ctx->data;
// // 	void *nh;
// // 	struct ethhdr *eth = data;
// // 	struct iphdr *iph;
// // 	struct udphdr *uh;
// // 	struct tcphdr *th;
// // 	__be16 h_proto;
// // 	int i;
// // #ifndef DW_XDP_TCP_ONLY
// // 	int rc;
// // 	__u32 frame_len;
// // 	__u32 req_mask = DW_REQ_MASK_3;
// // 	__u32 budget_key = DW_WORKLOAD_MAP_KEY;
// // #endif
// // 	__u32 monitor_mask;
// // #ifndef DW_XDP_TCP_ONLY
// // 	struct workload_state *ws;
// // #endif

// // 	if ((void *)(eth + 1) > data_end)
// // 		return XDP_PASS;

// // 	nh = (void *)(eth + 1);
// // 	h_proto = eth->h_proto;

// // #pragma unroll
// // 	for (i = 0; i < 2; i++) {
// // 		struct dw_vlan_hdr *vh;

// // 		if (h_proto != bpf_htons(ETH_P_8021Q) &&
// // 		    h_proto != bpf_htons(ETH_P_8021AD))
// // 			break;

// // 		vh = nh;
// // 		if ((void *)(vh + 1) > data_end)
// // 			return XDP_PASS;

// // 		h_proto = vh->enc_proto;
// // 		nh = (void *)(vh + 1);
// // 	}

// // 	if (h_proto != bpf_htons(ETH_P_IP))
// // 		return XDP_PASS;

// // 	iph = nh;
// // 	if ((void *)(iph + 1) > data_end)
// // 		return XDP_PASS;

// // 	if (iph->version != 4)
// // 		return XDP_PASS;

// // 	if (bpf_ntohs(iph->frag_off) & (DW_IP_MF | DW_IP_OFFSET))
// // 		return XDP_PASS;

// // 	monitor_mask = monitor_mask_for_packet();

// // 	if (iph->protocol == IPPROTO_TCP) {
// // 		if (!(monitor_mask & DW_MON_TCP))
// // 			return XDP_PASS;

// // 		th = (void *)iph + (iph->ihl * 4);
// // 		if ((void *)(th + 1) > data_end)
// // 			return XDP_PASS;

// // 		/*
// // 		 * TCP handling stays in dedicated backend modules.
// // 		 * XDP is the shared front-end classifier and records visibility
// // 		 * for TCP packets only when that monitoring class is enabled.
// // 		 */
// // 		note_tcp_candidate();
// // 		return XDP_PASS;
// // 	}

// // 	if (iph->protocol != IPPROTO_UDP)
// // 		return XDP_PASS;

// // 	if (!(monitor_mask & DW_MON_UDP))
// // 		return XDP_PASS;

// // #ifdef DW_XDP_TCP_ONLY
// // 	return XDP_PASS;
// // #else
// // 	uh = (void *)iph + (iph->ihl * 4);
// // 	if ((void *)(uh + 1) > data_end)
// // 		return XDP_PASS;

// // 	struct dw_pkt_key key = {};
// // 	key.saddr   = iph->saddr;
// // 	key.daddr   = iph->daddr;
// // 	key.sport   = uh->source;
// // 	key.dport   = uh->dest;
// // 	key.ip_id   = iph->id;
// // 	key.udp_len = uh->len;
// // 	key.proto   = iph->protocol;

// // 	__u32 pkt_id = next_pkt_id();
// // 	if (!pkt_id)
// // 		return XDP_PASS;

// // 	frame_len = (__u32)((long)data_end - (long)data);
// // 	rc = dw_pkt_snapshot_put(data, frame_len, pkt_id);
// // 	if (rc < 0)
// // 		bpf_printk("dw_pkt_snapshot_put failed rc=%d pkt_id=%u", rc, pkt_id);

// // 	ws = bpf_map_lookup_elem(&workload_state_map, &budget_key);
// // 	if (ws)
// // 		req_mask = dw_apply_deferred_budget(req_mask, ws->deferred_budget);
// // 	else
// // 		req_mask = dw_apply_deferred_budget(req_mask, DW_WORKLOAD_DEFAULT_BUDGET);

// // 	/* Step 1: create per-packet state before any deferred scheduling. */
// // 	rc = dw_state_init(pkt_id, req_mask);
// // 	if (rc < 0) {
// // 		bpf_printk("dw_state_init failed rc=%d pkt_id=%u", rc, pkt_id);
// // 		return XDP_PASS;
// // 	}

// // 	/* Step 2: register correlation for the UDP backend. */
// // 	rc = dw_meta_put(&key, pkt_id, req_mask);
// // 	count_meta_put_fail(rc);
// // 	if (rc < 0)
// // 		return XDP_PASS;

// // 	/* Step 3: schedule deferred analyses for the UDP backend. */
// // 	dw_register_and_schedule(pkt_id, req_mask);

// // 	return XDP_PASS;
// // #endif
// // }

// // char _license[] SEC("license") = "GPL";
// // SPDX-License-Identifier: GPL-2.0

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>
// #include <bpf/bpf_tracing.h>

// struct udp_recvmsg_ts {
// 	__u64 enter_ns;
// 	__u64 exit_ns;
// 	__u64 delta_ns;
// 	__u64 pid_tgid;
// 	__u32 cpu;
// 	__s32 ret;
// };

// #ifndef DW_UDP_RECVMSG_ONLY
// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, __u32);
// 	__type(value, __u64);
// } xdp_timestamp_ns_map SEC(".maps");
// #endif

// #ifdef DW_UDP_RECVMSG_ONLY
// struct {
// 	__uint(type, BPF_MAP_TYPE_LRU_HASH);
// 	__uint(max_entries, 16384);
// 	__type(key, __u64);
// 	__type(value, __u64);
// } udp_recvmsg_enter_ns_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, __u32);
// 	__type(value, struct udp_recvmsg_ts);
// } udp_recvmsg_last_ts_map SEC(".maps");
// #endif

// #ifndef DW_UDP_RECVMSG_ONLY
// SEC("xdp")
// int xdp_prog(struct xdp_md *ctx){
// 	__u32 key = 0;
// 	__u64 now_ns;

// 	now_ns = bpf_ktime_get_ns();
// 	bpf_map_update_elem(&xdp_timestamp_ns_map, &key, &now_ns, BPF_ANY);

// 	return XDP_PASS;
// }
// #endif

// SEC("kprobe/udp_recvmsg")
// int BPF_KPROBE(trace_udp_recvmsg_enter)
// {
// 	__u64 pid_tgid = bpf_get_current_pid_tgid();
// 	__u64 now = bpf_ktime_get_ns();

// 	bpf_map_update_elem(&udp_recvmsg_enter_ns_map, &pid_tgid, &now, BPF_ANY);
// 	return 0;
// }

// SEC("kretprobe/udp_recvmsg")
// int BPF_KRETPROBE(trace_udp_recvmsg_exit, int ret)
// {
// 	__u32 key = 0;
// 	__u64 pid_tgid = bpf_get_current_pid_tgid();
// 	__u64 now = bpf_ktime_get_ns();
// 	__u64 *enter_ns;
// 	struct udp_recvmsg_ts ts = {};

// 	enter_ns = bpf_map_lookup_elem(&udp_recvmsg_enter_ns_map, &pid_tgid);
// 	if (!enter_ns)
// 		return 0;

// 	ts.enter_ns = *enter_ns;
// 	ts.exit_ns = now;
// 	if (now > ts.enter_ns)
// 		ts.delta_ns = now - ts.enter_ns;
// 	ts.pid_tgid = pid_tgid;
// 	ts.cpu = bpf_get_smp_processor_id();
// 	ts.ret = ret;

// 	bpf_map_update_elem(&udp_recvmsg_last_ts_map, &key, &ts, BPF_ANY);
// 	bpf_map_delete_elem(&udp_recvmsg_enter_ns_map, &pid_tgid);
// 	return 0;
// }


// char _license[] SEC("license") = "GPL";



#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define MAX_VLAN_DEPTH 2
#ifndef LATENCY_FILTER_SPORT
#define LATENCY_FILTER_SPORT 5555
#endif
#ifndef LATENCY_FILTER_DPORT
#define LATENCY_FILTER_DPORT 9999
#endif

struct dw_latency_vlan_hdr {
	__be16 tci;
	__be16 enc_proto;
};

struct flow_key {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__be16 ip_id;
	__be16 udp_len;
	__u8 proto;
};

struct path_latency_stats {
	__u64 samples;
	__u64 total_delta_ns;
	__u64 avg_delta_ns;
	__u64 min_delta_ns;
	__u64 max_delta_ns;
	__u64 xdp_hook_samples;
	__u64 xdp_hook_total_ns;
	__u64 xdp_hook_avg_ns;
	__u64 xdp_hook_min_ns;
	__u64 xdp_hook_max_ns;
	__u64 rx_hook_samples;
	__u64 rx_hook_total_ns;
	__u64 rx_hook_avg_ns;
	__u64 rx_hook_min_ns;
	__u64 rx_hook_max_ns;
	__u64 xdp_seen;
	__u64 udp_seen;
	__u64 xdp_parse_fail;
	__u64 udp_parse_fail;
	__u64 lookup_miss;
};

#define PATH_LATENCY_SAMPLE_MAX 262144

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} latency_pkt_seq_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} xdp_timestamp_ns_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, __u64);
} xdp_ingress_ts_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct path_latency_stats);
} path_latency_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PATH_LATENCY_SAMPLE_MAX);
	__type(key, __u32);
	__type(value, __u64);
} path_latency_samples_map SEC(".maps");


static __always_inline void stats_inc(__u64 *counter)
{
	__sync_fetch_and_add(counter, 1);
}

static __always_inline __u64 record_ns_metric(__u64 delta_ns,
					     __u64 *samples_p,
					     __u64 *total_p,
					     __u64 *avg_p,
					     __u64 *min_p,
					     __u64 *max_p)
{
	__u64 samples;
	__u64 total;
	__u64 old;

	samples = __sync_fetch_and_add(samples_p, 1) + 1;
	total = __sync_fetch_and_add(total_p, delta_ns) + delta_ns;
	*avg_p = total / samples;

	old = *min_p;
	if (old == 0 || delta_ns < old)
		*min_p = delta_ns;

	old = *max_p;
	if (delta_ns > old)
		*max_p = delta_ns;

	return samples;
}

static __always_inline __be16 csum_replace16(__be16 check, __be16 old,
					     __be16 new)
{
	__u32 csum;

	csum = (~bpf_ntohs(check) & 0xffff) +
	       (~bpf_ntohs(old) & 0xffff) +
	       bpf_ntohs(new);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return bpf_htons((__u16)~csum);
}

static __always_inline __be16 next_latency_ip_id(void)
{
	__u32 key = 0;
	__u32 *seq;
	__u32 cpu;
	__u16 id;

	seq = bpf_map_lookup_elem(&latency_pkt_seq_map, &key);
	if (!seq)
		return 0;

	*seq += 1;
	cpu = bpf_get_smp_processor_id();
	id = (cpu & 0x3f) << 10;
	id |= *seq & 0x03ff;
	if (!id)
		id = 1;

	return bpf_htons(id);
}

static __always_inline int parse_l4_ports(void *hdr, void *data_end,
					  __u8 proto, struct flow_key *key)
{
	struct udphdr *udp;

	if (proto == IPPROTO_UDP) {
		udp = hdr;
		if ((void *)(udp + 1) > data_end)
			return -1;
		key->sport = udp->source;
		key->dport = udp->dest;
		key->udp_len = udp->len;
		return 0;
	}

	return -1;
}

static __always_inline bool flow_is_latency_target(const struct flow_key *key)
{
	return key->sport == bpf_htons(LATENCY_FILTER_SPORT) &&
	       key->dport == bpf_htons(LATENCY_FILTER_DPORT);
}

static __always_inline int stamp_xdp_latency_id(struct iphdr *iph)
{
	__be16 old_id;
	__be16 new_id;

	new_id = next_latency_ip_id();
	if (!new_id)
		return -1;

	old_id = iph->id;
	iph->id = new_id;
	iph->check = csum_replace16(iph->check, old_id, new_id);
	return 0;
}

static __always_inline int parse_xdp_flow(struct xdp_md *ctx,
					  struct flow_key *key)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *nh;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	__be16 h_proto;
	__u16 frag_off;
	__u32 ihl_len;
	int i;

	if ((void *)(eth + 1) > data_end)
		return -1;

	nh = (void *)(eth + 1);
	h_proto = eth->h_proto;

#pragma unroll
	for (i = 0; i < MAX_VLAN_DEPTH; i++) {
		struct dw_latency_vlan_hdr *vh;

		if (h_proto != bpf_htons(ETH_P_8021Q) &&
		    h_proto != bpf_htons(ETH_P_8021AD))
			break;

		vh = nh;
		if ((void *)(vh + 1) > data_end)
			return -1;

		h_proto = vh->enc_proto;
		nh = (void *)(vh + 1);
	}

	if (h_proto != bpf_htons(ETH_P_IP))
		return -1;

	iph = nh;
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->version != 4)
		return -1;
	if (iph->protocol != IPPROTO_UDP)
		return -1;

	frag_off = bpf_ntohs(iph->frag_off);
	if (frag_off & (IP_MF | IP_OFFSET))
		return -1;

	ihl_len = iph->ihl * 4;
	if (ihl_len < sizeof(*iph))
		return -1;
	if ((void *)iph + ihl_len > data_end)
		return -1;

	key->saddr = iph->saddr;
	key->daddr = iph->daddr;
	key->proto = iph->protocol;

	if (parse_l4_ports((void *)iph + ihl_len, data_end, iph->protocol, key) < 0)
		return -1;
	if (!flow_is_latency_target(key))
		return -1;
	if (stamp_xdp_latency_id(iph) < 0)
		return -1;

	key->ip_id = iph->id;
	return 0;
}

static __always_inline int parse_skb_flow(struct sk_buff *skb,
					  struct flow_key *key)
{
	unsigned char *head;
	__u16 network_header;
	struct iphdr iph;
	__u16 frag_off;
	__u32 ihl_len;
	void *iph_addr;

	if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
		return -1;
	if (bpf_probe_read_kernel(&network_header, sizeof(network_header),
				  &skb->network_header) < 0)
		return -1;
	if (!head)
		return -1;

	iph_addr = head + network_header;
	if (bpf_probe_read_kernel(&iph, sizeof(iph), iph_addr) < 0)
		return -1;
	if (iph.version != 4)
		return -1;
	if (iph.protocol != IPPROTO_UDP)
		return -1;

	frag_off = bpf_ntohs(iph.frag_off);
	if (frag_off & (IP_MF | IP_OFFSET))
		return -1;

	ihl_len = iph.ihl * 4;
	if (ihl_len < sizeof(iph))
		return -1;

	key->saddr = iph.saddr;
	key->daddr = iph.daddr;
	key->ip_id = iph.id;
	key->proto = iph.protocol;

	if (iph.protocol == IPPROTO_UDP) {
		struct udphdr udp;

		if (bpf_probe_read_kernel(&udp, sizeof(udp), iph_addr + ihl_len) < 0)
			return -1;
		key->sport = udp.source;
		key->dport = udp.dest;
		key->udp_len = udp.len;
		return flow_is_latency_target(key) ? 0 : -1;
	}

	return -1;
}

static __always_inline void record_path_latency(__u64 delta_ns)
{
	__u32 key = 0;
	__u32 sample_key;
	__u64 sample_nr;
	struct path_latency_stats *stats;

	stats = bpf_map_lookup_elem(&path_latency_stats_map, &key);
	if (!stats)
		return;

	sample_nr = record_ns_metric(delta_ns, &stats->samples,
				     &stats->total_delta_ns,
				     &stats->avg_delta_ns,
				     &stats->min_delta_ns,
				     &stats->max_delta_ns);
	if (sample_nr > 0 && sample_nr <= PATH_LATENCY_SAMPLE_MAX) {
		sample_key = sample_nr - 1;
		bpf_map_update_elem(&path_latency_samples_map, &sample_key,
				    &delta_ns, BPF_ANY);
	}
}

static __always_inline void record_xdp_hook_overhead(struct path_latency_stats *stats,
						     __u64 start_ns)
{
	__u64 now;

	if (!stats)
		return;

	now = bpf_ktime_get_ns();
	if (now > start_ns)
		record_ns_metric(now - start_ns,
				 &stats->xdp_hook_samples,
				 &stats->xdp_hook_total_ns,
				 &stats->xdp_hook_avg_ns,
				 &stats->xdp_hook_min_ns,
				 &stats->xdp_hook_max_ns);
}

static __always_inline void record_rx_hook_overhead(struct path_latency_stats *stats,
						    __u64 start_ns)
{
	__u64 now;

	if (!stats)
		return;

	now = bpf_ktime_get_ns();
	if (now > start_ns)
		record_ns_metric(now - start_ns,
				 &stats->rx_hook_samples,
				 &stats->rx_hook_total_ns,
				 &stats->rx_hook_avg_ns,
				 &stats->rx_hook_min_ns,
				 &stats->rx_hook_max_ns);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx){
	__u32 key = 0;
	__u64 start_ns;
	struct path_latency_stats *stats;
	struct flow_key flow = {};

	start_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&xdp_timestamp_ns_map, &key, &start_ns, BPF_ANY);

	stats = bpf_map_lookup_elem(&path_latency_stats_map, &key);
	if (parse_xdp_flow(ctx, &flow) < 0)
		return XDP_PASS;

	if (stats)
		stats_inc(&stats->xdp_seen);
	bpf_map_update_elem(&xdp_ingress_ts_map, &flow, &start_ns, BPF_ANY);
	record_xdp_hook_overhead(stats, start_ns);
	return XDP_PASS;
}


SEC("kprobe/__udp_enqueue_schedule_skb")
int BPF_KPROBE(trace_udp_enqueue, struct sock *sk, struct sk_buff *skb)
{
	__u32 key = 0;
	__u64 start_ns = bpf_ktime_get_ns();
	__u64 *ingress_ns;
	struct path_latency_stats *stats;
	struct flow_key flow = {};

	stats = bpf_map_lookup_elem(&path_latency_stats_map, &key);
	if (parse_skb_flow(skb, &flow) < 0)
		return 0;

	if (stats)
		stats_inc(&stats->udp_seen);
	ingress_ns = bpf_map_lookup_elem(&xdp_ingress_ts_map, &flow);
	if (!ingress_ns) {
		if (stats)
			stats_inc(&stats->lookup_miss);
		record_rx_hook_overhead(stats, start_ns);
		return 0;
	}

	if (start_ns > *ingress_ns)
		record_path_latency(start_ns - *ingress_ns);
	bpf_map_delete_elem(&xdp_ingress_ts_map, &flow);

	record_rx_hook_overhead(stats, start_ns);
	return 0;
}


char _license[] SEC("license") = "GPL";
