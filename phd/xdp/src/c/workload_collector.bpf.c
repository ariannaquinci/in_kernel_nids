// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "workload_shared.h"

struct cpu_run_state {
	__u32 seen;
	__u32 is_busy;
};

struct collector_state {
	__u32 busy_cpu_count;
	__u32 observed_cpu_count;
	__u64 last_update_ns;
};

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
	__type(value, struct collector_state);
} collector_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DW_WORKLOAD_MAX_CPUS);
	__type(key, __u32);
	__type(value, struct cpu_run_state);
} cpu_run_state_map SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int workload_collector(struct trace_event_raw_sched_switch *ctx)
{
	__u32 collector_key = 0;
	__u32 workload_key = DW_WORKLOAD_MAP_KEY;
	__u32 cpu = bpf_get_smp_processor_id();
	struct collector_state *collector;
	struct cpu_run_state *cpu_state;
	struct workload_state next = {};
	bool next_busy;
	__u64 now;

	if (cpu >= DW_WORKLOAD_MAX_CPUS)
		return 0;

	collector = bpf_map_lookup_elem(&collector_state_map, &collector_key);
	if (!collector)
		return 0;

	cpu_state = bpf_map_lookup_elem(&cpu_run_state_map, &cpu);
	if (!cpu_state)
		return 0;

	next_busy = ctx->next_pid != 0;

	if (!cpu_state->seen) {
		cpu_state->seen = 1;
		collector->observed_cpu_count++;
		if (next_busy)
			collector->busy_cpu_count++;
		cpu_state->is_busy = next_busy;
	} else if (cpu_state->is_busy != next_busy) {
		if (next_busy)
			collector->busy_cpu_count++;
		else if (collector->busy_cpu_count > 0)
			collector->busy_cpu_count--;
		cpu_state->is_busy = next_busy;
	}

	now = bpf_ktime_get_ns();
	/* Keep updates out of the XDP fast path and refresh only at a coarse rate. */
	if (now - collector->last_update_ns < DW_WORKLOAD_UPDATE_INTERVAL_NS)
		return 0;

	next.workload_level = dw_workload_level_from_cpu_busy(collector->busy_cpu_count,
							      collector->observed_cpu_count);
	next.deferred_budget = dw_budget_for_level(next.workload_level);
	next.last_update_ns = now;
	collector->last_update_ns = now;

	bpf_map_update_elem(&workload_state_map, &workload_key, &next, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
