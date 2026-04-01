// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "workload_shared.h"

struct cpu_run_state {
	__u32 is_busy;
	__u32 in_net_rx_softirq;
	__u32 pad;
	__u64 last_sched_ts_ns;
	__u64 busy_time_ns;
	__u64 idle_time_ns;
	__u64 softirq_enter_ns;
	__u64 net_rx_softirq_time_ns;
	__u64 runnable_count;
	__u64 runqueue_latency_ns;
	__u64 runqueue_latency_samples;
};

struct collector_state {
	__u64 last_update_ns;
	__u64 total_busy_time_ns;
	__u64 total_idle_time_ns;
	__u64 total_net_rx_softirq_time_ns;
	__u64 total_runqueue_latency_ns;
	__u64 total_runqueue_latency_samples;
	__u64 prev_busy_time_ns;
	__u64 prev_idle_time_ns;
	__u64 prev_net_rx_softirq_time_ns;
	__u64 prev_runqueue_latency_ns;
	__u64 prev_runqueue_latency_samples;
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

struct runnable_ts {
	__u64 ts_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct runnable_ts);
} runnable_ts_map SEC(".maps");

#define DW_SOFTIRQ_NET_RX 3u

static __always_inline void dw_account_cpu_time(struct cpu_run_state *cpu_state,
						struct collector_state *collector,
						__u64 now)
{
	__u64 delta;

	if (!cpu_state->last_sched_ts_ns) {
		cpu_state->last_sched_ts_ns = now;
		return;
	}

	delta = now - cpu_state->last_sched_ts_ns;
	if (cpu_state->is_busy) {
		cpu_state->busy_time_ns += delta;
		__sync_fetch_and_add(&collector->total_busy_time_ns, delta);
	} else {
		cpu_state->idle_time_ns += delta;
		__sync_fetch_and_add(&collector->total_idle_time_ns, delta);
	}

	cpu_state->last_sched_ts_ns = now;
}

static __always_inline void dw_publish_workload(__u64 now)
{
	__u32 collector_key = 0;
	__u32 workload_key = DW_WORKLOAD_MAP_KEY;
	struct collector_state *collector;
	struct workload_state next = {};
	__u64 window_busy_ns;
	__u64 window_idle_ns;
	__u64 window_total_cpu_ns;
	__u64 window_net_rx_ns;
	__u64 window_runqueue_latency_ns;
	__u64 window_runqueue_latency_samples;

	collector = bpf_map_lookup_elem(&collector_state_map, &collector_key);
	if (!collector)
		return;

	if (now - collector->last_update_ns < DW_WORKLOAD_UPDATE_INTERVAL_NS)
		return;

	window_busy_ns = collector->total_busy_time_ns - collector->prev_busy_time_ns;
	window_idle_ns = collector->total_idle_time_ns - collector->prev_idle_time_ns;
	window_total_cpu_ns = window_busy_ns + window_idle_ns;
	window_net_rx_ns = collector->total_net_rx_softirq_time_ns -
		collector->prev_net_rx_softirq_time_ns;
	window_runqueue_latency_ns = collector->total_runqueue_latency_ns -
		collector->prev_runqueue_latency_ns;
	window_runqueue_latency_samples = collector->total_runqueue_latency_samples -
		collector->prev_runqueue_latency_samples;

	if (window_total_cpu_ns) {
		next.cpu_busy_pct = (__u32)((window_busy_ns * 100ULL) / window_total_cpu_ns);
		next.net_rx_softirq_pct = (__u32)((window_net_rx_ns * 100ULL) / window_total_cpu_ns);
	}

	if (window_runqueue_latency_samples) {
		next.avg_runqueue_latency_us =
			(__u32)((window_runqueue_latency_ns / window_runqueue_latency_samples) / 1000ULL);
	}

	next.workload_level = dw_workload_level_from_signals(next.cpu_busy_pct,
							     next.net_rx_softirq_pct,
							     next.avg_runqueue_latency_us);
	next.deferred_budget = dw_budget_for_level(next.workload_level);
	next.last_update_ns = now;

	collector->prev_busy_time_ns = collector->total_busy_time_ns;
	collector->prev_idle_time_ns = collector->total_idle_time_ns;
	collector->prev_net_rx_softirq_time_ns = collector->total_net_rx_softirq_time_ns;
	collector->prev_runqueue_latency_ns = collector->total_runqueue_latency_ns;
	collector->prev_runqueue_latency_samples = collector->total_runqueue_latency_samples;
	collector->last_update_ns = now;

	bpf_map_update_elem(&workload_state_map, &workload_key, &next, BPF_ANY);
}

static __always_inline int dw_mark_runnable(__u32 pid)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 collector_key = 0;
	struct cpu_run_state *cpu_state;
	struct collector_state *collector;
	struct runnable_ts runnable_ts = {};
	__u64 now;

	if (cpu >= DW_WORKLOAD_MAX_CPUS)
		return 0;

	collector = bpf_map_lookup_elem(&collector_state_map, &collector_key);
	if (!collector)
		return 0;

	cpu_state = bpf_map_lookup_elem(&cpu_run_state_map, &cpu);
	if (!cpu_state)
		return 0;

	now = bpf_ktime_get_ns();
	runnable_ts.ts_ns = now;
	bpf_map_update_elem(&runnable_ts_map, &pid, &runnable_ts, BPF_ANY);
	dw_publish_workload(now);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int workload_collector(struct trace_event_raw_sched_switch *ctx)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 collector_key = 0;
	struct cpu_run_state *cpu_state;
	struct collector_state *collector;
	__u64 now;
	struct runnable_ts *runnable_ts;
	__u32 prev_pid;
	__u32 next_pid;

	if (cpu >= DW_WORKLOAD_MAX_CPUS)
		return 0;

	collector = bpf_map_lookup_elem(&collector_state_map, &collector_key);
	if (!collector)
		return 0;

	cpu_state = bpf_map_lookup_elem(&cpu_run_state_map, &cpu);
	if (!cpu_state)
		return 0;

	now = bpf_ktime_get_ns();
	dw_account_cpu_time(cpu_state, collector, now);
	cpu_state->is_busy = ctx->next_pid != 0;

	prev_pid = (__u32)ctx->prev_pid;
	next_pid = (__u32)ctx->next_pid;
	/* Skip map churn if the same task stays on CPU across the switch event. */
	if (prev_pid != next_pid && prev_pid && ctx->prev_state == 0) {
		struct runnable_ts prev_runnable_ts = {
			.ts_ns = now,
		};

		bpf_map_update_elem(&runnable_ts_map, &prev_pid, &prev_runnable_ts, BPF_ANY);
	}

	if (prev_pid != next_pid && next_pid) {
		runnable_ts = bpf_map_lookup_elem(&runnable_ts_map, &next_pid);
		if (runnable_ts) {
			if (now > runnable_ts->ts_ns) {
				__u64 latency = now - runnable_ts->ts_ns;

				cpu_state->runqueue_latency_ns += latency;
				cpu_state->runqueue_latency_samples++;
				cpu_state->runnable_count++;
				__sync_fetch_and_add(&collector->total_runqueue_latency_ns, latency);
				__sync_fetch_and_add(&collector->total_runqueue_latency_samples, 1);
			}
			bpf_map_delete_elem(&runnable_ts_map, &next_pid);
		}
	}

	dw_publish_workload(now);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int workload_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	return dw_mark_runnable((__u32)ctx->pid);
}

SEC("tracepoint/sched/sched_wakeup_new")
int workload_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	return dw_mark_runnable((__u32)ctx->pid);
}

SEC("tracepoint/irq/softirq_entry")
int workload_softirq_entry(struct trace_event_raw_softirq *ctx)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 collector_key = 0;
	struct cpu_run_state *cpu_state;
	struct collector_state *collector;
	__u64 now;

	if (cpu >= DW_WORKLOAD_MAX_CPUS || ctx->vec != DW_SOFTIRQ_NET_RX)
		return 0;

	collector = bpf_map_lookup_elem(&collector_state_map, &collector_key);
	if (!collector)
		return 0;

	cpu_state = bpf_map_lookup_elem(&cpu_run_state_map, &cpu);
	if (!cpu_state)
		return 0;

	if (cpu_state->in_net_rx_softirq)
		return 0;

	now = bpf_ktime_get_ns();
	cpu_state->in_net_rx_softirq = 1;
	cpu_state->softirq_enter_ns = now;
	dw_publish_workload(now);
	return 0;
}

SEC("tracepoint/irq/softirq_exit")
int workload_softirq_exit(struct trace_event_raw_softirq *ctx)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 collector_key = 0;
	struct cpu_run_state *cpu_state;
	struct collector_state *collector;
	__u64 now;

	if (cpu >= DW_WORKLOAD_MAX_CPUS || ctx->vec != DW_SOFTIRQ_NET_RX)
		return 0;

	collector = bpf_map_lookup_elem(&collector_state_map, &collector_key);
	if (!collector)
		return 0;

	cpu_state = bpf_map_lookup_elem(&cpu_run_state_map, &cpu);
	if (!cpu_state)
		return 0;

	if (!cpu_state->in_net_rx_softirq)
		return 0;

	now = bpf_ktime_get_ns();
	if (now > cpu_state->softirq_enter_ns)
	{
		__u64 delta = now - cpu_state->softirq_enter_ns;

		cpu_state->net_rx_softirq_time_ns += delta;
		__sync_fetch_and_add(&collector->total_net_rx_softirq_time_ns, delta);
	}
	cpu_state->in_net_rx_softirq = 0;
	cpu_state->softirq_enter_ns = 0;
	dw_publish_workload(now);
	return 0;
}

char _license[] SEC("license") = "GPL";
