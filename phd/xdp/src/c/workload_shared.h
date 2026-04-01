// SPDX-License-Identifier: GPL-2.0
#ifndef __WORKLOAD_SHARED_H__
#define __WORKLOAD_SHARED_H__

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#include "modules/dw_shared.h"

enum dw_workload_level {
	DW_WORKLOAD_LOW = 0,
	DW_WORKLOAD_MEDIUM = 1,
	DW_WORKLOAD_HIGH = 2,
	DW_WORKLOAD_CRITICAL = 3,
};

struct workload_state {
	__u32 workload_level;
	__u32 deferred_budget;
	__u64 last_update_ns;
	__u32 cpu_busy_pct;
	__u32 net_rx_softirq_pct;
	__u32 avg_runqueue_latency_us;
};

#define DW_WORKLOAD_MAP_KEY                 0u
#define DW_WORKLOAD_DEFAULT_BUDGET          3u
#define DW_WORKLOAD_UPDATE_INTERVAL_NS      250000000ULL
#define DW_WORKLOAD_MAX_CPUS                256u
#define DW_CPU_BUSY_MEDIUM_PCT              60u
#define DW_CPU_BUSY_HIGH_PCT                85u
#define DW_CPU_BUSY_CRITICAL_PCT            95u
#define DW_NET_RX_MEDIUM_PCT                10u
#define DW_NET_RX_HIGH_PCT                  20u
#define DW_NET_RX_CRITICAL_PCT              35u
#define DW_RUNQUEUE_LAT_MEDIUM_US           1000u
#define DW_RUNQUEUE_LAT_HIGH_US             5000u
#define DW_RUNQUEUE_LAT_CRITICAL_US         10000u

static __always_inline __u32 dw_max_u32(__u32 a, __u32 b)
{
	return a > b ? a : b;
}

static __always_inline __u32 dw_budget_for_level(__u32 level)
{
	switch (level) {
	case DW_WORKLOAD_LOW:
		return 3;
	case DW_WORKLOAD_MEDIUM:
		return 2;
	case DW_WORKLOAD_HIGH:
		return 1;
	case DW_WORKLOAD_CRITICAL:
		return 1;
	default:
		return DW_WORKLOAD_DEFAULT_BUDGET;
	}
}

static __always_inline __u32 dw_workload_level_from_cpu_busy(__u32 busy_cpus,
							     __u32 total_cpus)
{
	__u32 busy_pct;

	if (!total_cpus)
		return DW_WORKLOAD_LOW;

	busy_pct = (busy_cpus * 100u) / total_cpus;
	if (busy_pct < DW_CPU_BUSY_MEDIUM_PCT)
		return DW_WORKLOAD_LOW;
	if (busy_pct < DW_CPU_BUSY_HIGH_PCT)
		return DW_WORKLOAD_MEDIUM;
	if (busy_pct < DW_CPU_BUSY_CRITICAL_PCT)
		return DW_WORKLOAD_HIGH;
	return DW_WORKLOAD_CRITICAL;
}

static __always_inline __u32 dw_workload_level_from_pct(__u32 pct,
							__u32 medium_pct,
							__u32 high_pct,
							__u32 critical_pct)
{
	if (pct < medium_pct)
		return DW_WORKLOAD_LOW;
	if (pct < high_pct)
		return DW_WORKLOAD_MEDIUM;
	if (pct < critical_pct)
		return DW_WORKLOAD_HIGH;
	return DW_WORKLOAD_CRITICAL;
}

static __always_inline __u32 dw_workload_level_from_latency_us(__u32 latency_us)
{
	if (!latency_us)
		return DW_WORKLOAD_LOW;
	if (latency_us < DW_RUNQUEUE_LAT_MEDIUM_US)
		return DW_WORKLOAD_LOW;
	if (latency_us < DW_RUNQUEUE_LAT_HIGH_US)
		return DW_WORKLOAD_MEDIUM;
	if (latency_us < DW_RUNQUEUE_LAT_CRITICAL_US)
		return DW_WORKLOAD_HIGH;
	return DW_WORKLOAD_CRITICAL;
}

static __always_inline __u32 dw_workload_level_from_signals(__u32 cpu_busy_pct,
							    __u32 net_rx_pct,
							    __u32 runqueue_latency_us)
{
	__u32 level = dw_workload_level_from_pct(cpu_busy_pct,
						 DW_CPU_BUSY_MEDIUM_PCT,
						 DW_CPU_BUSY_HIGH_PCT,
						 DW_CPU_BUSY_CRITICAL_PCT);

	level = dw_max_u32(level,
			   dw_workload_level_from_pct(net_rx_pct,
						      DW_NET_RX_MEDIUM_PCT,
						      DW_NET_RX_HIGH_PCT,
						      DW_NET_RX_CRITICAL_PCT));
	level = dw_max_u32(level,
			   dw_workload_level_from_latency_us(runqueue_latency_us));
	return level;
}

static __always_inline __u32 dw_sanitize_budget(__u32 budget)
{
	if (budget < 1 || budget > 3)
		return DW_WORKLOAD_DEFAULT_BUDGET;
	return budget;
}

static __always_inline __u32 dw_apply_deferred_budget(__u32 req_mask, __u32 budget)
{
	__u32 capped = 0;
	__u32 remaining = dw_sanitize_budget(budget);

	if ((req_mask & DW_REQ_A1) && remaining) {
		capped |= DW_REQ_A1;
		remaining--;
	}
	if ((req_mask & DW_REQ_A2) && remaining) {
		capped |= DW_REQ_A2;
		remaining--;
	}
	if ((req_mask & DW_REQ_A3) && remaining)
		capped |= DW_REQ_A3;

	return capped;
}

#endif
