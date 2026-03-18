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
};

#define DW_WORKLOAD_MAP_KEY                 0u
#define DW_WORKLOAD_DEFAULT_BUDGET          3u
#define DW_WORKLOAD_UPDATE_INTERVAL_NS      250000000ULL
#define DW_WORKLOAD_MAX_CPUS                256u
#define DW_CPU_BUSY_MEDIUM_PCT              60u
#define DW_CPU_BUSY_HIGH_PCT                85u
#define DW_CPU_BUSY_CRITICAL_PCT            95u

static __always_inline __u32 dw_budget_for_level(__u32 level)
{
	switch (level) {
	case DW_WORKLOAD_LOW:
	case DW_WORKLOAD_MEDIUM:
		return 3;
	case DW_WORKLOAD_HIGH:
		return 2;
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
