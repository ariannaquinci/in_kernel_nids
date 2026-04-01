// SPDX-License-Identifier: GPL-2.0
#ifndef __DW_POLICY_H__
#define __DW_POLICY_H__

enum {
	DW_MON_UDP  = 1u << 0,
	DW_MON_TCP  = 1u << 1,
	DW_MON_BOTH = DW_MON_UDP | DW_MON_TCP,
};

#define DW_POLICY_MAP_KEY 0

struct dw_monitor_policy {
	__u32 monitor_mask;
	__u32 reserved;
};

static __always_inline __u32 dw_policy_sanitize_mask(__u32 mask)
{
	mask &= DW_MON_BOTH;
	if (!mask)
		return DW_MON_UDP;

	return mask;
}

#endif
