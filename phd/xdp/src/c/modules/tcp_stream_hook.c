// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>

#include <net/sock.h>

#include "deferred_work_tcp.h"
#include "dw_policy.h"
#include "dw_shared_tcp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("TCP stream hook on post-reordering receive path");

struct dw_tcp_probe_ctx {
	struct sock *sk;
};

static int dw_tcp_data_queue_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dw_tcp_probe_ctx *ctx = (struct dw_tcp_probe_ctx *)ri->data;

	ctx->sk = (struct sock *)regs->di;
	return 0;
}

static int dw_tcp_data_queue_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dw_tcp_probe_ctx *ctx = (struct dw_tcp_probe_ctx *)ri->data;
	int rc;

	if (!ctx->sk)
		return 0;

	rc = dw_tcp_enqueue_stream(ctx->sk);
	if (rc > 0)
		pr_debug("post-reordering tcp chunk queued bytes=%d sk=%p\n", rc, ctx->sk);

	return 0;
}

static struct kretprobe dw_tcp_data_queue_probe = {
	.kp.symbol_name = "tcp_data_queue",
	.entry_handler = dw_tcp_data_queue_entry,
	.handler = dw_tcp_data_queue_ret,
	.data_size = sizeof(struct dw_tcp_probe_ctx),
	.maxactive = 64,
};

static int __init tcp_stream_hook_init(void)
{
	int ret;

	ret = register_kretprobe(&dw_tcp_data_queue_probe);
	if (ret) {
		pr_err("register_kretprobe(tcp_data_queue) failed: %d\n", ret);
		return ret;
	}

	pr_info("loaded kretprobe on tcp_data_queue, post-reordering TCP path active\n");
	return 0;
}

static void __exit tcp_stream_hook_exit(void)
{
	unregister_kretprobe(&dw_tcp_data_queue_probe);
	pr_info("unloaded\n");
}

module_init(tcp_stream_hook_init);
module_exit(tcp_stream_hook_exit);
