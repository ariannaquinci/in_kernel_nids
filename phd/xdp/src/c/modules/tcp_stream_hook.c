// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>

#include <net/sock.h>
#include <net/tcp.h>

#include "dw_print.h"
#include "deferred_work_tcp.h"
#include "dw_policy.h"
#include "dw_shared_tcp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("TCP stream hook on post-reordering receive path");

struct dw_tcp_probe_ctx {
	struct sock *sk;
};

struct dw_tcp_recv_probe_ctx {
	struct sock *sk;
};

static int dw_tcp_recvmsg_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sock *sk = (struct sock *)regs->di;
	size_t req_len = (size_t)regs->dx;
	size_t allowed;

	if (!sk)
		return 0;

	if (dw_tcp_is_drop_armed(sk)) {
		/* Probe handlers run in atomic context: only gate the read path here. */
		regs->dx = 0;
		return 0;
	}

	allowed = dw_tcp_approved_len(sk, req_len);
	/*
	 * Forcing len=0 on a live socket makes many callers observe a spurious
	 * EOF while deferred analysis is still in flight. Only clamp positive
	 * approved windows; keep the original request size while nothing has
	 * been approved yet.
	 */
	if (allowed > 0 && allowed < req_len)
		regs->dx = allowed;

	return 0;
}

static struct kprobe dw_tcp_recvmsg_probe = {
	.symbol_name = "tcp_recvmsg",
	.pre_handler = dw_tcp_recvmsg_pre,
};

static int dw_tcp_recvmsg_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dw_tcp_recv_probe_ctx *ctx = (struct dw_tcp_recv_probe_ctx *)ri->data;

	ctx->sk = (struct sock *)regs->di;
	return 0;
}

static int dw_tcp_recvmsg_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dw_tcp_recv_probe_ctx *ctx = (struct dw_tcp_recv_probe_ctx *)ri->data;

	if (!ctx->sk || !dw_tcp_is_drop_armed(ctx->sk))
		return 0;

	regs_set_return_value(regs, (unsigned long)-ECONNRESET);
	return 0;
}

static struct kretprobe dw_tcp_recvmsg_ret_probe = {
	.kp.symbol_name = "tcp_recvmsg",
	.entry_handler = dw_tcp_recvmsg_entry,
	.handler = dw_tcp_recvmsg_ret,
	.data_size = sizeof(struct dw_tcp_recv_probe_ctx),
	.maxactive = 64,
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

	ret = register_kprobe(&dw_tcp_recvmsg_probe);
	if (ret) {
		unregister_kretprobe(&dw_tcp_data_queue_probe);
		pr_err("register_kprobe(tcp_recvmsg) failed: %d\n", ret);
		return ret;
	}

	ret = register_kretprobe(&dw_tcp_recvmsg_ret_probe);
	if (ret) {
		unregister_kprobe(&dw_tcp_recvmsg_probe);
		unregister_kretprobe(&dw_tcp_data_queue_probe);
		pr_err("register_kretprobe(tcp_recvmsg) failed: %d\n", ret);
		return ret;
	}

	pr_info("loaded kretprobe tcp_data_queue + kprobe/kretprobe tcp_recvmsg\n");
	return 0;
}

static void __exit tcp_stream_hook_exit(void)
{
	unregister_kretprobe(&dw_tcp_recvmsg_ret_probe);
	unregister_kprobe(&dw_tcp_recvmsg_probe);
	unregister_kretprobe(&dw_tcp_data_queue_probe);
	pr_info("unloaded\n");
}

module_init(tcp_stream_hook_init);
module_exit(tcp_stream_hook_exit);
