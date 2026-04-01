// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <net/tcp.h>

#include "deferred_work_tcp.h"
#include "dw_policy.h"
#include "dw_shared_tcp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("TCP deferred analysis backend for post-reordering stream chunks");

#define DW_TCP_ANALYSIS_BITS 10
#define DW_TCP_CHUNK_MAX 4096u
#define DW_TCP_NEEDLE "malicious"
#define DW_TCP_NEEDLE_LEN (sizeof(DW_TCP_NEEDLE) - 1)
#define DW_TCP_TAIL_LEN (DW_TCP_NEEDLE_LEN - 1)

struct dw_tcp_flow_state {
	u64 sock_cookie;
	u32 next_seq;
	bool next_seq_valid;
	u8 tail_len;
	u8 tail[DW_TCP_TAIL_LEN];
	unsigned long last_seen_jiffies;
	struct hlist_node hnode;
};

struct dw_tcp_analysis_work {
	struct work_struct work;
	u64 sock_cookie;
	u32 from_seq;
	u32 to_seq;
	u32 scan_from_seq;
	u32 scan_to_seq;
	u8 prefix_len;
	u32 len;
	u8 data[];
};

static DEFINE_HASHTABLE(dw_tcp_flow_ht, DW_TCP_ANALYSIS_BITS);
static DEFINE_SPINLOCK(dw_tcp_flow_lock);
static struct workqueue_struct *dw_tcp_wq;

static bool dw_tcp_buf_contains_needle(const u8 *buf, size_t len)
{
	size_t i;
	size_t nlen = DW_TCP_NEEDLE_LEN;

	if (!buf || len < nlen)
		return false;

	for (i = 0; i + nlen <= len; i++) {
		if (!memcmp(buf + i, DW_TCP_NEEDLE, nlen))
			return true;
	}

	return false;
}

static struct dw_tcp_flow_state *dw_tcp_flow_lookup_locked(u64 sock_cookie, u32 hash)
{
	struct dw_tcp_flow_state *state;

	hash_for_each_possible(dw_tcp_flow_ht, state, hnode, hash) {
		if (state->sock_cookie == sock_cookie)
			return state;
	}

	return NULL;
}

static struct dw_tcp_flow_state *dw_tcp_flow_get_locked(u64 sock_cookie, u32 hash)
{
	struct dw_tcp_flow_state *state;

	state = dw_tcp_flow_lookup_locked(sock_cookie, hash);
	if (state) {
		state->last_seen_jiffies = jiffies;
		return state;
	}

	state = kzalloc(sizeof(*state), GFP_ATOMIC);
	if (!state)
		return NULL;

	state->sock_cookie = sock_cookie;
	state->last_seen_jiffies = jiffies;
	hash_add(dw_tcp_flow_ht, &state->hnode, hash);
	return state;
}

static int dw_tcp_copy_stream_chunk(struct sock *sk, u32 from_seq, u32 to_seq, u8 *dst)
{
	struct sk_buff *skb;
	u32 out_off = 0;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		u32 skb_seq = TCP_SKB_CB(skb)->seq;
		u32 skb_end_seq = TCP_SKB_CB(skb)->end_seq;
		u32 copy_from;
		u32 copy_to;
		u32 copy_len;
		int rc;

		if (!before(skb_seq, to_seq))
			break;

		if (!before(from_seq, skb_end_seq))
			continue;

		copy_from = before(from_seq, skb_seq) ? skb_seq : from_seq;
		copy_to = before(skb_end_seq, to_seq) ? skb_end_seq : to_seq;
		if (!before(copy_from, copy_to))
			continue;

		copy_len = copy_to - copy_from;
		rc = skb_copy_bits(skb, copy_from - skb_seq, dst + out_off, copy_len);
		if (rc < 0)
			return rc;

		out_off += copy_len;
		if (out_off >= to_seq - from_seq)
			break;
	}

	return (int)out_off;
}

static unsigned int dw_tcp_hash_to_cpu(u64 sock_cookie)
{
	unsigned int online = 0;
	unsigned int target;
	int cpu;

	for_each_online_cpu(cpu)
		online++;

	if (!online)
		return raw_smp_processor_id();

	target = reciprocal_scale(sock_cookie, online);
	for_each_online_cpu(cpu) {
		if (!target)
			return cpu;
		target--;
	}

	return raw_smp_processor_id();
}

static void dw_tcp_analysis_workfn(struct work_struct *work)
{
	struct dw_tcp_analysis_work *aw = container_of(work, struct dw_tcp_analysis_work, work);
	bool hit;

	hit = dw_tcp_buf_contains_needle(aw->data, aw->len);
	if (hit) {
		pr_info("tcp deferred chunk cookie=%#llx chunk=%u..%u scan=%u..%u len=%u verdict=DROP_CANDIDATE\n",
			aw->sock_cookie, aw->from_seq, aw->to_seq,
			aw->scan_from_seq, aw->scan_to_seq, aw->len);
	}

	kfree(aw);
}

int dw_tcp_enqueue_stream(struct sock *sk)
{
	struct tcp_sock *tp;
	struct dw_tcp_flow_state *state;
	struct dw_tcp_analysis_work *aw;
	u64 sock_cookie;
	u32 hash;
	u32 from_seq;
	u32 to_seq;
	u32 available_end;
	u32 chunk_len;
	u32 alloc_len;
	unsigned int cpu;
	u8 prefix_len;
	u8 prefix[DW_TCP_TAIL_LEN];
	u8 next_tail_len;
	int copied;

	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return -EINVAL;

	tp = tcp_sk(sk);
	sock_cookie = (u64)(uintptr_t)sk;
	hash = jhash_1word((u32)sock_cookie, (u32)(sock_cookie >> 32));

	spin_lock_bh(&dw_tcp_flow_lock);
	state = dw_tcp_flow_get_locked(sock_cookie, hash);
	if (!state) {
		spin_unlock_bh(&dw_tcp_flow_lock);
		return -ENOMEM;
	}

	if (!state->next_seq_valid) {
		state->next_seq = READ_ONCE(tp->copied_seq);
		state->next_seq_valid = true;
	}

	prefix_len = state->tail_len;
	if (prefix_len)
		memcpy(prefix, state->tail, prefix_len);

	available_end = READ_ONCE(tp->rcv_nxt);
	from_seq = state->next_seq;
	if (!before(from_seq, available_end)) {
		spin_unlock_bh(&dw_tcp_flow_lock);
		return 0;
	}

	chunk_len = min_t(u32, available_end - from_seq, DW_TCP_CHUNK_MAX);
	to_seq = from_seq + chunk_len;
	state->next_seq = to_seq;
	state->last_seen_jiffies = jiffies;
	spin_unlock_bh(&dw_tcp_flow_lock);

	alloc_len = prefix_len + chunk_len;
	aw = kzalloc(struct_size(aw, data, alloc_len), GFP_ATOMIC);
	if (!aw)
		return -ENOMEM;

	aw->sock_cookie = sock_cookie;
	aw->from_seq = from_seq;
	aw->to_seq = to_seq;
	aw->prefix_len = prefix_len;
	aw->scan_from_seq = from_seq - prefix_len;
	aw->scan_to_seq = to_seq;

	if (prefix_len)
		memcpy(aw->data, prefix, prefix_len);

	copied = dw_tcp_copy_stream_chunk(sk, from_seq, to_seq, aw->data + prefix_len);
	if (copied <= 0) {
		kfree(aw);
		return copied ? copied : -ENODATA;
	}

	aw->len = prefix_len + copied;

	next_tail_len = min_t(u8, aw->len, DW_TCP_TAIL_LEN);
	spin_lock_bh(&dw_tcp_flow_lock);
	state = dw_tcp_flow_lookup_locked(sock_cookie, hash);
	if (state) {
		state->tail_len = next_tail_len;
		if (next_tail_len)
			memcpy(state->tail, aw->data + aw->len - next_tail_len, next_tail_len);
		state->last_seen_jiffies = jiffies;
	}
	spin_unlock_bh(&dw_tcp_flow_lock);

	INIT_WORK(&aw->work, dw_tcp_analysis_workfn);

	cpu = dw_tcp_hash_to_cpu(sock_cookie);
	queue_work_on(cpu, dw_tcp_wq, &aw->work);

	pr_debug("tcp enqueue cookie=%#llx copied_seq=%u rcv_nxt=%u chunk=%u..%u len=%u cpu=%u\n",
		 sock_cookie, READ_ONCE(tp->copied_seq), available_end,
		 aw->from_seq, aw->to_seq, aw->len, cpu);
	return copied;
}
EXPORT_SYMBOL_GPL(dw_tcp_enqueue_stream);

static int __init deferred_analysis_tcp_init(void)
{
	hash_init(dw_tcp_flow_ht);
	dw_tcp_wq = alloc_workqueue("dw_tcp_wq", WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!dw_tcp_wq)
		return -ENOMEM;

	pr_info("loaded monitor flags: udp=0x%x tcp=0x%x both=0x%x chunk_max=%u needle=\"%s\"\n",
		DW_MON_UDP, DW_MON_TCP, DW_MON_BOTH, DW_TCP_CHUNK_MAX, DW_TCP_NEEDLE);
	return 0;
}

static void __exit deferred_analysis_tcp_exit(void)
{
	struct dw_tcp_flow_state *state;
	struct hlist_node *tmp;
	int bkt;

	if (dw_tcp_wq) {
		destroy_workqueue(dw_tcp_wq);
		dw_tcp_wq = NULL;
	}

	spin_lock_bh(&dw_tcp_flow_lock);
	hash_for_each_safe(dw_tcp_flow_ht, bkt, tmp, state, hnode) {
		hash_del(&state->hnode);
		kfree(state);
	}
	spin_unlock_bh(&dw_tcp_flow_lock);

	pr_info("unloaded\n");
}

module_init(deferred_analysis_tcp_init);
module_exit(deferred_analysis_tcp_exit);
