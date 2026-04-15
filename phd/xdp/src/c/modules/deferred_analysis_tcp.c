// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/atomic.h>
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
#define DW_TCP_REQ_A1 BIT(0)
#define DW_TCP_REQ_A2 BIT(1)
#define DW_TCP_REQ_MASK_2 (DW_TCP_REQ_A1 | DW_TCP_REQ_A2)

struct dw_tcp_flow_state {
	u64 sock_cookie;
	struct sock *sk;
	u32 next_seq;
	u32 approved_seq;
	bool next_seq_valid;
	bool approved_seq_valid;
	bool drop_armed;
	u8 tail_len;
	u8 tail[DW_TCP_TAIL_LEN];
	unsigned long last_seen_jiffies;
	struct hlist_node hnode;
};

struct dw_tcp_chunk_state {
	struct dw_tcp_flow_state *state;
	u64 sock_cookie;
	u32 from_seq;
	u32 to_seq;
	u32 scan_from_seq;
	u32 scan_to_seq;
	u32 req_mask;
	atomic_t done_mask;
	atomic_t hit_mask;
	atomic_t pending;
	u32 len;
	u8 data[];
};

struct dw_tcp_analysis_work {
	struct work_struct work;
	struct dw_tcp_chunk_state *chunk;
	u32 bit;
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
	//fsleep(3); //simulate expensive analysis
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

static struct dw_tcp_flow_state *dw_tcp_flow_get_locked(struct sock *sk, u64 sock_cookie, u32 hash)
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
	state->sk = sk;
	state->last_seen_jiffies = jiffies;
	sock_hold(sk);
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

static u32 dw_tcp_chunk_req_mask(u32 scan_len)
{
	u32 req_mask = DW_TCP_REQ_A1;

	if (scan_len >= DW_TCP_NEEDLE_LEN)
		req_mask |= DW_TCP_REQ_A2;

	return req_mask;
}

static void dw_tcp_finalize_chunk(struct dw_tcp_chunk_state *chunk)
{
	struct dw_tcp_flow_state *state = chunk->state;
	struct sock *drop_sk = NULL;
	u32 hits;

	hits = (u32)atomic_read(&chunk->hit_mask);
	if (hits) {
		if (state) {
			WRITE_ONCE(state->drop_armed, true);
			drop_sk = READ_ONCE(state->sk);
		}

		if (drop_sk) {
			lock_sock(drop_sk);
			__skb_queue_purge(&drop_sk->sk_receive_queue);
			release_sock(drop_sk);
			tcp_abort(drop_sk, ECONNRESET);
		}

		pr_info("tcp deferred chunk cookie=%#llx chunk=%u..%u scan=%u..%u len=%u done=0x%x hits=0x%x verdict=DROP_CANDIDATE\n",
			chunk->sock_cookie, chunk->from_seq, chunk->to_seq,
			chunk->scan_from_seq, chunk->scan_to_seq, chunk->len,
			(u32)atomic_read(&chunk->done_mask), hits);
	} else {
		if (state && READ_ONCE(state->approved_seq_valid))
			cmpxchg(&state->approved_seq, chunk->from_seq, chunk->to_seq);
	}
}

static void dw_tcp_analysis_workfn(struct work_struct *work)
{
	struct dw_tcp_analysis_work *aw = container_of(work, struct dw_tcp_analysis_work, work);
	struct dw_tcp_chunk_state *chunk = aw->chunk;
	bool hit;

	switch (aw->bit) {
	case DW_TCP_REQ_A1:
		hit = false;
		break;
	case DW_TCP_REQ_A2:
		hit = dw_tcp_buf_contains_needle(chunk->data, chunk->len);
		break;
	default:
		hit = false;
		break;
	}

	if (hit)
		atomic_or(aw->bit, &chunk->hit_mask);

	atomic_or(aw->bit, &chunk->done_mask);

	if (atomic_dec_and_test(&chunk->pending)) {
		dw_tcp_finalize_chunk(chunk);
		kfree(chunk);
	}

	kfree(aw);
}

int dw_tcp_enqueue_stream(struct sock *sk)
{
	struct tcp_sock *tp;
	struct dw_tcp_flow_state *state;
	struct dw_tcp_analysis_work *aw[2] = {};
	struct dw_tcp_chunk_state *chunk;
	u64 sock_cookie;
	u32 hash;
	u32 from_seq;
	u32 to_seq;
	u32 available_end;
	u32 chunk_len;
	u32 alloc_len;
	u32 req_mask;
	unsigned int cpu;
	u8 prefix_len;
	u8 prefix[DW_TCP_TAIL_LEN];
	u8 next_tail_len;
	u32 analysis_bits[2] = { DW_TCP_REQ_A1, DW_TCP_REQ_A2 };
	unsigned int scheduled = 0;
	int i;
	int copied;

	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return -EINVAL;

	tp = tcp_sk(sk);
	sock_cookie = (u64)(uintptr_t)sk;
	hash = jhash_1word((u32)sock_cookie, (u32)(sock_cookie >> 32));

	spin_lock_bh(&dw_tcp_flow_lock);
	state = dw_tcp_flow_get_locked(sk, sock_cookie, hash);
	if (!state) {
		spin_unlock_bh(&dw_tcp_flow_lock);
		return -ENOMEM;
	}

	if (state->drop_armed) {
		spin_unlock_bh(&dw_tcp_flow_lock);
		return -EPERM;
	}

	if (!state->next_seq_valid) {
		state->next_seq = READ_ONCE(tp->copied_seq);
		state->next_seq_valid = true;
		state->approved_seq = state->next_seq;
		state->approved_seq_valid = true;
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
	chunk = kzalloc(struct_size(chunk, data, alloc_len), GFP_ATOMIC);
	if (!chunk)
		return -ENOMEM;

	chunk->sock_cookie = sock_cookie;
	chunk->state = state;
	chunk->from_seq = from_seq;
	chunk->to_seq = to_seq;
	chunk->scan_from_seq = from_seq - prefix_len;
	chunk->scan_to_seq = to_seq;

	if (prefix_len)
		memcpy(chunk->data, prefix, prefix_len);

	copied = dw_tcp_copy_stream_chunk(sk, from_seq, to_seq, chunk->data + prefix_len);
	if (copied <= 0) {
		kfree(chunk);
		return copied ? copied : -ENODATA;
	}

	chunk->len = prefix_len + copied;
	req_mask = dw_tcp_chunk_req_mask(chunk->len);
	chunk->req_mask = req_mask;
	atomic_set(&chunk->done_mask, 0);
	atomic_set(&chunk->hit_mask, 0);

	next_tail_len = min_t(u8, chunk->len, DW_TCP_TAIL_LEN);
	spin_lock_bh(&dw_tcp_flow_lock);
	state = dw_tcp_flow_lookup_locked(sock_cookie, hash);
	if (state) {
		state->tail_len = next_tail_len;
		if (next_tail_len)
			memcpy(state->tail, chunk->data + chunk->len - next_tail_len, next_tail_len);
		state->last_seen_jiffies = jiffies;
	}
	spin_unlock_bh(&dw_tcp_flow_lock);

	cpu = dw_tcp_hash_to_cpu(sock_cookie);
	for (i = 0; i < ARRAY_SIZE(analysis_bits); i++) {
		if (!(req_mask & analysis_bits[i]))
			continue;

		aw[i] = kzalloc(sizeof(*aw[i]), GFP_ATOMIC);
		if (!aw[i])
			goto err_alloc;

		aw[i]->chunk = chunk;
		aw[i]->bit = analysis_bits[i];
		INIT_WORK(&aw[i]->work, dw_tcp_analysis_workfn);
		scheduled++;
	}

	atomic_set(&chunk->pending, scheduled);

	for (i = 0; i < ARRAY_SIZE(analysis_bits); i++) {
		if (!aw[i])
			continue;
		queue_work_on(cpu, dw_tcp_wq, &aw[i]->work);
	}

	pr_debug("tcp enqueue cookie=%#llx copied_seq=%u rcv_nxt=%u chunk=%u..%u len=%u cpu=%u analyses=0x%x\n",
		 sock_cookie, READ_ONCE(tp->copied_seq), available_end,
		 chunk->from_seq, chunk->to_seq, chunk->len, cpu, req_mask);
	return copied;

err_alloc:
	while (--i >= 0)
		kfree(aw[i]);
	kfree(chunk);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(dw_tcp_enqueue_stream);

bool dw_tcp_is_drop_armed(struct sock *sk)
{
	struct dw_tcp_flow_state *state;
	u64 sock_cookie;
	u32 hash;
	bool armed = false;

	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return false;

	sock_cookie = (u64)(uintptr_t)sk;
	hash = jhash_1word((u32)sock_cookie, (u32)(sock_cookie >> 32));

	spin_lock_bh(&dw_tcp_flow_lock);
	state = dw_tcp_flow_lookup_locked(sock_cookie, hash);
	if (state)
		armed = state->drop_armed;
	spin_unlock_bh(&dw_tcp_flow_lock);

	return armed;
}
EXPORT_SYMBOL_GPL(dw_tcp_is_drop_armed);

size_t dw_tcp_approved_len(struct sock *sk, size_t requested_len)
{
	struct dw_tcp_flow_state *state;
	u64 sock_cookie;
	u32 hash;
	u32 copied_seq;
	u32 approved_seq;
	size_t allowed = requested_len;

	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return requested_len;

	sock_cookie = (u64)(uintptr_t)sk;
	hash = jhash_1word((u32)sock_cookie, (u32)(sock_cookie >> 32));
	copied_seq = READ_ONCE(tcp_sk(sk)->copied_seq);

	spin_lock_bh(&dw_tcp_flow_lock);
	state = dw_tcp_flow_lookup_locked(sock_cookie, hash);
	if (!state || !state->approved_seq_valid || state->drop_armed) {
		allowed = 0;
		goto out;
	}

	approved_seq = state->approved_seq;
	if (!before(copied_seq, approved_seq)) {
		allowed = 0;
		goto out;
	}

	allowed = min_t(size_t, requested_len, (size_t)(approved_seq - copied_seq));

out:
	spin_unlock_bh(&dw_tcp_flow_lock);
	return allowed;
}
EXPORT_SYMBOL_GPL(dw_tcp_approved_len);

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
		if (state->sk)
			sock_put(state->sk);
		kfree(state);
	}
	spin_unlock_bh(&dw_tcp_flow_lock);

	pr_info("unloaded\n");
}

module_init(deferred_analysis_tcp_init);
module_exit(deferred_analysis_tcp_exit);
