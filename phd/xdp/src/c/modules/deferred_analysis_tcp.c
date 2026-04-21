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
#include <linux/refcount.h>
#include <linux/workqueue.h>

#include <net/tcp.h>

#include "dw_print.h"
#include "../algolib/algo-ac.h"
#include "../algolib/algo-ac.c"
#include "dw_ac_patterns_autogen.h"
#include "deferred_work_tcp.h"
#include "dw_policy.h"
#include "dw_shared_tcp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("TCP deferred analysis backend for post-reordering stream chunks");

#define DW_TCP_ANALYSIS_BITS 10
#define DW_TCP_FLOW_BUCKETS (1U << DW_TCP_ANALYSIS_BITS)
#define DW_TCP_CHUNK_MAX 4096u
#define DW_TCP_DUMMY_NEEDLE "malicious"
#define DW_TCP_DUMMY_NEEDLE_LEN (sizeof(DW_TCP_DUMMY_NEEDLE) - 1)
#define DW_TCP_TAIL_LEN ((DW_AC_MAX_LEN > 1) ? (DW_AC_MAX_LEN - 1) : 1)
#define DW_TCP_RING_SIZE 256U
#define DW_TCP_RING_MASK (DW_TCP_RING_SIZE - 1)
#define DW_TCP_MAX_INFLIGHT_BYTES (DW_TCP_RING_SIZE * DW_TCP_CHUNK_MAX)
#define DW_TCP_REQ_A1 BIT(0)
#define DW_TCP_REQ_A2 BIT(1)
#define DW_TCP_REQ_MASK_2 (DW_TCP_REQ_A1 | DW_TCP_REQ_A2)

struct dw_tcp_chunk_state;

struct dw_tcp_ring_ent {
	struct dw_tcp_chunk_state *chunk;
	u32 pos;
	u32 from_seq;
	bool ready;
};

struct dw_tcp_flow_state {
	u64 sock_cookie;
	struct sock *sk;
	refcount_t refs;
	u32 approved_seq;
	u32 approved_pos;
	u64 reserve_state;
	u32 tail_seq;
	bool drop_armed;
	u8 tail_len;
	u8 tail[DW_TCP_TAIL_LEN];
	atomic_t init_done;
	atomic_t tail_busy;
	atomic_t drain_running;
	unsigned long last_seen_jiffies;
	struct dw_tcp_ring_ent ring[DW_TCP_RING_SIZE];
	struct dw_tcp_flow_state *next;
};

struct dw_tcp_chunk_state {
	struct dw_tcp_flow_state *state;
	u64 sock_cookie;
	u32 pos;
	u32 from_seq;
	u32 to_seq;
	u32 scan_from_seq;
	u32 scan_to_seq;
	u32 req_mask;
	atomic_t done_mask;
	atomic_t hit_mask;
	atomic_t pending;
	bool ready;
	u32 len;
	u8 data[];
};

struct dw_tcp_analysis_work {
	struct work_struct work;
	struct dw_tcp_chunk_state *chunk;
	u32 bit;
};

static struct dw_tcp_flow_state *dw_tcp_flow_ht[DW_TCP_FLOW_BUCKETS];
static struct workqueue_struct *dw_tcp_wq;
static DFA_node *dw_tcp_ac_root;

static bool dw_tcp_buf_contains_dummy(const u8 *buf, size_t len)
{
	size_t i;

	if (!buf || len < DW_TCP_DUMMY_NEEDLE_LEN)
		return false;

	for (i = 0; i <= len - DW_TCP_DUMMY_NEEDLE_LEN; i++) {
		if (!memcmp(buf + i, DW_TCP_DUMMY_NEEDLE, DW_TCP_DUMMY_NEEDLE_LEN))
			return true;
	}

	return false;
}

static bool dw_tcp_buf_contains_ac(const u8 *buf, size_t len)
{
	unsigned char *tmp;
	int *match_indices = NULL;
	int matches;

	if (!dw_tcp_ac_root || !buf || len < DW_AC_MIN_LEN)
		return false;

	tmp = kmalloc(len + 1, GFP_KERNEL);
	if (!tmp)
		return false;

	memcpy(tmp, buf, len);
	tmp[len] = '\0';

	matches = DFA_exec(dw_tcp_ac_root, tmp, &match_indices);
	kfree(match_indices);
	kfree(tmp);

	return matches > 0;
}

static u32 dw_tcp_flow_bucket(u32 hash)
{
	return hash_min(hash, DW_TCP_ANALYSIS_BITS);
}

static struct dw_tcp_flow_state *dw_tcp_flow_lookup(u64 sock_cookie, u32 hash)
{
	struct dw_tcp_flow_state *state;
	u32 bkt = dw_tcp_flow_bucket(hash);

	for (state = READ_ONCE(dw_tcp_flow_ht[bkt]);
	     state;
	     state = READ_ONCE(state->next)) {
		if (state->sock_cookie == sock_cookie)
			return state;
	}

	return NULL;
}

static void dw_tcp_flow_free(struct dw_tcp_flow_state *state)
{
	u32 i;

	if (!state)
		return;

	for (i = 0; i < DW_TCP_RING_SIZE; i++) {
		struct dw_tcp_chunk_state *chunk = READ_ONCE(state->ring[i].chunk);

		if (!chunk)
			continue;
		WRITE_ONCE(state->ring[i].chunk, NULL);
		kfree(chunk);
	}

	if (state->sk)
		sock_put(state->sk);
	kfree(state);
}

static void dw_tcp_flow_put(struct dw_tcp_flow_state *state)
{
	if (state && refcount_dec_and_test(&state->refs))
		dw_tcp_flow_free(state);
}

static struct dw_tcp_flow_state *dw_tcp_flow_lookup_get(u64 sock_cookie, u32 hash)
{
	struct dw_tcp_flow_state *state;

	state = dw_tcp_flow_lookup(sock_cookie, hash);
	if (state)
		refcount_inc(&state->refs);

	return state;
}

static struct dw_tcp_flow_state *dw_tcp_flow_get(struct sock *sk, u64 sock_cookie, u32 hash)
{
	struct dw_tcp_flow_state *state;
	struct dw_tcp_flow_state *head;
	u32 bkt = dw_tcp_flow_bucket(hash);

	for (;;) {
		state = dw_tcp_flow_lookup(sock_cookie, hash);
		if (state) {
			refcount_inc(&state->refs);
			state->last_seen_jiffies = jiffies;
			return state;
		}

		state = kzalloc(sizeof(*state), GFP_ATOMIC);
		if (!state)
			return NULL;

		state->sock_cookie = sock_cookie;
		state->sk = sk;
		refcount_set(&state->refs, 2);
		atomic_set(&state->init_done, 0);
		atomic_set(&state->tail_busy, 0);
		atomic_set(&state->drain_running, 0);
		state->last_seen_jiffies = jiffies;
		sock_hold(sk);

		head = READ_ONCE(dw_tcp_flow_ht[bkt]);
		WRITE_ONCE(state->next, head);
		if (cmpxchg(&dw_tcp_flow_ht[bkt], head, state) == head)
			return state;

		dw_tcp_flow_free(state);
		cpu_relax();
	}
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

	if (scan_len >= DW_AC_MIN_LEN)
		req_mask |= DW_TCP_REQ_A2;

	return req_mask;
}

static u32 dw_tcp_ring_idx(u32 pos)
{
	return pos & DW_TCP_RING_MASK;
}

static u64 dw_tcp_pack_reserve_state(u32 pos, u32 seq)
{
	return ((u64)pos << 32) | seq;
}

static u32 dw_tcp_reserve_pos(u64 state)
{
	return (u32)(state >> 32);
}

static u32 dw_tcp_reserve_seq(u64 state)
{
	return (u32)state;
}

static void dw_tcp_flow_init_once(struct dw_tcp_flow_state *state, struct tcp_sock *tp)
{
	if (atomic_cmpxchg(&state->init_done, 0, 1) == 0) {
		u32 copied_seq = READ_ONCE(tp->copied_seq);

		WRITE_ONCE(state->approved_seq, copied_seq);
		WRITE_ONCE(state->approved_pos, 0);
		WRITE_ONCE(state->reserve_state,
			   dw_tcp_pack_reserve_state(0, copied_seq));
		WRITE_ONCE(state->tail_seq, copied_seq);
		WRITE_ONCE(state->tail_len, 0);
	}
}

static int dw_tcp_reserve_chunk(struct dw_tcp_flow_state *state, u32 available_end,
				u32 *pos, u32 *from_seq, u32 *to_seq)
{
	for (;;) {
		u64 cur_state = READ_ONCE(state->reserve_state);
		u32 head_pos = READ_ONCE(state->approved_pos);
		u32 cur_pos = dw_tcp_reserve_pos(cur_state);
		u32 cur_from = dw_tcp_reserve_seq(cur_state);
		u32 chunk_len;
		u32 cur_to;
		u64 next_state;

		if (!before(cur_from, available_end))
			return 0;

		if (cur_pos - head_pos >= DW_TCP_RING_SIZE)
			return -EAGAIN;

		chunk_len = min_t(u32, available_end - cur_from, DW_TCP_CHUNK_MAX);
		cur_to = cur_from + chunk_len;
		next_state = dw_tcp_pack_reserve_state(cur_pos + 1, cur_to);
		if (cmpxchg64(&state->reserve_state, cur_state, next_state) == cur_state) {

			*pos = cur_pos;
			*from_seq = cur_from;
			*to_seq = cur_to;
			return 1;
		}
		cpu_relax();
	}
}

static u8 dw_tcp_tail_snapshot(struct dw_tcp_flow_state *state, u32 from_seq, u8 *prefix)
{
	int retries;

	for (retries = 0; retries < 1024; retries++) {
		u32 tail_seq;
		u8 tail_len;

		if (atomic_read(&state->tail_busy)) {
			cpu_relax();
			continue;
		}

		tail_seq = READ_ONCE(state->tail_seq);
		if (tail_seq != from_seq) {
			cpu_relax();
			continue;
		}

		tail_len = READ_ONCE(state->tail_len);
		if (tail_len)
			memcpy(prefix, state->tail, tail_len);

		smp_rmb();
		if (!atomic_read(&state->tail_busy) &&
		    READ_ONCE(state->tail_seq) == from_seq &&
		    READ_ONCE(state->tail_len) == tail_len)
			return tail_len;
	}

	return 0;
}

static void dw_tcp_publish_tail(struct dw_tcp_flow_state *state, u32 to_seq,
				const u8 *buf, u32 len)
{
	u32 cur_tail;
	u8 next_tail_len;

	cur_tail = READ_ONCE(state->tail_seq);
	if (!before(cur_tail, to_seq))
		return;

	if (atomic_cmpxchg(&state->tail_busy, 0, 1) != 0)
		return;

	cur_tail = READ_ONCE(state->tail_seq);
	if (before(cur_tail, to_seq)) {
		next_tail_len = min_t(u8, len, DW_TCP_TAIL_LEN);
		WRITE_ONCE(state->tail_len, next_tail_len);
		if (next_tail_len)
			memcpy(state->tail, buf + len - next_tail_len, next_tail_len);
		smp_wmb();
		WRITE_ONCE(state->tail_seq, to_seq);
	}

	atomic_set(&state->tail_busy, 0);
}

static void dw_tcp_try_drain_flow(struct dw_tcp_flow_state *state)
{
	struct sock *drop_sk = NULL;
	bool dropped = false;

	if (atomic_cmpxchg(&state->drain_running, 0, 1) != 0)
		return;

	for (;;) {
		struct dw_tcp_ring_ent *ent;
		struct dw_tcp_chunk_state *chunk;
		u32 approved_pos = READ_ONCE(state->approved_pos);
		u32 idx = dw_tcp_ring_idx(approved_pos);
		u32 hits;

		ent = &state->ring[idx];
		chunk = READ_ONCE(ent->chunk);
		if (!chunk || !READ_ONCE(ent->ready) || READ_ONCE(ent->pos) != approved_pos)
			break;

		hits = (u32)atomic_read(&chunk->hit_mask);
		if (hits) {
			WRITE_ONCE(state->drop_armed, true);
			drop_sk = READ_ONCE(state->sk);
			dropped = true;
			pr_info("tcp deferred chunk cookie=%#llx chunk=%u..%u scan=%u..%u len=%u done=0x%x hits=0x%x verdict=DROP_CANDIDATE\n",
				chunk->sock_cookie, chunk->from_seq, chunk->to_seq,
				chunk->scan_from_seq, chunk->scan_to_seq, chunk->len,
				(u32)atomic_read(&chunk->done_mask), hits);
		} else {
			cmpxchg(&state->approved_seq, chunk->from_seq, chunk->to_seq);
		}

		WRITE_ONCE(state->approved_pos, approved_pos + 1);
		WRITE_ONCE(ent->ready, false);
		WRITE_ONCE(ent->chunk, NULL);
		dw_tcp_flow_put(state);
		kfree(chunk);

		if (dropped)
			break;
	}

	atomic_set(&state->drain_running, 0);

	if (drop_sk)
		tcp_abort(drop_sk, ECONNRESET);
}

static void dw_tcp_mark_chunk_ready(struct dw_tcp_chunk_state *chunk)
{
	struct dw_tcp_flow_state *state = chunk->state;
	struct dw_tcp_ring_ent *ent;

	ent = &state->ring[dw_tcp_ring_idx(chunk->pos)];
	if (READ_ONCE(ent->chunk) != chunk)
		return;

	chunk->ready = true;
	smp_wmb();
	WRITE_ONCE(ent->ready, true);
	dw_tcp_try_drain_flow(state);
}

static void dw_tcp_finalize_chunk(struct dw_tcp_chunk_state *chunk)
{
	if (!chunk || !chunk->state) {
		kfree(chunk);
		return;
	}

	if ((u32)atomic_read(&chunk->hit_mask)) {
		pr_info("tcp deferred chunk cookie=%#llx chunk=%u..%u scan=%u..%u len=%u done=0x%x hits=0x%x ready=1\n",
			chunk->sock_cookie, chunk->from_seq, chunk->to_seq,
			chunk->scan_from_seq, chunk->scan_to_seq, chunk->len,
			(u32)atomic_read(&chunk->done_mask),
			(u32)atomic_read(&chunk->hit_mask));
	} else {
		pr_debug("tcp deferred chunk cookie=%#llx chunk=%u..%u scan=%u..%u len=%u done=0x%x ready=1\n",
			 chunk->sock_cookie, chunk->from_seq, chunk->to_seq,
			 chunk->scan_from_seq, chunk->scan_to_seq, chunk->len,
			 (u32)atomic_read(&chunk->done_mask));
	}

	dw_tcp_mark_chunk_ready(chunk);
}

static void dw_tcp_analysis_workfn(struct work_struct *work)
{
	struct dw_tcp_analysis_work *aw = container_of(work, struct dw_tcp_analysis_work, work);
	struct dw_tcp_chunk_state *chunk = aw->chunk;
	bool hit;

	switch (aw->bit) {
	case DW_TCP_REQ_A1:
		
		hit = dw_tcp_buf_contains_dummy(chunk->data, chunk->len);
		break;
	case DW_TCP_REQ_A2:
		hit = dw_tcp_buf_contains_ac(chunk->data, chunk->len);
		break;
	default:
		hit = false;
		break;
	}

	if (hit)
		atomic_or(aw->bit, &chunk->hit_mask);

	atomic_or(aw->bit, &chunk->done_mask);

	if (atomic_dec_and_test(&chunk->pending))
		dw_tcp_finalize_chunk(chunk);

	kfree(aw);
}

int dw_tcp_enqueue_stream(struct sock *sk)
{
	struct tcp_sock *tp;
	struct dw_tcp_flow_state *state;
	struct dw_tcp_analysis_work *aw[2] = {};
	struct dw_tcp_ring_ent *ent;
	struct dw_tcp_chunk_state *chunk;
	u64 sock_cookie;
	u64 reserve_state;
	u64 expect_state;
	u32 hash;
	u32 pos;
	u32 from_seq;
	u32 to_seq;
	u32 available_end;
	u32 req_mask;
	unsigned int cpu;
	u8 prefix_len;
	u8 prefix[DW_TCP_TAIL_LEN];
	u32 analysis_bits[2] = { DW_TCP_REQ_A1, DW_TCP_REQ_A2 };
	unsigned int scheduled = 0;
	int i;
	int copied;
	int reserve_rc;
	bool hit;

	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return -EINVAL;

	tp = tcp_sk(sk);
	sock_cookie = (u64)(uintptr_t)sk;
	hash = jhash_1word((u32)sock_cookie, (u32)(sock_cookie >> 32));

	state = dw_tcp_flow_get(sk, sock_cookie, hash);
	if (!state)
		return -ENOMEM;

	dw_tcp_flow_init_once(state, tp);

	if (READ_ONCE(state->drop_armed)) {
		dw_tcp_flow_put(state);
		return -EPERM;
	}

	available_end = READ_ONCE(tp->rcv_nxt);
	reserve_rc = dw_tcp_reserve_chunk(state, available_end, &pos, &from_seq, &to_seq);
	if (reserve_rc <= 0) {
		dw_tcp_flow_put(state);
		return (reserve_rc == 0) ? 0 : reserve_rc;
	}

	WRITE_ONCE(state->last_seen_jiffies, jiffies);

	prefix_len = dw_tcp_tail_snapshot(state, from_seq, prefix);
	chunk = kzalloc(struct_size(chunk, data, DW_TCP_TAIL_LEN + DW_TCP_CHUNK_MAX),
			GFP_ATOMIC);
	if (!chunk) {
		expect_state = dw_tcp_pack_reserve_state(pos + 1, to_seq);
		if (cmpxchg64(&state->reserve_state, expect_state,
			      dw_tcp_pack_reserve_state(pos, from_seq)) != expect_state)
			pr_info("tcp rollback failed cookie=%#llx chunk=%u..%u\n",
				sock_cookie, from_seq, to_seq);
		dw_tcp_flow_put(state);
		return -ENOMEM;
	}

	chunk->sock_cookie = sock_cookie;
	chunk->state = state;
	chunk->pos = pos;
	chunk->from_seq = from_seq;
	chunk->to_seq = to_seq;
	chunk->scan_from_seq = from_seq - prefix_len;
	chunk->scan_to_seq = to_seq;

	if (prefix_len)
		memcpy(chunk->data, prefix, prefix_len);

	copied = dw_tcp_copy_stream_chunk(sk, from_seq, to_seq, chunk->data + prefix_len);
	if (copied <= 0) {
		expect_state = dw_tcp_pack_reserve_state(pos + 1, to_seq);
		if (cmpxchg64(&state->reserve_state, expect_state,
			      dw_tcp_pack_reserve_state(pos, from_seq)) != expect_state)
			pr_info("tcp rollback failed cookie=%#llx chunk=%u..%u rc=%d\n",
				sock_cookie, from_seq, to_seq, copied);
		dw_tcp_flow_put(state);
		kfree(chunk);
		return copied ? copied : -ENODATA;
	}

	chunk->len = prefix_len + copied;
	req_mask = dw_tcp_chunk_req_mask(chunk->len);
	chunk->req_mask = req_mask;
	atomic_set(&chunk->done_mask, 0);
	atomic_set(&chunk->hit_mask, 0);
	WRITE_ONCE(state->last_seen_jiffies, jiffies);
	dw_tcp_publish_tail(state, to_seq, chunk->data, chunk->len);

	ent = &state->ring[dw_tcp_ring_idx(pos)];
	if (READ_ONCE(ent->chunk)) {
		reserve_state = READ_ONCE(state->reserve_state);
		pr_info("tcp ring collision cookie=%#llx pos=%u from=%u approved_pos=%u approved_seq=%u next_pos=%u next_seq=%u\n",
			sock_cookie, pos, from_seq, READ_ONCE(state->approved_pos),
			READ_ONCE(state->approved_seq),
			dw_tcp_reserve_pos(reserve_state),
			dw_tcp_reserve_seq(reserve_state));
		dw_tcp_flow_put(state);
		kfree(chunk);
		return -EAGAIN;
	}
	WRITE_ONCE(ent->pos, pos);
	WRITE_ONCE(ent->from_seq, from_seq);
	WRITE_ONCE(ent->ready, false);
	smp_wmb();
	WRITE_ONCE(ent->chunk, chunk);

	cpu = dw_tcp_hash_to_cpu(sock_cookie);
	for (i = 0; i < ARRAY_SIZE(analysis_bits); i++) {
		if (!(req_mask & analysis_bits[i]))
			continue;

		aw[i] = kzalloc(sizeof(*aw[i]), GFP_ATOMIC);
		if (!aw[i]) {
			switch (analysis_bits[i]) {
			case DW_TCP_REQ_A1:
				hit = dw_tcp_buf_contains_dummy(chunk->data, chunk->len);
				break;
			case DW_TCP_REQ_A2:
				hit = dw_tcp_buf_contains_ac(chunk->data, chunk->len);
				break;
			default:
				hit = false;
				break;
			}

			if (hit)
				atomic_or(analysis_bits[i], &chunk->hit_mask);
			atomic_or(analysis_bits[i], &chunk->done_mask);
			continue;
		}

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

	if (!scheduled)
		dw_tcp_finalize_chunk(chunk);

	pr_debug("tcp enqueue cookie=%#llx copied_seq=%u rcv_nxt=%u chunk=%u..%u len=%u cpu=%u analyses=0x%x\n",
		 sock_cookie, READ_ONCE(tp->copied_seq), available_end,
		 chunk->from_seq, chunk->to_seq, chunk->len, cpu, req_mask);
	return copied;
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

	state = dw_tcp_flow_lookup_get(sock_cookie, hash);
	if (!state)
		return false;

	armed = READ_ONCE(state->drop_armed);
	dw_tcp_flow_put(state);

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

	state = dw_tcp_flow_lookup_get(sock_cookie, hash);
	if (!state)
		return requested_len;

	if (READ_ONCE(state->drop_armed)) {
		allowed = 0;
		goto out;
	}

	approved_seq = READ_ONCE(state->approved_seq);
	if (!before(copied_seq, approved_seq)) {
		allowed = 0;
		goto out;
	}

	allowed = min_t(size_t, requested_len, (size_t)(approved_seq - copied_seq));

out:
	dw_tcp_flow_put(state);
	return allowed;
}
EXPORT_SYMBOL_GPL(dw_tcp_approved_len);

static int __init deferred_analysis_tcp_init(void)
{
	memset(dw_tcp_flow_ht, 0, sizeof(dw_tcp_flow_ht));
	dw_tcp_wq = alloc_workqueue("dw_tcp_wq", WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!dw_tcp_wq)
		return -ENOMEM;

	state_id = 0;
	dw_tcp_ac_root = DFA_build((const void **)dw_ac_patterns,
				   DW_AC_PATTERN_COUNT);
	if (!dw_tcp_ac_root) {
		destroy_workqueue(dw_tcp_wq);
		dw_tcp_wq = NULL;
		return -ENOMEM;
	}

	pr_info("loaded monitor flags: udp=0x%x tcp=0x%x both=0x%x chunk_max=%u signatures=%u source=\"%s\"\n",
		DW_MON_UDP, DW_MON_TCP, DW_MON_BOTH, DW_TCP_CHUNK_MAX,
		DW_AC_PATTERN_COUNT, DW_AC_PATTERN_LABEL);
	return 0;
}

static void __exit deferred_analysis_tcp_exit(void)
{
	struct dw_tcp_flow_state *state;
	int bkt;

	if (dw_tcp_wq) {
		destroy_workqueue(dw_tcp_wq);
		dw_tcp_wq = NULL;
	}
	if (dw_tcp_ac_root) {
		DFA_free(dw_tcp_ac_root);
		dw_tcp_ac_root = NULL;
	}

	for (bkt = 0; bkt < DW_TCP_FLOW_BUCKETS; bkt++) {
		state = xchg(&dw_tcp_flow_ht[bkt], NULL);
		while (state) {
			struct dw_tcp_flow_state *next = READ_ONCE(state->next);

			WRITE_ONCE(state->next, NULL);
			dw_tcp_flow_put(state);
			state = next;
		}
	}

	pr_info("unloaded\n");
}

module_init(deferred_analysis_tcp_init);
module_exit(deferred_analysis_tcp_exit);
