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
#include <linux/ktime.h>

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
#define DW_TCP_RING_SIZE 256U
#define DW_TCP_RING_MASK (DW_TCP_RING_SIZE - 1)
#define DW_TCP_MAX_INFLIGHT_BYTES (DW_TCP_RING_SIZE * DW_TCP_CHUNK_MAX)
#define DW_TCP_REQ_A1 BIT(0)
#define DW_TCP_REQ_A2 BIT(1)
#define DW_TCP_REQ_MASK_2 (DW_TCP_REQ_A1 | DW_TCP_REQ_A2)
#define DW_TCP_CHUNK_MAX_SEGS 32U

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
	bool drop_armed;
	atomic_t init_done;
	atomic_t drain_running;
	unsigned long last_seen_jiffies;
	struct dw_tcp_ring_ent ring[DW_TCP_RING_SIZE];
	struct dw_tcp_flow_state *next;
};

struct dw_tcp_seg_ref {
	struct sk_buff *skb;
	const u8 *data;
	u32 len;
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
	u32 nr_segs;
	struct dw_tcp_seg_ref segs[DW_TCP_CHUNK_MAX_SEGS];
};

struct dw_tcp_analysis_work {
	struct work_struct work;
	struct dw_tcp_chunk_state *chunk;
	u32 bit;
	u64 scheduled_ns;
};

struct dw_tcp_flow_state *dw_tcp_flow_ht[DW_TCP_FLOW_BUCKETS];
static struct workqueue_struct *dw_tcp_wq;
static DFA_struct *dw_tcp_ac_root;
static atomic64_t st_schedule_delay_total_ns = ATOMIC64_INIT(0);
static atomic64_t st_schedule_delay_max_ns = ATOMIC64_INIT(0);
static atomic64_t st_schedule_delay_count = ATOMIC64_INIT(0);

static void dw_tcp_chunk_free(struct dw_tcp_chunk_state *chunk);

static void dw_tcp_note_schedule_delay(u64 scheduled_ns)
{
	u64 now;
	u64 delta;
	u64 old;

	if (!scheduled_ns)
		return;

	now = ktime_get_ns();
	if (now <= scheduled_ns)
		return;

	delta = now - scheduled_ns;
	atomic64_inc(&st_schedule_delay_count);
	atomic64_add(delta, &st_schedule_delay_total_ns);

	old = (u64)atomic64_read(&st_schedule_delay_max_ns);
	while (delta > old) {
		u64 prev = (u64)atomic64_cmpxchg(&st_schedule_delay_max_ns,
						      (s64)old, (s64)delta);

		if (prev == old)
			break;
		old = prev;
	}
}

static bool dw_tcp_chunk_contains_ac(const struct dw_tcp_chunk_state *chunk)
{
	DFA_node *state;
	u32 seg;
	u32 count = 0;

	if (!dw_tcp_ac_root || !chunk || chunk->len < DW_AC_MIN_LEN)
		return false;

	state = dw_tcp_ac_root->root;
	for (seg = 0; seg < chunk->nr_segs; seg++) {
		int *match_indices = NULL;
		int matches;

		if (!chunk->segs[seg].data || !chunk->segs[seg].len)
			continue;

		matches = DFA_exec_chunk(state, chunk->segs[seg].data,
					 chunk->segs[seg].len, &match_indices,
					 &state);
		kfree(match_indices);
		if (matches > 0)
			count += matches;
		if (!state)
			state = dw_tcp_ac_root->root;
	}

	return count > 0;
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
		dw_tcp_chunk_free(chunk);
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

static void dw_tcp_chunk_free(struct dw_tcp_chunk_state *chunk)
{
	u32 i;

	if (!chunk)
		return;
	for (i = 0; i < chunk->nr_segs; i++) {
		if (chunk->segs[i].skb)
			kfree_skb(chunk->segs[i].skb);
	}
	kfree(chunk);
}

static void dw_tcp_chunk_put_refs(struct dw_tcp_chunk_state *chunk)
{
	u32 i;

	if (!chunk)
		return;
	for (i = 0; i < chunk->nr_segs; i++) {
		if (chunk->segs[i].skb)
			kfree_skb(chunk->segs[i].skb);
	}
	memset(chunk->segs, 0, sizeof(chunk->segs));
	chunk->nr_segs = 0;
	chunk->len = 0;
}

static int dw_tcp_collect_linear_refs(struct sock *sk, u32 from_seq,
				      u32 available_end,
				      struct dw_tcp_chunk_state *chunk,
				      u32 *to_seq_out)
{
	struct sk_buff *skb;
	u32 cur = from_seq;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		u32 skb_seq = TCP_SKB_CB(skb)->seq;
		u32 skb_end_seq = TCP_SKB_CB(skb)->end_seq;
		u32 seg_to;
		u32 off;
		u32 len;

		if (chunk->len >= DW_TCP_CHUNK_MAX)
			break;
		if (!before(cur, available_end))
			break;
		if (!before(skb_seq, available_end))
			break;

		if (!before(cur, skb_end_seq))
			continue;

		if (before(cur, skb_seq))
			return -EAGAIN;

		seg_to = before(skb_end_seq, available_end) ? skb_end_seq : available_end;
		if (!before(cur, seg_to))
			continue;

		off = cur - skb_seq;
		len = min_t(u32, seg_to - cur, DW_TCP_CHUNK_MAX - chunk->len);
		if (!len)
			break;

		if (off > skb_headlen(skb) || len > skb_headlen(skb) - off)
			return -EMSGSIZE;
		if (chunk->nr_segs >= DW_TCP_CHUNK_MAX_SEGS)
			return -E2BIG;

		skb_get(skb);
		chunk->segs[chunk->nr_segs].skb = skb;
		chunk->segs[chunk->nr_segs].data = skb->data + off;
		chunk->segs[chunk->nr_segs].len = len;
		chunk->nr_segs++;
		chunk->len += len;
		cur += len;
	}

	if (!chunk->len)
		return -ENODATA;

	*to_seq_out = cur;
	return 0;
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
	}
}

static void dw_tcp_fail_open_to(struct dw_tcp_flow_state *state, u32 seq)
{
	u64 cur_state;
	u32 cur_pos;
	u32 cur_seq;
	u32 approved;

	for (;;) {
		cur_state = READ_ONCE(state->reserve_state);
		cur_pos = dw_tcp_reserve_pos(cur_state);
		cur_seq = dw_tcp_reserve_seq(cur_state);
		if (!before(cur_seq, seq))
			break;
		if (cmpxchg64(&state->reserve_state, cur_state,
			      dw_tcp_pack_reserve_state(cur_pos, seq)) == cur_state)
			break;
		cpu_relax();
	}

	for (;;) {
		approved = READ_ONCE(state->approved_seq);
		if (!before(approved, seq))
			break;
		if (cmpxchg(&state->approved_seq, approved, seq) == approved)
			break;
		cpu_relax();
	}
}

static int dw_tcp_reserve_chunk(struct dw_tcp_flow_state *state, struct sock *sk,
				u32 available_end, struct dw_tcp_chunk_state *chunk,
				u32 *pos, u32 *from_seq, u32 *to_seq)
{
	for (;;) {
		u64 cur_state = READ_ONCE(state->reserve_state);
		u32 head_pos = READ_ONCE(state->approved_pos);
		u32 cur_pos = dw_tcp_reserve_pos(cur_state);
		u32 cur_from = dw_tcp_reserve_seq(cur_state);
		u32 cur_to;
		u64 next_state;
		int rc;

		if (!before(cur_from, available_end))
			return 0;

		if (cur_pos - head_pos >= DW_TCP_RING_SIZE)
			return -EAGAIN;

		chunk->nr_segs = 0;
		chunk->len = 0;
		rc = dw_tcp_collect_linear_refs(sk, cur_from, available_end,
						chunk, &cur_to);
		if (rc < 0) {
			dw_tcp_chunk_put_refs(chunk);
			return rc;
		}

		next_state = dw_tcp_pack_reserve_state(cur_pos + 1, cur_to);
		if (cmpxchg64(&state->reserve_state, cur_state, next_state) == cur_state) {

			*pos = cur_pos;
			*from_seq = cur_from;
			*to_seq = cur_to;
			return 1;
		}
		dw_tcp_chunk_put_refs(chunk);
		cpu_relax();
	}
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
		dw_tcp_chunk_free(chunk);

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
		dw_tcp_chunk_free(chunk);
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

static void dw_tcp_analysis_complete(struct dw_tcp_chunk_state *chunk, u32 bit)
{
	bool hit;

	switch (bit) {
	case DW_TCP_REQ_A1:
		hit = false;
		break;
	case DW_TCP_REQ_A2:
		hit = dw_tcp_chunk_contains_ac(chunk);
		break;
	default:
		hit = false;
		break;
	}

	if (hit)
		atomic_or(bit, &chunk->hit_mask);

	atomic_or(bit, &chunk->done_mask);

	if (atomic_dec_and_test(&chunk->pending))
		dw_tcp_finalize_chunk(chunk);
}

static void dw_tcp_analysis_work_complete(struct dw_tcp_analysis_work *aw)
{
	dw_tcp_analysis_complete(aw->chunk, aw->bit);

	kfree(aw);
}

static void dw_tcp_analysis_workfn(struct work_struct *work)
{
	struct dw_tcp_analysis_work *aw = container_of(work, struct dw_tcp_analysis_work, work);

	dw_tcp_note_schedule_delay(aw->scheduled_ns);
	dw_tcp_analysis_work_complete(aw);
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
	u32 hash;
	u32 pos;
	u32 from_seq;
	u32 to_seq;
	u32 available_end;
	u32 req_mask;
	unsigned int cpu;
	u32 analysis_bits[2] = { DW_TCP_REQ_A1, DW_TCP_REQ_A2 };
	unsigned int scheduled = 0;
	int i;
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
	chunk = kzalloc(sizeof(*chunk), GFP_ATOMIC);
	if (!chunk) {
		dw_tcp_flow_put(state);
		return -ENOMEM;
	}

	reserve_rc = dw_tcp_reserve_chunk(state, sk, available_end, chunk,
					  &pos, &from_seq, &to_seq);
	if (reserve_rc <= 0) {
		if (reserve_rc < 0) {
			pr_info_ratelimited("tcp zero-copy unavailable cookie=%#llx rc=%d rcv_nxt=%u -> fail open\n",
					    sock_cookie, reserve_rc,
					    available_end);
			dw_tcp_fail_open_to(state, available_end);
		}
		dw_tcp_chunk_free(chunk);
		dw_tcp_flow_put(state);
		return (reserve_rc == 0) ? 0 : reserve_rc;
	}

	WRITE_ONCE(state->last_seen_jiffies, jiffies);

	chunk->sock_cookie = sock_cookie;
	chunk->state = state;
	chunk->pos = pos;
	chunk->from_seq = from_seq;
	chunk->to_seq = to_seq;
	chunk->scan_from_seq = from_seq;
	chunk->scan_to_seq = to_seq;
	req_mask = dw_tcp_chunk_req_mask(chunk->len);
	chunk->req_mask = req_mask;
	atomic_set(&chunk->done_mask, 0);
	atomic_set(&chunk->hit_mask, 0);
	WRITE_ONCE(state->last_seen_jiffies, jiffies);

	ent = &state->ring[dw_tcp_ring_idx(pos)];
	if (READ_ONCE(ent->chunk)) {
		reserve_state = READ_ONCE(state->reserve_state);
		pr_info("tcp ring collision cookie=%#llx pos=%u from=%u approved_pos=%u approved_seq=%u next_pos=%u next_seq=%u\n",
			sock_cookie, pos, from_seq, READ_ONCE(state->approved_pos),
			READ_ONCE(state->approved_seq),
			dw_tcp_reserve_pos(reserve_state),
			dw_tcp_reserve_seq(reserve_state));
		dw_tcp_flow_put(state);
		dw_tcp_chunk_free(chunk);
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
				hit = false;
				break;
			case DW_TCP_REQ_A2:
				hit = dw_tcp_chunk_contains_ac(chunk);
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
		aw[i]->scheduled_ns = ktime_get_ns();
		queue_work_on(cpu, dw_tcp_wq, &aw[i]->work);
	}

	if (!scheduled)
		dw_tcp_finalize_chunk(chunk);

	pr_debug("tcp enqueue cookie=%#llx copied_seq=%u rcv_nxt=%u chunk=%u..%u len=%u cpu=%u analyses=0x%x\n",
		 sock_cookie, READ_ONCE(tp->copied_seq), available_end,
		 chunk->from_seq, chunk->to_seq, chunk->len, cpu, req_mask);
	return chunk->len;
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

static int get_st_schedule_delay_total_ns(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n",
		       (long long)atomic64_read(&st_schedule_delay_total_ns));
}

static int get_st_schedule_delay_max_ns(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n",
		       (long long)atomic64_read(&st_schedule_delay_max_ns));
}

static int get_st_schedule_delay_count(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n",
		       (long long)atomic64_read(&st_schedule_delay_count));
}

static const struct kernel_param_ops st_schedule_delay_total_ns_ops = { .get = get_st_schedule_delay_total_ns };
static const struct kernel_param_ops st_schedule_delay_max_ns_ops = { .get = get_st_schedule_delay_max_ns };
static const struct kernel_param_ops st_schedule_delay_count_ops = { .get = get_st_schedule_delay_count };

module_param_cb(st_schedule_delay_total_ns, &st_schedule_delay_total_ns_ops, NULL, 0440);
MODULE_PARM_DESC(st_schedule_delay_total_ns,
		 "Total ns between deferred work scheduling and execution start");
module_param_cb(st_schedule_delay_max_ns, &st_schedule_delay_max_ns_ops, NULL, 0440);
MODULE_PARM_DESC(st_schedule_delay_max_ns,
		 "Max ns between deferred work scheduling and execution start");
module_param_cb(st_schedule_delay_count, &st_schedule_delay_count_ops, NULL, 0440);
MODULE_PARM_DESC(st_schedule_delay_count,
		 "Deferred work items measured for schedule-to-execute delay");

static int hot_state_array[20];
static int hot_state_size = 0;

module_param_array(hot_state_array, int, &hot_state_size, 0660);

EXPORT_SYMBOL_GPL(dw_tcp_approved_len);
static int __init deferred_analysis_tcp_init(void)
{
	memset(dw_tcp_flow_ht, 0, sizeof(dw_tcp_flow_ht));
	atomic64_set(&st_schedule_delay_total_ns, 0);
	atomic64_set(&st_schedule_delay_max_ns, 0);
	atomic64_set(&st_schedule_delay_count, 0);
	dw_tcp_wq = alloc_workqueue("dw_tcp_wq", WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!dw_tcp_wq)
		return -ENOMEM;

	state_id = 0;
	dw_tcp_ac_root = DFA_build((const void **)dw_ac_patterns,DW_AC_PATTERN_COUNT,hot_state_array,hot_state_size);
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
