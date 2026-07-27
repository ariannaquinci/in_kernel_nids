#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <linux/unistd.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/overflow.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/math64.h>

#include <linux/skbuff.h>
#include <linux/hashtable.h>
#include <net/netfilter/nf_queue.h>

#include <net/ip.h>

#include "dw_print.h"
#include "../algolib/algo-ac.h"
#include "../algolib/algo-ac.c"
#include "dw_ac_patterns_autogen.h"
#include "deferred_work.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("UDP deferred analysis path separated from the future TCP stream pipeline");

/* -------- per-packet analysis state -------- */

struct pkt_state {
	u32 pkt_id;
	atomic_t analysis_done;
	atomic_t verdict; /* 0 unknown, 1 pass, 2 drop */
	unsigned long last_seen_jiffies;
	struct pkt_state *next;
	struct rcu_head rcu;
};

#define STATE_BITS 12
#define STATE_BUCKETS (1U << STATE_BITS)
static struct pkt_state *state_ht[STATE_BUCKETS];

/* -------- correlation table: fingerprint -> pkt_id -------- */

struct meta_ent {
	struct dw_pkt_key key;
	u32 pkt_id;
	unsigned long ts_jiffies;
	unsigned long claimed_jiffies;
	atomic_t claimed;
	struct meta_ent *next;
	struct rcu_head rcu;
};

#define META_BITS 12
#define META_BUCKETS (1U << META_BITS)
#define META_CLAIM_TIMEOUT (5 * HZ)
static struct meta_ent *meta_ht[META_BUCKETS];

/* -------- XDP packet snapshots: pkt_id -> frame copy -------- */

struct pkt_snap_ent {
	u32 pkt_id;
	u32 frame_len;
	u32 cap_len;
	unsigned long ts_jiffies;
	refcount_t refs;
	struct pkt_snap_ent *next;
	struct rcu_head rcu;
	u8 data[];
};

#define SNAP_BITS 12
#define SNAP_BUCKETS (1U << SNAP_BITS)
static struct pkt_snap_ent *snap_ht[SNAP_BUCKETS];

/* -------- per-flow buffering lock-free (head/tail ring per flow) -------- */

struct dw_flow_key {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8  proto;
	u8  pad1;
	u16 pad2;
} __aligned(4);

struct dw_buf_ent {
	struct nf_queue_entry *qent;
	u32 pkt_id;
	u32 pos;
	bool ready;
	u64 enqueue_ns;
};

#define FLOW_BITS 12
#define FLOW_BUCKETS (1U << FLOW_BITS)
#define DW_FLOW_RING_SIZE 256U
#define DW_FLOW_RING_MASK (DW_FLOW_RING_SIZE - 1)

struct flow_ent {
	struct dw_flow_key key;
	struct flow_ent *next;
	atomic_t tail;
	u32 head;
	unsigned long last_seen_jiffies;
	struct dw_buf_ent ring[DW_FLOW_RING_SIZE];
};

static struct flow_ent *flow_ht[FLOW_BUCKETS];

static struct workqueue_struct *dw_wq;

/* -------- deferred analyses -------- */
#define DW_SPEC_CHUNK_SIZE 128U
#define DW_SPEC_CHUNK_INC_BITS 4U
#define DW_SPEC_COUNT_BITS 32U
#define DW_SPEC_HOT_BITS (64U - DW_SPEC_CHUNK_INC_BITS - DW_SPEC_COUNT_BITS)
#define DW_SPEC_CHUNK_INC_MASK ((1ULL << DW_SPEC_CHUNK_INC_BITS) - 1ULL)
#define DW_SPEC_COUNT_MASK ((1ULL << DW_SPEC_COUNT_BITS) - 1ULL)
#define DW_SPEC_HOT_MASK ((1ULL << DW_SPEC_HOT_BITS) - 1ULL)
#define DW_SPEC_HOT_NONE ((u32)DW_SPEC_HOT_MASK)
#define DW_SPEC_ENTRY_EMPTY 0LL
#define DW_SPEC_ENTRY_MASTER (-1LL)
#define DW_SPEC_SLOTS_PER_CACHELINE \
	(SMP_CACHE_BYTES / sizeof(atomic64_t))
#define DW_SPEC_MAX_WORKERS_PER_PKT 512U
#define DW_SKB_REF_PAYLOAD_MAX 65535U
#define DW_DEFERRED_WORKER_MAX 64U
#define DW_AC_SCAN_CHUNK 512U
#define DW_SKB_DRAIN_BUDGET 64U
#define DW_DELIVERY_REINJECT_BUDGET 256U

typedef struct analysis_metadata {
	atomic64_t *result_state;
	void *result_state_alloc;
	const u8 *payload;
	struct pkt_snap_ent *snap;
	struct sk_buff *skb_ref;
	u32 payload_len;
	u32 chunk_size;
	u32 num_chunks;
	u32 num_start_states;
	u32 result_stride;
	u32 pkt_id;
	u32 checkpoint;
	u32 spec_used_workers;
	u64 count_global;
	bool payload_owned;
	atomic_t pending_workers;
	atomic_t done;
} analysis_metadata;

struct analysis_work {
	struct work_struct work;
	u32 chunk_idx;
	u32 start_idx;
	analysis_metadata * am;
	u64 scheduled_ns;
};

struct skb_direct_work {
	struct work_struct work;
	struct list_head list;
	struct sk_buff *skb;
	u32 pkt_id;
	u32 payload_off;
	u32 payload_len;
	u64 scheduled_ns;
};

struct payload_single_work {
	struct work_struct work;
	struct list_head list;
	const u8 *payload;
	struct pkt_snap_ent *snap;
	struct sk_buff *skb_ref;
	u32 pkt_id;
	u32 payload_len;
	u64 scheduled_ns;
	bool payload_owned;
};

/* -------- stats/debug -------- */

static atomic_t st_pending   = ATOMIC_INIT(0);
static atomic_t st_delivered = ATOMIC_INIT(0);
static atomic_t st_dropped   = ATOMIC_INIT(0);
static atomic_t delivery_running = ATOMIC_INIT(0);
static atomic_t delivery_kicked  = ATOMIC_INIT(0);
static atomic_t nfq_stopping     = ATOMIC_INIT(0);
static atomic_t nfq_quiescing    = ATOMIC_INIT(0);
static atomic_t dw_stopping      = ATOMIC_INIT(0);
static atomic_t nf_pkt_seq       = ATOMIC_INIT(0);
static bool inline_analysis;
static bool single_worker;
static uint deferred_worker_count = 1;
static char *nids_action = "enforce";
static LIST_HEAD(skb_single_queue);
static DEFINE_SPINLOCK(skb_single_lock);
static struct work_struct skb_single_drain_work;
static struct work_struct skb_deferred_worker_work[DW_DEFERRED_WORKER_MAX];
static bool skb_single_work_pending;
static unsigned int skb_deferred_worker_active;
static unsigned int skb_single_depth;
static LIST_HEAD(payload_single_queue);
static DEFINE_SPINLOCK(payload_single_lock);
static struct work_struct payload_single_drain_work;
static bool payload_single_work_pending;
static unsigned int payload_single_depth;
static struct kmem_cache *skb_direct_work_cache;
static struct kmem_cache *payload_single_work_cache;
/* Per-packet analysis latency for the multi-worker path.
 * Placed on their own cache lines to avoid false sharing with
 * delivery_running/delivery_kicked which are hit by the delivery loop. */
static atomic64_t st_analysis_total_ns ____cacheline_aligned = ATOMIC64_INIT(0);
static atomic64_t st_analysis_max_ns   ____cacheline_aligned = ATOMIC64_INIT(0);
static atomic64_t st_schedule_delay_total_ns = ATOMIC64_INIT(0);
static atomic64_t st_schedule_delay_max_ns   = ATOMIC64_INIT(0);
static atomic64_t st_schedule_delay_count    = ATOMIC64_INIT(0);
static atomic64_t st_spec_workers_total = ATOMIC64_INIT(0);
static atomic64_t st_spec_workers_used  = ATOMIC64_INIT(0);
static atomic64_t st_spec_workers_wasted = ATOMIC64_INIT(0);

static DFA_struct *dw_ac_root;
static void dw_try_deliver_ready(void);
static void dw_finish_payload_signature(u32 pkt_id, bool is_malicious);

static inline void dw_cond_resched(void)
{
	if (!in_atomic() && !irqs_disabled())
		cond_resched();
}

static void dw_note_schedule_delay(u64 scheduled_ns)
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

static u32 dw_ac_match_bytes(DFA_node *root, const u8 *buf, size_t len,
			     DFA_node **final_stage)
{
	DFA_node *state = root;
	int *match_indices = NULL;
	u32 count = 0;
	size_t off = 0;

	if (!root || !buf || !len)
		return 0;

	while (off < len) {
		size_t n = min_t(size_t, len - off, DW_AC_SCAN_CHUNK);
		int matches;

		matches = DFA_exec_chunk(state, buf + off, n, &match_indices,
					 &state);
		kfree(match_indices);
		match_indices = NULL;
		if (matches > 0)
			count += matches;
		off += n;
		dw_cond_resched();
	}

	if (final_stage)
		*final_stage = state ? state : root;

	return count;
}




/* -------- helpers -------- */

static inline u32 state_bucket(u32 pkt_id)
{
	return hash_min(pkt_id, STATE_BITS);
}

static inline u32 flow_bucket_hash(u32 h)
{
	return hash_min(h, FLOW_BITS);
}

static bool dw_module_is_stopping(void);

static struct pkt_state *state_lookup_rcu(u32 pkt_id)
{
	struct pkt_state *st;
	u32 bkt = state_bucket(pkt_id);

	for (st = READ_ONCE(state_ht[bkt]); st; st = READ_ONCE(st->next)) {
		if (READ_ONCE(st->pkt_id) == pkt_id)
			return st;
	}

	return NULL;
}

static struct pkt_state *state_alloc(u32 pkt_id)
{
	struct pkt_state *st;

	st = kzalloc(sizeof(*st), GFP_ATOMIC);
	if (!st)
		return NULL;

	st->pkt_id = pkt_id;
	atomic_set(&st->analysis_done, 0);
	atomic_set(&st->verdict, DW_VERDICT_UNKNOWN);
	st->last_seen_jiffies = jiffies;
	st->next = NULL;
	return st;
}

static void state_drop(u32 pkt_id)
{
	struct pkt_state *prev = NULL;
	struct pkt_state *st;
	struct pkt_state *next;
	u32 bkt = state_bucket(pkt_id);

	if (!pkt_id)
		return;

retry:
	rcu_read_lock();
	prev = NULL;
	for (st = READ_ONCE(state_ht[bkt]); st; st = READ_ONCE(st->next)) {
		if (READ_ONCE(st->pkt_id) != pkt_id) {
			prev = st;
			continue;
		}

		next = READ_ONCE(st->next);
		if (prev) {
			if (cmpxchg(&prev->next, st, next) != st) {
				rcu_read_unlock();
				goto retry;
			}
		} else {
			if (cmpxchg(&state_ht[bkt], st, next) != st) {
				rcu_read_unlock();
				goto retry;
			}
		}

		WRITE_ONCE(st->next, NULL);
		rcu_read_unlock();
		kfree_rcu(st, rcu);
		return;
	}
	rcu_read_unlock();
}

static __bpf_kfunc int dw_state_init(u32 pkt_id)
{
	struct pkt_state *st;
	struct pkt_state *new_st;
	struct pkt_state *head;
	u32 bkt;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!pkt_id)
		return -EINVAL;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st) {
		WRITE_ONCE(st->last_seen_jiffies, jiffies);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	new_st = state_alloc(pkt_id);
	if (!new_st)
		return -ENOMEM;

	bkt = state_bucket(pkt_id);
	for (;;) {
		head = READ_ONCE(state_ht[bkt]);
		WRITE_ONCE(new_st->next, head);
		if (cmpxchg(&state_ht[bkt], head, new_st) == head)
			return 0;

		rcu_read_lock();
		st = state_lookup_rcu(pkt_id);
		if (st) {
			WRITE_ONCE(st->last_seen_jiffies, jiffies);
			rcu_read_unlock();
			kfree(new_st);
			return 0;
		}
		rcu_read_unlock();
	}
}

static void pkt_state_try_set_pass(struct pkt_state *st)
{
	atomic_cmpxchg(&st->verdict, DW_VERDICT_UNKNOWN, DW_VERDICT_PASS);
}

static bool dw_alert_only_mode(void)
{
	return nids_action && !strcmp(nids_action, "alert");
}

static void pkt_state_set_drop(struct pkt_state *st)
{
	int verdict;

	if (dw_alert_only_mode()) {
		/*
		 * Alert-only UDP mode: record completion, but never publish a
		 * DROP verdict. Netfilter/NFQUEUE will accept.
		 */
		// pr_warn_ratelimited("ALERT UDP payload signature match pkt_id=%u action=accept\n",
		// 		    st->pkt_id);
		atomic_set(&st->verdict, DW_VERDICT_PASS);
		return;
	}

	for (;;) {
		verdict = atomic_read(&st->verdict);
		if (verdict == DW_VERDICT_DROP)
			return;
		if (atomic_cmpxchg(&st->verdict, verdict, DW_VERDICT_DROP) == verdict)
			return;
	}
}

static inline u32 snap_bucket(u32 pkt_id)
{
	return hash_min(pkt_id, SNAP_BITS);
}

static struct pkt_snap_ent *snap_lookup_rcu(u32 pkt_id)
{
	struct pkt_snap_ent *e;
	u32 bkt = snap_bucket(pkt_id);

	for (e = READ_ONCE(snap_ht[bkt]); e; e = READ_ONCE(e->next)) {
		if (READ_ONCE(e->pkt_id) == pkt_id)
			return e;
	}

	return NULL;
}

static void snap_put(struct pkt_snap_ent *snap)
{
	int refs;

	if (!snap)
		return;

	if (refcount_dec_and_test(&snap->refs)) {
		pr_debug("snapshot pkt_id=%u ref put refs=0 -> free\n",
			snap->pkt_id);
		kfree_rcu(snap, rcu);
		return;
	}

	refs = refcount_read(&snap->refs);
	pr_debug("snapshot pkt_id=%u ref put refs=%d\n", snap->pkt_id, refs);
}

static struct pkt_snap_ent *snap_get(u32 pkt_id)
{
	struct pkt_snap_ent *snap;
	int refs = 0;

	rcu_read_lock();
	snap = snap_lookup_rcu(pkt_id);
	if (snap) {
		if (refcount_inc_not_zero(&snap->refs))
			refs = refcount_read(&snap->refs);
		else
			snap = NULL;
	}
	rcu_read_unlock();

	if (snap)
		pr_debug("snapshot pkt_id=%u ref get refs=%d\n", pkt_id, refs);
	else
		pr_debug("snapshot pkt_id=%u ref get miss\n", pkt_id);

	return snap;
}

static inline u32 meta_bucket_hash(u32 h)
{
	return hash_min(h, META_BITS);
}

static bool meta_claim_expired(struct meta_ent *e, unsigned long now)
{
	unsigned long claimed_at;

	if (!atomic_read(&e->claimed))
		return false;

	claimed_at = READ_ONCE(e->claimed_jiffies);
	return time_after_eq(now, claimed_at + META_CLAIM_TIMEOUT);
}

static bool meta_try_unlink(u32 bkt, struct meta_ent *prev, struct meta_ent *cur)
{
	struct meta_ent *next = READ_ONCE(cur->next);

	if (prev)
		return cmpxchg(&prev->next, cur, next) == cur;

	return cmpxchg(&meta_ht[bkt], cur, next) == cur;
}

static void meta_gc_bucket(u32 bkt, unsigned long now)
{
	struct meta_ent *prev = NULL;
	struct meta_ent *cur;

retry:
	rcu_read_lock();
	prev = NULL;
	for (cur = READ_ONCE(meta_ht[bkt]); cur; cur = READ_ONCE(cur->next)) {
		if (!meta_claim_expired(cur, now)) {
			prev = cur;
			continue;
		}

		if (!meta_try_unlink(bkt, prev, cur)) {
			rcu_read_unlock();
			goto retry;
		}

		WRITE_ONCE(cur->next, NULL);
		kfree_rcu(cur, rcu);
		rcu_read_unlock();
		goto retry;
	}
	rcu_read_unlock();
}

static void snap_drop(u32 pkt_id)
{
	struct pkt_snap_ent *prev = NULL;
	struct pkt_snap_ent *e;
	struct pkt_snap_ent *next;
	u32 bkt = snap_bucket(pkt_id);

retry:
	rcu_read_lock();
	prev = NULL;
	for (e = READ_ONCE(snap_ht[bkt]); e; e = READ_ONCE(e->next)) {
		if (READ_ONCE(e->pkt_id) != pkt_id) {
			prev = e;
			continue;
		}

		next = READ_ONCE(e->next);
		if (prev) {
			if (cmpxchg(&prev->next, e, next) != e) {
				rcu_read_unlock();
				goto retry;
			}
		} else {
			if (cmpxchg(&snap_ht[bkt], e, next) != e) {
				rcu_read_unlock();
				goto retry;
			}
		}

		rcu_read_unlock();
		pr_debug("snapshot pkt_id=%u dropped from table refs=%d\n",
			pkt_id, refcount_read(&e->refs));
		snap_put(e);
		return;
	}
	rcu_read_unlock();
}

static bool frame_udp_payload_view(const u8 *frame, u32 frame_len,
				   const u8 **payload_out, u32 *payload_len_out)
{
	const struct ethhdr *eth;
	const struct iphdr *iph;
	const struct udphdr *uh;
	const u8 *nh;
	u32 nh_len, l4_off, payload_off, payload_len;

	if (!frame || !payload_out || !payload_len_out || frame_len < sizeof(*eth))
		return false;

	eth = (const struct ethhdr *)frame;
	if (eth->h_proto != htons(ETH_P_IP))
		return false;

	nh = frame + sizeof(*eth);
	nh_len = frame_len - sizeof(*eth);

	if (nh_len < sizeof(*iph))
		return false;

	iph = (const struct iphdr *)nh;
	if (iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return false;

	l4_off = iph->ihl * 4;
	if (l4_off < sizeof(*iph) || nh_len < l4_off + sizeof(*uh))
		return false;

	uh = (const struct udphdr *)(nh + l4_off);
	if (ntohs(uh->len) <= sizeof(*uh))
		return false;

	payload_off = (u32)((const u8 *)(uh + 1) - frame);
	if (payload_off > frame_len)
		return false;

	payload_len = frame_len - payload_off;
	payload_len = min_t(u32, payload_len, ntohs(uh->len) - sizeof(*uh));
	if (!payload_len)
		return false;

	*payload_out = frame + payload_off;
	*payload_len_out = payload_len;
	return true;
}

static u32 dw_next_nf_pkt_id(void)
{
	u32 seq = (u32)atomic_inc_return(&nf_pkt_seq) & 0x00ffffff;
	u32 cpu;

	if (!seq)
		seq = (u32)atomic_inc_return(&nf_pkt_seq) & 0x00ffffff;

	cpu = raw_smp_processor_id() & 0xff;
	return (cpu << 24) | seq;
}

static int skb_udp_payload_copy(struct sk_buff *skb, u8 **payload_out,
				u32 *payload_len_out)
{
	struct iphdr _iph, *iph;
	struct udphdr _uh, *uh;
	unsigned int ip_off;
	unsigned int l4_off;
	u32 payload_off;
	u32 payload_len;
	u8 *payload;
	int rc;

	if (!skb || !payload_out || !payload_len_out)
		return -EINVAL;

	ip_off = skb_network_offset(skb);
	iph = skb_header_pointer(skb, ip_off, sizeof(_iph), &_iph);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;

	if (iph->ihl * 4 < sizeof(*iph))
		return -EINVAL;
	l4_off = ip_off + iph->ihl * 4;

	uh = skb_header_pointer(skb, l4_off, sizeof(_uh), &_uh);
	if (!uh)
		return -EINVAL;

	if (ntohs(uh->len) <= sizeof(*uh))
		return -EINVAL;

	payload_off = l4_off + sizeof(*uh);
	payload_len = ntohs(uh->len) - sizeof(*uh);
	if (payload_off > skb->len)
		return -EINVAL;
	payload_len = min_t(u32, payload_len, skb->len - payload_off);
	if (!payload_len)
		return -EINVAL;

	payload = kmalloc(payload_len, GFP_ATOMIC);
	if (!payload)
		return -ENOMEM;

	rc = skb_copy_bits(skb, payload_off, payload, payload_len);
	if (rc < 0) {
		kfree(payload);
		return rc;
	}

	*payload_out = payload;
	*payload_len_out = payload_len;
	return 0;
}

static __maybe_unused int skb_udp_payload_view_linear(struct sk_buff *skb,
						      const u8 **payload_out,
						      u32 *payload_len_out)
{
	struct iphdr *iph;
	struct udphdr *uh;
	unsigned int l4_off;
	u32 payload_off;
	u32 payload_len;

	if (!skb || !payload_out || !payload_len_out)
		return -EINVAL;

	if (!pskb_may_pull(skb, sizeof(*iph)))
		return -EINVAL;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;

	l4_off = iph->ihl * 4;
	if (l4_off < sizeof(*iph))
		return -EINVAL;

	if (!pskb_may_pull(skb, l4_off + sizeof(*uh)))
		return -EINVAL;

	iph = ip_hdr(skb);
	uh = (struct udphdr *)((u8 *)iph + l4_off);
	if (ntohs(uh->len) <= sizeof(*uh))
		return -EINVAL;

	payload_off = skb_network_offset(skb) + l4_off + sizeof(*uh);
	payload_len = ntohs(uh->len) - sizeof(*uh);
	if (payload_off > skb_headlen(skb) ||
	    payload_len > skb_headlen(skb) - payload_off)
		return -EMSGSIZE;
	if (!payload_len)
		return -EINVAL;

	*payload_out = skb->data + payload_off;
	*payload_len_out = payload_len;
	return 0;
}

static int skb_udp_payload_desc(struct sk_buff *skb, u32 *payload_off_out,
				u32 *payload_len_out)
{
	struct iphdr *iph;
	struct udphdr *uh;
	unsigned int l4_off;
	u32 payload_off;
	u32 payload_len;

	if (!skb || !payload_off_out || !payload_len_out)
		return -EINVAL;

	if (!pskb_may_pull(skb, sizeof(*iph)))
		return -EINVAL;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;

	l4_off = iph->ihl * 4;
	if (l4_off < sizeof(*iph))
		return -EINVAL;

	if (!pskb_may_pull(skb, l4_off + sizeof(*uh)))
		return -EINVAL;

	iph = ip_hdr(skb);
	uh = (struct udphdr *)((u8 *)iph + l4_off);
	if (ntohs(uh->len) <= sizeof(*uh))
		return -EINVAL;

	payload_off = skb_network_offset(skb) + l4_off + sizeof(*uh);
	payload_len = ntohs(uh->len) - sizeof(*uh);
	if (payload_off > skb->len)
		return -EINVAL;
	payload_len = min_t(u32, payload_len, skb->len - payload_off);
	if (!payload_len)
		return -EINVAL;

	*payload_off_out = payload_off;
	*payload_len_out = payload_len;
	return 0;
}

static int dw_ac_match_skb_range(struct sk_buff *skb, DFA_node **state_io,
				 u32 off, u32 len, u32 *count_out,
				 u32 *done_out, u32 depth)
{
	u32 head_len;
	u32 done = 0;
	u32 i;
	struct sk_buff *frag_skb;

	if (!skb || !state_io || !*state_io || !count_out || !done_out)
		return -EINVAL;
	if (depth > 8)
		return -ELOOP;

	head_len = skb_headlen(skb);
	if (off < head_len) {
		u32 head_done = 0;
		u32 head_total = min_t(u32, len, head_len - off);

		while (head_done < head_total) {
			u32 n = min_t(u32, head_total - head_done,
				      DW_AC_SCAN_CHUNK);
			int *match_indices = NULL;
			int matches;

			matches = DFA_exec_chunk(*state_io,
						 skb->data + off + head_done, n,
						 &match_indices, state_io);
			kfree(match_indices);
			if (matches > 0)
				*count_out += matches;
			done += n;
			head_done += n;
			dw_cond_resched();
		}
	}

	off = (off > head_len) ? off - head_len : 0;
	for (i = 0; done < len && i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 frag_len = skb_frag_size(frag);
		u32 n;
		void *addr;
		u8 *ptr;
		int *match_indices = NULL;
		int matches;

		if (off >= frag_len) {
			off -= frag_len;
			continue;
		}

		n = min_t(u32, len - done, frag_len - off);
		while (n) {
			u32 chunk = min_t(u32, n, DW_AC_SCAN_CHUNK);

			addr = kmap_local_page(skb_frag_page(frag));
			ptr = (u8 *)addr + skb_frag_off(frag) + off;
			matches = DFA_exec_chunk(*state_io, ptr, chunk,
						 &match_indices, state_io);
			kunmap_local(addr);
			kfree(match_indices);
			match_indices = NULL;
			if (matches > 0)
				*count_out += matches;
			done += chunk;
			off += chunk;
			n -= chunk;
			dw_cond_resched();
		}
		off = 0;
	}

	if (done >= len) {
		*done_out += done;
		return 0;
	}

	frag_skb = skb_shinfo(skb)->frag_list;
	while (done < len && frag_skb) {
		u32 child_len = frag_skb->len;
		u32 child_done = 0;
		u32 n;
		int rc;

		if (off >= child_len) {
			off -= child_len;
			frag_skb = frag_skb->next;
			continue;
		}

		n = min_t(u32, len - done, child_len - off);
		rc = dw_ac_match_skb_range(frag_skb, state_io, off, n,
					   count_out, &child_done, depth + 1);
		done += child_done;
		if (rc < 0)
			return rc;
		off = 0;
		frag_skb = frag_skb->next;
	}

	*done_out += done;
	return done == len ? 0 : -EOPNOTSUPP;
}

static __maybe_unused int dw_ac_match_skb_payload(struct sk_buff *skb, u32 off, u32 len,
				   bool *found_out)
{
	DFA_node *state;
	u32 done = 0;
	u32 count = 0;
	int rc;

	if (!skb || !found_out)
		return -EINVAL;
	if (!dw_ac_root || len < DW_AC_MIN_LEN) {
		*found_out = false;
		return 0;
	}

	state = dw_ac_root->root;
	rc = dw_ac_match_skb_range(skb, &state, off, len, &count, &done, 0);
	if (rc < 0)
		return rc;
	if (done < len)
		return -EOPNOTSUPP;

	*found_out = count > 0;
	return 0;
}

static void skb_direct_finish(struct skb_direct_work *sw)
{
	bool found = false;
	int rc;

	rc = dw_ac_match_skb_payload(sw->skb, sw->payload_off,
				     sw->payload_len, &found);
	if (rc < 0)
		found = false;

	dw_finish_payload_signature(sw->pkt_id, found);
	kfree_skb(sw->skb);
	kmem_cache_free(skb_direct_work_cache, sw);
}

static void skb_direct_workfn(struct work_struct *work)
{
	struct skb_direct_work *sw = container_of(work, struct skb_direct_work, work);

	dw_note_schedule_delay(sw->scheduled_ns);
	skb_direct_finish(sw);
}

static void skb_single_drain_workfn(struct work_struct *work)
{
	unsigned int processed = 0;

	for (;;) {
		struct skb_direct_work *sw = NULL;

		spin_lock_bh(&skb_single_lock);
		if (!list_empty(&skb_single_queue)) {
			sw = list_first_entry(&skb_single_queue,
					      struct skb_direct_work, list);
			list_del_init(&sw->list);
			if (skb_single_depth)
				skb_single_depth--;
		} else {
			skb_single_work_pending = false;
		}
		spin_unlock_bh(&skb_single_lock);

		if (!sw)
			return;
		dw_note_schedule_delay(sw->scheduled_ns);
		skb_direct_finish(sw);
		if (++processed >= DW_SKB_DRAIN_BUDGET) {
			queue_work(dw_wq, &skb_single_drain_work);
			return;
		}
		dw_cond_resched();
	}
}

static void skb_single_queue_work_item(struct skb_direct_work *sw)
{
	bool queue_now = false;

	sw->scheduled_ns = ktime_get_ns();
	INIT_LIST_HEAD(&sw->list);

	spin_lock_bh(&skb_single_lock);
	list_add_tail(&sw->list, &skb_single_queue);
	skb_single_depth++;
	if (!skb_single_work_pending) {
		skb_single_work_pending = true;
		queue_now = true;
	}
	spin_unlock_bh(&skb_single_lock);

	if (queue_now)
		queue_work(dw_wq, &skb_single_drain_work);
}

static unsigned int dw_deferred_worker_limit(void)
{
	unsigned int limit = READ_ONCE(deferred_worker_count);

	if (limit < 1)
		limit = 1;
	if (limit > DW_DEFERRED_WORKER_MAX)
		limit = DW_DEFERRED_WORKER_MAX;
	return limit;
}

static void skb_deferred_worker_drain_workfn(struct work_struct *work)
{
	unsigned int processed = 0;

	for (;;) {
		struct skb_direct_work *sw = NULL;

		spin_lock_bh(&skb_single_lock);
		if (!list_empty(&skb_single_queue)) {
			sw = list_first_entry(&skb_single_queue,
					      struct skb_direct_work, list);
			list_del_init(&sw->list);
			if (skb_single_depth)
				skb_single_depth--;
		} else {
			if (skb_deferred_worker_active)
				skb_deferred_worker_active--;
			spin_unlock_bh(&skb_single_lock);
			return;
		}
		spin_unlock_bh(&skb_single_lock);

		dw_note_schedule_delay(sw->scheduled_ns);
		skb_direct_finish(sw);
		if (++processed >= DW_SKB_DRAIN_BUDGET) {
			queue_work(dw_wq, work);
			return;
		}
		dw_cond_resched();
	}
}

static void skb_deferred_worker_queue_work_item(struct skb_direct_work *sw)
{
	unsigned int queue_from = 0;
	unsigned int queue_to = 0;
	unsigned int limit;
	unsigned int i;

	sw->scheduled_ns = ktime_get_ns();
	INIT_LIST_HEAD(&sw->list);

	spin_lock_bh(&skb_single_lock);
	list_add_tail(&sw->list, &skb_single_queue);
	skb_single_depth++;
	limit = dw_deferred_worker_limit();
	if (skb_deferred_worker_active < limit) {
		queue_from = skb_deferred_worker_active;
		queue_to = limit;
		skb_deferred_worker_active = limit;
	}
	spin_unlock_bh(&skb_single_lock);

	for (i = queue_from; i < queue_to; i++)
		queue_work(dw_wq, &skb_deferred_worker_work[i]);
}

static inline u32 dw_spec_slot_idx(const analysis_metadata *am, u32 chunk_idx,
				   u32 start_idx)
{
	return chunk_idx * am->result_stride + start_idx;
}

static inline atomic64_t *dw_spec_slot(const analysis_metadata *am, u32 chunk_idx,
				       u32 start_idx)
{
	return &am->result_state[dw_spec_slot_idx(am, chunk_idx, start_idx)];
}

static inline s64 dw_spec_pack(u32 chunk_inc, u32 hot_idx, u32 count)
{
	u64 hot = hot_idx;

	if (hot > DW_SPEC_HOT_MASK)
		hot = DW_SPEC_HOT_NONE;
	if (count > DW_SPEC_COUNT_MASK)
		count = DW_SPEC_COUNT_MASK;
	if (chunk_inc > DW_SPEC_CHUNK_INC_MASK)
		chunk_inc = DW_SPEC_CHUNK_INC_MASK;

	return (s64)((hot << (DW_SPEC_COUNT_BITS + DW_SPEC_CHUNK_INC_BITS)) |
		     ((u64)count << DW_SPEC_CHUNK_INC_BITS) |
		     chunk_inc);
}

static inline void dw_spec_unpack(s64 entry, u32 *chunk_inc, u32 *hot_idx,
				  u32 *count)
{
	u64 value = (u64)entry;

	*chunk_inc = value & DW_SPEC_CHUNK_INC_MASK;
	*count = (value >> DW_SPEC_CHUNK_INC_BITS) & DW_SPEC_COUNT_MASK;
	*hot_idx = (value >> (DW_SPEC_COUNT_BITS + DW_SPEC_CHUNK_INC_BITS)) &
		   DW_SPEC_HOT_MASK;
}

static DFA_node *dw_spec_start_state(u32 start_idx)
{
	if (!dw_ac_root)
		return NULL;
	if (start_idx == 0)
		return dw_ac_root->root;
	if (start_idx - 1 >= dw_ac_root->hot_state_size)
		return NULL;
	return dw_ac_root->hot_state[start_idx - 1];
}

static __maybe_unused u32 dw_spec_find_hot_state(DFA_node *state)
{
	u32 i;

	if (!dw_ac_root || !state)
		return DW_SPEC_HOT_NONE;
	if (state == dw_ac_root->root)
		return 0;
	for (i = 0; i < dw_ac_root->hot_state_size; i++) {
		if (dw_ac_root->hot_state[i] == state)
			return i + 1;
	}
	return DW_SPEC_HOT_NONE;
}

static u32 dw_spec_total_workers(const analysis_metadata *am)
{
	if (!am->num_chunks)
		return 0;
	return 1 + (am->num_chunks - 1) *
	       (am->num_start_states ? am->num_start_states - 1 : 0);
}

static void dw_spec_account_packet(analysis_metadata *am)
{
	u32 total = dw_spec_total_workers(am);
	u32 used = min_t(u32, READ_ONCE(am->spec_used_workers), total);
	u32 wasted = total - used;

	atomic64_add(total, &st_spec_workers_total);
	atomic64_add(used, &st_spec_workers_used);
	atomic64_add(wasted, &st_spec_workers_wasted);
}

static s64 dw_spec_scan(analysis_metadata *am, u32 chunk_idx, u32 start_idx)
{
	DFA_node *state = dw_spec_start_state(start_idx);
	u32 chunk_inc = 0;
	u32 hot_idx = DW_SPEC_HOT_NONE;
	u32 count = 0;

	while (state && chunk_idx + chunk_inc < am->num_chunks &&
	       chunk_inc < DW_SPEC_CHUNK_INC_MASK) {
		u32 off = (chunk_idx + chunk_inc) * am->chunk_size;
		u32 len = min_t(u32, am->chunk_size, am->payload_len - off);

		count += dw_ac_match_bytes(state, am->payload + off, len, &state);
		chunk_inc++;
		hot_idx = dw_spec_find_hot_state(state);
		if (hot_idx != DW_SPEC_HOT_NONE)
			break;
	}

	return dw_spec_pack(chunk_inc, hot_idx, count);
}

static void dw_spec_finalize(analysis_metadata *am)
{
	struct pkt_state *st;
	bool malicious;
	bool terminal = false;

	if (atomic_xchg(&am->done, 1))
		return;

	malicious = READ_ONCE(am->count_global) > 0;

	rcu_read_lock();
	st = state_lookup_rcu(am->pkt_id);
	if (st) {
		atomic_set(&st->analysis_done, 1);
		if (malicious)
			pkt_state_set_drop(st);
		else
			pkt_state_try_set_pass(st);

		WRITE_ONCE(st->last_seen_jiffies, jiffies);
		terminal = true;
	}
	rcu_read_unlock();

	pr_debug("spec pkt_id=%u chunks=%u states=%u count=%llu verdict=%s\n",
		am->pkt_id, am->num_chunks, am->num_start_states,
		READ_ONCE(am->count_global),
		malicious ? (dw_alert_only_mode() ? "ALERT_PASS" : "DROP") : "PASS");

	if (terminal)
		dw_try_deliver_ready();
}

static void dw_spec_drop_verified(analysis_metadata *am)
{
	struct pkt_state *st;

	if (atomic_xchg(&am->done, 1))
		return;

	rcu_read_lock();
	st = state_lookup_rcu(am->pkt_id);
	if (st) {
		atomic_set(&st->analysis_done, 1);
		pkt_state_set_drop(st);
		WRITE_ONCE(st->last_seen_jiffies, jiffies);
	}
	rcu_read_unlock();

	pr_debug("spec pkt_id=%u verified malicious count=%llu -> %s\n",
		am->pkt_id, READ_ONCE(am->count_global),
		dw_alert_only_mode() ? "ALERT_PASS" : "DROP");
	dw_try_deliver_ready();
}

static void dw_spec_continue_master(analysis_metadata *am, s64 verified_entry)
{
	u32 chunk_inc_done;
	u32 hot_idx;
	u32 count;
	u32 c;
	u64 total;

	dw_spec_unpack(verified_entry, &chunk_inc_done, &hot_idx, &count);
	WRITE_ONCE(am->spec_used_workers,
		   READ_ONCE(am->spec_used_workers) + 1);
	c = READ_ONCE(am->checkpoint);
	pr_debug("spec pkt_id=%u master running checkpoint=%u consumed=%u next_hot=%u count=%u\n",
		am->pkt_id, c, chunk_inc_done, hot_idx, count);
	total = READ_ONCE(am->count_global) + count;
	WRITE_ONCE(am->count_global, total);
	c += chunk_inc_done;
	WRITE_ONCE(am->checkpoint, c);
	if (count) {
		dw_spec_drop_verified(am);
		return;
	}

	for (;;) {
		atomic64_t *slot;
		s64 entry;
		u32 chunk_inc;
		u32 next_hot;
		u32 next_count;

		c = READ_ONCE(am->checkpoint);
		if (c >= am->num_chunks || hot_idx == DW_SPEC_HOT_NONE) {
			dw_spec_finalize(am);
			return;
		}

			slot = dw_spec_slot(am, c, hot_idx);
			entry = atomic64_cmpxchg(slot, DW_SPEC_ENTRY_EMPTY,
						 DW_SPEC_ENTRY_MASTER);
			if (entry == DW_SPEC_ENTRY_EMPTY) {
				/* CAS succeeded: this result is not ready yet; hand master role to that worker. */
				pr_debug("spec pkt_id=%u master handoff waiting chunk=%u start=%u\n",
					am->pkt_id, c, hot_idx);
				return;
			}

			/* CAS failed: a worker has already published the packed result; consume it. */
			if (entry == DW_SPEC_ENTRY_MASTER)
				continue;

			dw_spec_unpack(entry, &chunk_inc, &next_hot, &next_count);
			WRITE_ONCE(am->spec_used_workers,
				   READ_ONCE(am->spec_used_workers) + 1);
			pr_debug("spec pkt_id=%u master consumed ready chunk=%u start=%u consumed=%u next_hot=%u count=%u\n",
				am->pkt_id, c, hot_idx, chunk_inc, next_hot,
				next_count);
			total = READ_ONCE(am->count_global) + next_count;
			WRITE_ONCE(am->count_global, total);
		c += chunk_inc;
		WRITE_ONCE(am->checkpoint, c);
		if (next_count) {
			dw_spec_drop_verified(am);
			return;
		}
		hot_idx = next_hot;
	}
}

bool dw_analysis_done(u32 pkt_id)
{
	struct pkt_state *st;
	bool done = false;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st)
		done = atomic_read(&st->analysis_done) != 0;
	rcu_read_unlock();

	return done;
}
EXPORT_SYMBOL_GPL(dw_analysis_done);

int dw_get_verdict(u32 pkt_id)
{
	struct pkt_state *st;
	int v = DW_VERDICT_UNKNOWN;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st)
		v = atomic_read(&st->verdict);
	rcu_read_unlock();

	return v;
}
EXPORT_SYMBOL_GPL(dw_get_verdict);

void dw_note_payload_signature(u32 pkt_id, bool is_malicious)
{
	struct pkt_state *st;

	if (!pkt_id || !is_malicious)
		return;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st) {
		atomic_set(&st->analysis_done, 1);
		pkt_state_set_drop(st);
		WRITE_ONCE(st->last_seen_jiffies, jiffies);

		pr_debug("payload signature hit pkt_id=%u source=\"%s\" -> verdict=%s\n",
			pkt_id, DW_AC_PATTERN_LABEL,
			dw_alert_only_mode() ? "ALERT_PASS" : "DROP");
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(dw_note_payload_signature);

static void dw_finish_payload_signature(u32 pkt_id, bool is_malicious)
{
	struct pkt_state *st;
	bool terminal = false;

	if (!pkt_id)
		return;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st) {
		atomic_set(&st->analysis_done, 1);
		if (is_malicious)
			pkt_state_set_drop(st);
		else
			pkt_state_try_set_pass(st);
		WRITE_ONCE(st->last_seen_jiffies, jiffies);
		terminal = true;
	}
	rcu_read_unlock();

	if (terminal)
		dw_try_deliver_ready();
}

static void dw_analyze_payload_inline(u32 pkt_id, const u8 *payload,
				      u32 payload_len)
{
	DFA_node *last = NULL;
	bool found = false;

	if (dw_ac_root && payload && payload_len >= DW_AC_MIN_LEN)
		found = dw_ac_match_bytes(dw_ac_root->root, payload,
					  payload_len, &last) > 0;

	dw_finish_payload_signature(pkt_id, found);
}

static void payload_single_finish(struct payload_single_work *sw)
{
	dw_analyze_payload_inline(sw->pkt_id, sw->payload, sw->payload_len);
	if (sw->payload_owned)
		kfree(sw->payload);
	snap_put(sw->snap);
	if (sw->skb_ref)
		kfree_skb(sw->skb_ref);
	kmem_cache_free(payload_single_work_cache, sw);
}

static void payload_single_drain_workfn(struct work_struct *work)
{
	for (;;) {
		struct payload_single_work *sw = NULL;

		spin_lock_bh(&payload_single_lock);
		if (!list_empty(&payload_single_queue)) {
			sw = list_first_entry(&payload_single_queue,
					      struct payload_single_work, list);
			list_del_init(&sw->list);
			if (payload_single_depth)
				payload_single_depth--;
		} else {
			payload_single_work_pending = false;
		}
		spin_unlock_bh(&payload_single_lock);

		if (!sw)
			return;
		dw_note_schedule_delay(sw->scheduled_ns);
		payload_single_finish(sw);
	}
}

static void payload_single_queue_work_item(struct payload_single_work *sw)
{
	bool queue_now = false;

	sw->scheduled_ns = ktime_get_ns();
	INIT_LIST_HEAD(&sw->list);
	spin_lock_bh(&payload_single_lock);
	list_add_tail(&sw->list, &payload_single_queue);
	payload_single_depth++;
	if (!payload_single_work_pending) {
		payload_single_work_pending = true;
		queue_now = true;
	}
	spin_unlock_bh(&payload_single_lock);

	if (queue_now)
		queue_work(dw_wq, &payload_single_drain_work);
}

int dw_analyze_pkt_inline(u32 pkt_id)
{
	struct pkt_snap_ent *snap;
	const u8 *payload;
	u32 payload_len;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!pkt_id)
		return -EINVAL;

	snap = snap_get(pkt_id);
	if (!snap || !frame_udp_payload_view(snap->data, snap->cap_len,
					     &payload, &payload_len)) {
		snap_put(snap);
		atomic_inc(&st_dropped);
		return -ENOENT;
	}

	dw_analyze_payload_inline(pkt_id, payload, payload_len);
	snap_put(snap);
	return 0;
}
EXPORT_SYMBOL_GPL(dw_analyze_pkt_inline);

bool dw_nfqueue_is_stopping(void)
{
	return atomic_read(&nfq_stopping) != 0;
}
EXPORT_SYMBOL_GPL(dw_nfqueue_is_stopping);

void dw_begin_nfqueue_stop(void)
{
	atomic_set(&nfq_stopping, 1);
}
EXPORT_SYMBOL_GPL(dw_begin_nfqueue_stop);

bool dw_udp_inline_analysis_enabled(void)
{
	return inline_analysis;
}
EXPORT_SYMBOL_GPL(dw_udp_inline_analysis_enabled);

bool dw_udp_single_worker_enabled(void)
{
	return single_worker;
}
EXPORT_SYMBOL_GPL(dw_udp_single_worker_enabled);

static bool dw_module_is_stopping(void)
{
	return atomic_read(&dw_stopping) != 0;
}

/* -------- meta store: used by XDP (put) and NF (get+del) -------- */

static bool key_equal(const struct dw_pkt_key *a, const struct dw_pkt_key *b)
{
	return !memcmp(a, b, sizeof(*a));
}

static bool flow_key_equal(const struct dw_flow_key *a, const struct dw_flow_key *b)
{
	return !memcmp(a, b, sizeof(*a));
}

static bool skb_build_flow_key_ipv4_udp(struct sk_buff *skb, struct dw_flow_key *key)
{
	struct iphdr _iph, *iph;
	struct udphdr _uh, *uh;
	unsigned int l4_off;

	if (!skb || !key)
		return false;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return false;

	l4_off = iph->ihl * 4;
	uh = skb_header_pointer(skb, l4_off, sizeof(_uh), &_uh);
	if (!uh)
		return false;

	memset(key, 0, sizeof(*key));
	key->saddr = iph->saddr;
	key->daddr = iph->daddr;
	key->sport = uh->source;
	key->dport = uh->dest;
	key->proto = iph->protocol;

	return true;
}

static struct flow_ent *flow_lookup_rcu(const struct dw_flow_key *key, u32 h)
{
	struct flow_ent *fe;
	u32 bkt = flow_bucket_hash(h);

	for (fe = READ_ONCE(flow_ht[bkt]); fe; fe = READ_ONCE(fe->next)) {
		if (flow_key_equal(&fe->key, key))
			return fe;
	}
	return NULL;
}

static struct flow_ent *flow_get_or_create(const struct dw_flow_key *key, u32 h)
{
	struct flow_ent *fe;
	struct flow_ent *head;
	u32 bkt = flow_bucket_hash(h);

	rcu_read_lock();
	fe = flow_lookup_rcu(key, h);
	if (fe) {
		WRITE_ONCE(fe->last_seen_jiffies, jiffies);
		rcu_read_unlock();
		return fe;
	}
	rcu_read_unlock();

	fe = kzalloc(sizeof(*fe), GFP_ATOMIC);
	if (!fe)
		return NULL;

	memcpy(&fe->key, key, sizeof(*key));
	atomic_set(&fe->tail, 0);
	WRITE_ONCE(fe->head, 0);
	fe->last_seen_jiffies = jiffies;

	for (;;) {
		head = READ_ONCE(flow_ht[bkt]);
		WRITE_ONCE(fe->next, head);
		if (cmpxchg(&flow_ht[bkt], head, fe) == head)
			return fe;

		rcu_read_lock();
		head = flow_lookup_rcu(key, h);
		if (head) {
			WRITE_ONCE(head->last_seen_jiffies, jiffies);
			rcu_read_unlock();
			kfree(fe);
			return head;
		}
		rcu_read_unlock();
	}
}

/* kfunc: correlation put (XDP writes) */
static __bpf_kfunc int dw_meta_put(struct dw_pkt_key *key, u32 pkt_id)
{
	struct meta_ent *e;
	u32 h;
	u32 bkt;
	struct meta_ent *head;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!key || !pkt_id)
		return -EINVAL;

	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return -ENOMEM;

	memcpy(&e->key, key, sizeof(*key));
	e->pkt_id = pkt_id;
	e->ts_jiffies = jiffies;
	e->claimed_jiffies = 0;
	atomic_set(&e->claimed, 0);
	e->next = NULL;

	if (ntohs(e->key.sport) == 5005 || ntohs(e->key.dport) == 5005)
		pr_debug("meta put pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
			pkt_id,
			ntohl(e->key.saddr), ntohl(e->key.daddr),
			ntohs(e->key.sport), ntohs(e->key.dport),
			ntohs(e->key.ip_id), ntohs(e->key.udp_len),
			e->key.proto);

	h = jhash(&e->key, sizeof(e->key), 0);
	bkt = meta_bucket_hash(h);
	meta_gc_bucket(bkt, jiffies);

	for (;;) {
		head = READ_ONCE(meta_ht[bkt]);
		WRITE_ONCE(e->next, head);
		if (cmpxchg(&meta_ht[bkt], head, e) == head)
			return 0;
	}

}

static __bpf_kfunc int dw_pkt_snapshot_put(const u8 *data, u32 len, u32 pkt_id)
{
	struct pkt_snap_ent *e;
	struct pkt_snap_ent *head;
	u32 cap_len;
	u32 bkt;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!data || !len || !pkt_id)
		return -EINVAL;

	cap_len = min_t(u32, len, (u32)DW_XDP_SNAPSHOT_MAX);
	e = kmalloc(struct_size(e, data, cap_len), GFP_ATOMIC);
	if (!e)
		return -ENOMEM;

	e->pkt_id = pkt_id;
	e->frame_len = len;
	e->cap_len = cap_len;
	e->ts_jiffies = jiffies;
	refcount_set(&e->refs, 1);
	e->next = NULL;
	memcpy(e->data, data, cap_len);
	pr_debug("snapshot pkt_id=%u created refs=1 frame_len=%u cap_len=%u\n",
		pkt_id, len, cap_len);

	snap_drop(pkt_id);
	bkt = snap_bucket(pkt_id);
	for (;;) {
		head = READ_ONCE(snap_ht[bkt]);
		WRITE_ONCE(e->next, head);
		if (cmpxchg(&snap_ht[bkt], head, e) == head)
			break;
	}

	if (len > cap_len)
		pr_debug("snapshot pkt_id=%u truncated frame_len=%u cap_len=%u\n",
			pkt_id, len, cap_len);

	return (int)cap_len;
}

/* exported API: NF consumes */
bool dw_meta_get_and_del(struct dw_pkt_key *key, u32 *pkt_id_out)
{
	struct meta_ent *prev;
	struct meta_ent *e;
	struct meta_ent *next;
	u32 h;
	u32 bkt;
	unsigned long now;
	u32 pkt_id;

	if (!key)
		return false;

	h = jhash(key, sizeof(*key), 0);
	bkt = meta_bucket_hash(h);
	now = jiffies;

retry:
	rcu_read_lock();
	prev = NULL;
	for (e = READ_ONCE(meta_ht[bkt]); e; e = READ_ONCE(e->next)) {
		if (!key_equal(&e->key, key)) {
			prev = e;
			continue;
		}

		if (meta_claim_expired(e, now)) {
			prev = e;
			continue;
		}

		next = READ_ONCE(e->next);
		if (prev) {
			if (cmpxchg(&prev->next, e, next) != e) {
				rcu_read_unlock();
				goto retry;
			}
		} else {
			if (cmpxchg(&meta_ht[bkt], e, next) != e) {
				rcu_read_unlock();
				goto retry;
			}
		}

		pkt_id = READ_ONCE(e->pkt_id);
		WRITE_ONCE(e->next, NULL);
		rcu_read_unlock();

		if (pkt_id_out)
			*pkt_id_out = pkt_id;
		kfree_rcu(e, rcu);
		return true;
	}
	rcu_read_unlock();

	meta_gc_bucket(bkt, now);
	return false;
}
EXPORT_SYMBOL_GPL(dw_meta_get_and_del);



static int flow_try_reserve_slot(struct flow_ent *fe, u32 *pos_out)
{
	for (;;) {
		u32 head = READ_ONCE(fe->head);
		u32 tail = (u32)atomic_read(&fe->tail);

		if (tail - head >= DW_FLOW_RING_SIZE)
			return -ENOSPC;

		if (atomic_cmpxchg(&fe->tail, tail, tail + 1) == tail) {
			*pos_out = tail;
			return 0;
		}

		cpu_relax();
	}
}

static struct dw_buf_ent *flow_slot_at(struct flow_ent *fe, u32 pos)
{
	return &fe->ring[pos & DW_FLOW_RING_MASK];
}

void dw_udp_cleanup_packet(u32 pkt_id)
{
	snap_drop(pkt_id);
	state_drop(pkt_id);
}
EXPORT_SYMBOL_GPL(dw_udp_cleanup_packet);

bool dw_udp_try_fast_accept_done(struct sk_buff *skb, u32 pkt_id)
{
	struct dw_flow_key fkey;
	struct flow_ent *fe;
	u32 h;
	bool backlog = true;

	if (!skb || !pkt_id)
		return false;
	if (dw_get_verdict(pkt_id) == DW_VERDICT_DROP)
		return false;
	if (!dw_analysis_done(pkt_id))
		return false;
	if (!skb_build_flow_key_ipv4_udp(skb, &fkey))
		return false;

	h = jhash(&fkey, sizeof(fkey), 0);
	rcu_read_lock();
	fe = flow_lookup_rcu(&fkey, h);
	if (!fe)
		backlog = false;
	else
		backlog = READ_ONCE(fe->head) != (u32)atomic_read(&fe->tail);
	rcu_read_unlock();

	if (backlog)
		return false;

	dw_udp_cleanup_packet(pkt_id);
	return true;
}
EXPORT_SYMBOL_GPL(dw_udp_try_fast_accept_done);

static bool __dw_try_deliver_ready(void)
{
	struct flow_ent *fe;
	struct nf_queue_entry *qent;
	unsigned int reinjected = 0;
	unsigned int scanned_flows = 0;
	bool stopping;
	int bkt;

	for (bkt = 0; bkt < FLOW_BUCKETS; bkt++) {
		for (fe = READ_ONCE(flow_ht[bkt]); fe; fe = READ_ONCE(fe->next)) {
			u32 head = READ_ONCE(fe->head);

			for (;;) {
				struct dw_buf_ent *be;
				u32 pkt_id;
				u32 tail;
				int verdict;

				tail = (u32)atomic_read(&fe->tail);
				if (head == tail)
					break;

				be = flow_slot_at(fe, head);
				if (!smp_load_acquire(&be->ready) ||
				    READ_ONCE(be->pos) != head)
					break;

				pkt_id = be->pkt_id;
				stopping = atomic_read(&nfq_stopping);
				verdict = dw_get_verdict(pkt_id);

				if (stopping) {
					pr_debug("deliver flow-head pkt_id=%u teardown -> accept queued packet\n",
						pkt_id);
					snap_drop(pkt_id);
					state_drop(pkt_id);
					qent = be->qent;
					WRITE_ONCE(be->qent, NULL);
					smp_store_release(&be->ready, false);
					WRITE_ONCE(fe->head, ++head);
					nf_reinject(qent, NF_ACCEPT);
					atomic_dec(&st_pending);
					atomic_inc(&st_delivered);
					WRITE_ONCE(fe->last_seen_jiffies, jiffies);
					if (++reinjected >= DW_DELIVERY_REINJECT_BUDGET)
						return true;
					dw_cond_resched();
					continue;
				}

				if (verdict == DW_VERDICT_DROP) {
					pr_debug("deliver flow-head pkt_id=%u verdict=DROP -> drop queued packet\n",
						pkt_id);
					snap_drop(pkt_id);
					state_drop(pkt_id);
					qent = be->qent;
					WRITE_ONCE(be->qent, NULL);
					smp_store_release(&be->ready, false);
					WRITE_ONCE(fe->head, ++head);
					nf_reinject(qent, NF_DROP);
					atomic_dec(&st_pending);
					atomic_inc(&st_dropped);
					WRITE_ONCE(fe->last_seen_jiffies, jiffies);
					if (++reinjected >= DW_DELIVERY_REINJECT_BUDGET)
						return true;
					dw_cond_resched();
					continue;
				}

				if (!dw_analysis_done(pkt_id)) {
					pr_debug("deliver flow-head pkt_id=%u analysis pending -> block flow head\n",
						pkt_id);
					break;
				}

				pr_debug("deliver flow-head pkt_id=%u verdict=PASS -> reinject\n",
					pkt_id);
				snap_drop(pkt_id);
				state_drop(pkt_id);

				if (be->enqueue_ns) {
					u64 delta = ktime_get_ns() - be->enqueue_ns;

					atomic64_add(delta, &st_analysis_total_ns);
					if (delta > (u64)atomic64_read(&st_analysis_max_ns))
						atomic64_set(&st_analysis_max_ns, delta);
				}
				qent = be->qent;
				WRITE_ONCE(be->qent, NULL);
				smp_store_release(&be->ready, false);
				WRITE_ONCE(fe->head, ++head);
				nf_reinject(qent, NF_ACCEPT);
				atomic_inc(&st_delivered);
				atomic_dec(&st_pending);
				WRITE_ONCE(fe->last_seen_jiffies, jiffies);
				if (++reinjected >= DW_DELIVERY_REINJECT_BUDGET)
					return true;
				dw_cond_resched();
			}

			if ((++scanned_flows & 0x3f) == 0)
				dw_cond_resched();
		}
		if ((bkt & 0x3f) == 0)
			dw_cond_resched();
	}

	return false;
}

static void dw_try_deliver_ready(void)
{
	atomic_set(&delivery_kicked, 1);

	if (atomic_cmpxchg(&delivery_running, 0, 1) != 0)
		return;

	for (;;) {
		bool more;

		/*
		 * Only one drainer may walk flow_ht at a time. Even without
		 * per-flow locks, keeping a single consumer preserves the
		 * circular-buffer head invariant for each flow.
		 */
		atomic_set(&delivery_kicked, 0);
		more = __dw_try_deliver_ready();
		if (more)
			atomic_set(&delivery_kicked, 1);
		smp_mb__after_atomic();
		if (!atomic_read(&delivery_kicked))
			break;
		dw_cond_resched();
	}

	atomic_set(&delivery_running, 0);
	smp_mb__after_atomic();

	if (atomic_xchg(&delivery_kicked, 0) &&
	    atomic_cmpxchg(&delivery_running, 0, 1) == 0) {
		for (;;) {
			bool more;

			atomic_set(&delivery_kicked, 0);
			more = __dw_try_deliver_ready();
			if (more)
				atomic_set(&delivery_kicked, 1);
			smp_mb__after_atomic();
			if (!atomic_read(&delivery_kicked))
				break;
			dw_cond_resched();
		}
		atomic_set(&delivery_running, 0);
	}
}

static void analysis_job_complete(analysis_metadata *am, u32 chunk_idx,
				  u32 start_idx)
{
	atomic64_t *slot = dw_spec_slot(am, chunk_idx, start_idx);
	s64 entry;
	s64 prev;

	entry = dw_spec_scan(am, chunk_idx, start_idx);
	prev = atomic64_cmpxchg(slot, DW_SPEC_ENTRY_EMPTY, entry);
	if (prev == DW_SPEC_ENTRY_MASTER) {
		pr_debug("spec pkt_id=%u worker chunk=%u start=%u becomes master\n",
			am->pkt_id, chunk_idx, start_idx);
		dw_spec_continue_master(am, entry);
	}

	if (atomic_dec_and_test(&am->pending_workers)) {
		dw_spec_finalize(am);
		dw_spec_account_packet(am);
		kfree(am->result_state_alloc);
		if (am->payload_owned)
			kfree(am->payload);
		snap_put(am->snap);
		if (am->skb_ref)
			kfree_skb(am->skb_ref);
		kfree(am);
	}
}

static void analysis_work_complete(struct analysis_work *aw)
{
	analysis_job_complete(aw->am, aw->chunk_idx, aw->start_idx);
	kfree(aw);
}

static void analysis_workfn(struct work_struct *work)
{
	struct analysis_work *aw = container_of(work, struct analysis_work, work);

	dw_note_schedule_delay(aw->scheduled_ns);
	analysis_work_complete(aw);
}

static int dw_schedule_payload(u32 pkt_id, const u8 *payload, u32 payload_len,
			       struct pkt_snap_ent *snap,
			       struct sk_buff *skb_ref, bool payload_owned)
{
	struct pkt_state *st;

	if (dw_module_is_stopping()) {
		if (payload_owned)
			kfree(payload);
		snap_put(snap);
		if (skb_ref)
			kfree_skb(skb_ref);
		return -ESHUTDOWN;
	}

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st) {
		WRITE_ONCE(st->last_seen_jiffies, jiffies);
	}
	rcu_read_unlock();

	if (!st) {
		pr_err("dw_register_and_schedule entry not found pkt_id=%u\n",
		       pkt_id);
		if (payload_owned)
			kfree(payload);
		snap_put(snap);
		if (skb_ref)
			kfree_skb(skb_ref);
		atomic_inc(&st_dropped);
		return -ENOENT;
	}

	if (inline_analysis) {
		dw_analyze_payload_inline(pkt_id, payload, payload_len);
		if (payload_owned)
			kfree(payload);
		snap_put(snap);
		if (skb_ref)
			kfree_skb(skb_ref);
		return 0;
	}

	if (single_worker) {
		struct payload_single_work *sw;

		sw = kmem_cache_zalloc(payload_single_work_cache, GFP_ATOMIC);
		if (!sw) {
			if (payload_owned)
				kfree(payload);
			snap_put(snap);
			if (skb_ref)
				kfree_skb(skb_ref);
			atomic_inc(&st_dropped);
			return -ENOMEM;
		}

		sw->payload = payload;
		sw->snap = snap;
		sw->skb_ref = skb_ref;
		sw->pkt_id = pkt_id;
		sw->payload_len = payload_len;
		sw->payload_owned = payload_owned;
		payload_single_queue_work_item(sw);
		return 0;
	}

	{
		u32 total_workers;
		u32 slot_count;
		u32 result_bytes;
		u32 chunk_idx;
		u32 start_idx;
		analysis_metadata *am;

		if (payload_len < DW_AC_MIN_LEN) {
			snap_put(snap);
			if (payload_owned)
				kfree(payload);
			if (skb_ref)
				kfree_skb(skb_ref);
			atomic_set(&st->analysis_done, 1);
			pkt_state_try_set_pass(st);
			dw_try_deliver_ready();
			return 0;
		}

		am = kzalloc(sizeof(*am), GFP_ATOMIC);
		if (!am) {
			snap_put(snap);
			if (payload_owned)
				kfree(payload);
			if (skb_ref)
				kfree_skb(skb_ref);
			atomic_inc(&st_dropped);
			return -ENOMEM;
		}

		am->payload = payload;
		am->snap = snap;
		am->skb_ref = skb_ref;
		am->payload_len = payload_len;
		am->payload_owned = payload_owned;
		am->num_chunks = dw_deferred_worker_limit();
		if (am->num_chunks > payload_len)
			am->num_chunks = payload_len;
		if (am->num_chunks < 1)
			am->num_chunks = 1;
		am->chunk_size = DIV_ROUND_UP(payload_len, am->num_chunks);
		am->num_start_states = (dw_ac_root ? dw_ac_root->hot_state_size : 0) + 1;
		am->result_stride = roundup(am->num_start_states,
					     DW_SPEC_SLOTS_PER_CACHELINE);
		am->pkt_id = pkt_id;
		WRITE_ONCE(am->checkpoint, 0);
		WRITE_ONCE(am->spec_used_workers, 0);
		WRITE_ONCE(am->count_global, 0);
		atomic_set(&am->done, 0);

		slot_count = am->num_chunks * am->result_stride;
		if (check_mul_overflow(slot_count, (u32)sizeof(*am->result_state),
				       &result_bytes) ||
		    check_add_overflow(result_bytes, (u32)SMP_CACHE_BYTES - 1,
				       &result_bytes)) {
			if (am->payload_owned)
				kfree(am->payload);
			if (am->skb_ref)
				kfree_skb(am->skb_ref);
			snap_put(am->snap);
			kfree(am);
			atomic_inc(&st_dropped);
			return -EOVERFLOW;
		}

		am->result_state_alloc = kzalloc(result_bytes, GFP_ATOMIC);
		if (!am->result_state_alloc) {
			if (am->payload_owned)
				kfree(am->payload);
			if (am->skb_ref)
				kfree_skb(am->skb_ref);
			snap_put(am->snap);
			kfree(am);
			atomic_inc(&st_dropped);
			return -ENOMEM;
		}
		am->result_state = PTR_ALIGN(am->result_state_alloc,
					     SMP_CACHE_BYTES);
		atomic64_set(dw_spec_slot(am, 0, 0), DW_SPEC_ENTRY_MASTER);

			total_workers = dw_spec_total_workers(am);
			if (total_workers > DW_SPEC_MAX_WORKERS_PER_PKT) {
				pr_debug_ratelimited("spec pkt_id=%u too many workers=%u payload_len=%u start_states=%u -> fail open\n",
						    pkt_id, total_workers,
						    payload_len,
						    am->num_start_states);
				kfree(am->result_state_alloc);
				if (am->payload_owned)
					kfree(am->payload);
				if (am->skb_ref)
					kfree_skb(am->skb_ref);
				snap_put(am->snap);
				kfree(am);
				atomic_set(&st->analysis_done, 1);
				pkt_state_try_set_pass(st);
				dw_try_deliver_ready();
				return 0;
			}
			atomic_set(&am->pending_workers, total_workers);
			pr_debug("spec pkt_id=%u schedule payload_len=%u chunk_size=%u chunks=%u start_states=%u stride=%u workers=%u\n",
				pkt_id, payload_len, am->chunk_size, am->num_chunks,
				am->num_start_states, am->result_stride,
				total_workers);

			for (chunk_idx = 0; chunk_idx < am->num_chunks; chunk_idx++) {
			for (start_idx = 0; start_idx < am->num_start_states; start_idx++) {
				struct analysis_work *aw;

				if ((chunk_idx == 0 && start_idx > 0) ||
				    (chunk_idx > 0 && start_idx == 0))
					continue;

				aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
				if (!aw) {
					atomic_inc(&st_dropped);
					analysis_job_complete(am, chunk_idx, start_idx);
					continue;
				}
				aw->chunk_idx = chunk_idx;
				aw->start_idx = start_idx;
				aw->am = am;
				aw->scheduled_ns = ktime_get_ns();
				INIT_WORK(&aw->work, analysis_workfn);
				queue_work(dw_wq, &aw->work);
			}
		}
	}

	return 0;
}

/* -------- kfunc called by XDP: schedule analyses -------- */

static __bpf_kfunc int dw_register_and_schedule(u32 pkt_id)
{
	struct pkt_snap_ent *snap;
	const u8 *payload;
	u32 payload_len;

	snap = snap_get(pkt_id);
	if (!snap || !frame_udp_payload_view(snap->data, snap->cap_len,
					     &payload, &payload_len)) {
		snap_put(snap);
		atomic_inc(&st_dropped);
		return -ENOENT;
	}

	return dw_schedule_payload(pkt_id, payload, payload_len, snap, NULL, false);
}

int dw_schedule_skb_deferred(struct sk_buff *skb, u32 *pkt_id_out)
{
	u8 *payload;
	u32 payload_len;
	u32 pkt_id;
	int rc;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!skb)
		return -EINVAL;

	rc = skb_udp_payload_copy(skb, &payload, &payload_len);
	if (rc < 0)
		return rc;

	pkt_id = dw_next_nf_pkt_id();
	if (!pkt_id) {
		kfree(payload);
		return -EOVERFLOW;
	}

	rc = dw_state_init(pkt_id);
	if (rc < 0) {
		kfree(payload);
		return rc;
	}

	rc = dw_schedule_payload(pkt_id, payload, payload_len, NULL, NULL, true);
	if (rc < 0) {
		state_drop(pkt_id);
		return rc;
	}

	if (pkt_id_out)
		*pkt_id_out = pkt_id;
	return 0;
}
EXPORT_SYMBOL_GPL(dw_schedule_skb_deferred);

static int __dw_schedule_skb_ref_deferred(struct sk_buff *skb,
					  struct dw_pkt_key *key,
					  u32 *pkt_id_out, bool publish_meta)
{
	struct skb_direct_work *sw;
	u32 payload_off;
	u32 payload_len;
	u32 pkt_id;
	int rc;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!skb || (publish_meta && !key))
		return -EINVAL;

	rc = skb_udp_payload_desc(skb, &payload_off, &payload_len);
	if (rc < 0)
		return rc;
	if (payload_len > DW_SKB_REF_PAYLOAD_MAX)
		return -E2BIG;

	pkt_id = dw_next_nf_pkt_id();
	if (!pkt_id)
		return -EOVERFLOW;

	rc = dw_state_init(pkt_id);
	if (rc < 0)
		return rc;

	if (publish_meta) {
		rc = dw_meta_put(key, pkt_id);
		if (rc < 0) {
			state_drop(pkt_id);
			return rc;
		}
	}

	if (inline_analysis) {
		bool found = false;
		int match_rc;

		match_rc = dw_ac_match_skb_payload(skb, payload_off, payload_len,
						   &found);
		if (match_rc < 0)
			found = false;
		dw_finish_payload_signature(pkt_id, found);
		if (pkt_id_out)
			*pkt_id_out = pkt_id;
		return 0;
	}

	if (!single_worker && READ_ONCE(deferred_worker_count) > 1) {
		u8 *payload;

		rc = skb_udp_payload_copy(skb, &payload, &payload_len);
		if (rc < 0) {
			dw_finish_payload_signature(pkt_id, false);
			state_drop(pkt_id);
			return rc;
		}

		rc = dw_schedule_payload(pkt_id, payload, payload_len, NULL, NULL, true);
		if (rc < 0) {
			state_drop(pkt_id);
			return rc;
		}

		if (pkt_id_out)
			*pkt_id_out = pkt_id;
		return 0;
	}

	sw = kmem_cache_zalloc(skb_direct_work_cache, GFP_ATOMIC);
	if (!sw) {
		dw_finish_payload_signature(pkt_id, false);
		state_drop(pkt_id);
		return -ENOMEM;
	}

	skb_get(skb);
	sw->skb = skb;
	sw->pkt_id = pkt_id;
	sw->payload_off = payload_off;
	sw->payload_len = payload_len;
	if (single_worker || READ_ONCE(deferred_worker_count) > 1) {
		if (READ_ONCE(deferred_worker_count) > 1)
			skb_deferred_worker_queue_work_item(sw);
		else
			skb_single_queue_work_item(sw);
	} else {
		sw->scheduled_ns = ktime_get_ns();
		INIT_WORK(&sw->work, skb_direct_workfn);
		queue_work(dw_wq, &sw->work);
	}

	if (pkt_id_out)
		*pkt_id_out = pkt_id;
	return 0;
}

int dw_schedule_skb_ref_deferred(struct sk_buff *skb, struct dw_pkt_key *key,
				 u32 *pkt_id_out)
{
	return __dw_schedule_skb_ref_deferred(skb, key, pkt_id_out, true);
}
EXPORT_SYMBOL_GPL(dw_schedule_skb_ref_deferred);

int dw_schedule_skb_ref_deferred_nometa(struct sk_buff *skb, u32 *pkt_id_out)
{
	return __dw_schedule_skb_ref_deferred(skb, NULL, pkt_id_out, false);
}
EXPORT_SYMBOL_GPL(dw_schedule_skb_ref_deferred_nometa);

/* export kfunc set for XDP */
BTF_SET8_START(dw_kfunc_set)
BTF_ID_FLAGS(func, dw_state_init,            KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, dw_register_and_schedule, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, dw_meta_put,              KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, dw_pkt_snapshot_put,      0)
BTF_SET8_END(dw_kfunc_set)

static const struct btf_kfunc_id_set dw_kfunc_ids = {
	.owner = THIS_MODULE,
	.set   = &dw_kfunc_set,
};

/* -------- API used by Netfilter -------- */

int dw_buffer_nfqueue_entry(struct nf_queue_entry *entry, u32 pkt_id)
{
	struct dw_flow_key fkey;
	u32 h;
	u32 pos;
	struct flow_ent *fe;
	struct dw_buf_ent *be;
	int verdict;

	if (!entry || !entry->skb)
		return -EINVAL;

	if (atomic_read(&nfq_stopping)) {
		pr_debug("nfqueue stopping pkt_id=%u -> accept queued packet\n",
			pkt_id);
		snap_drop(pkt_id);
		state_drop(pkt_id);
		nf_reinject(entry, NF_ACCEPT);
		atomic_inc(&st_delivered);
		return DW_NFQ_DROPPED;
	}

	verdict = dw_get_verdict(pkt_id);
	if (verdict == DW_VERDICT_DROP) {
		pr_debug("nfqueue immediate drop pkt_id=%u verdict=DROP\n",
			pkt_id);
		snap_drop(pkt_id);
		state_drop(pkt_id);
		nf_reinject(entry, NF_DROP);
		atomic_inc(&st_dropped);
		return DW_NFQ_DROPPED;
	}

	if (!skb_build_flow_key_ipv4_udp(entry->skb, &fkey)) {
		atomic_inc(&st_dropped);
		return -EINVAL;
	}

	h = jhash(&fkey, sizeof(fkey), 0);
	fe = flow_get_or_create(&fkey, h);
	if (!fe) {
		atomic_inc(&st_dropped);
		return -ENOMEM;
	}

	if (flow_try_reserve_slot(fe, &pos) < 0) {
		pr_debug("flow ring full pkt_id=%u -> drop queued packet\n",
			pkt_id);
		snap_drop(pkt_id);
		state_drop(pkt_id);
		nf_reinject(entry, NF_DROP);
		atomic_inc(&st_dropped);
		return DW_NFQ_DROPPED;
	}

	be = flow_slot_at(fe, pos);
	be->qent = entry;
	be->pkt_id = pkt_id;
	be->pos = pos;
	be->enqueue_ns = ktime_get_ns();
	smp_store_release(&be->ready, true);
	WRITE_ONCE(fe->last_seen_jiffies, jiffies);

	atomic_inc(&st_pending);
	dw_try_deliver_ready();
	return DW_NFQ_BUFFERED;
}
EXPORT_SYMBOL_GPL(dw_buffer_nfqueue_entry);

void dw_quiesce_nfqueue(void)
{
	struct flow_ent *fe;
	int bkt;

	if (atomic_cmpxchg(&nfq_quiescing, 0, 1) != 0) {
		pr_debug("nfqueue quiesce already in progress\n");
		return;
	}

	atomic_set(&nfq_stopping, 1);
	/*
	 * Wait for any in-flight netfilter callbacks to finish before we
	 * claim delivery ownership and tear down queued entries.
	 */
	synchronize_net();
	flush_workqueue(dw_wq);

	while (atomic_cmpxchg(&delivery_running, 0, 1) != 0)
		usleep_range(1000, 2000);

	for (bkt = 0; bkt < FLOW_BUCKETS; bkt++) {
		for (fe = READ_ONCE(flow_ht[bkt]); fe; fe = READ_ONCE(fe->next)) {
			u32 head = READ_ONCE(fe->head);
			u32 tail = (u32)atomic_read(&fe->tail);

			while (head != tail) {
				struct dw_buf_ent *be = flow_slot_at(fe, head);

				if (smp_load_acquire(&be->ready) &&
				    READ_ONCE(be->pos) == head &&
				    READ_ONCE(be->qent)) {
					snap_drop(be->pkt_id);
					/*
					 * Complete each queued packet through NFQUEUE
					 * before unregistering the queue handler,
					 * otherwise the queue core may still consider
					 * the entry in flight and stall module
					 * teardown.
					 */
					nf_reinject(be->qent, NF_ACCEPT);
					atomic_dec(&st_pending);
					atomic_inc(&st_delivered);
					WRITE_ONCE(be->qent, NULL);
					smp_store_release(&be->ready, false);
				}
				head++;
			}

			WRITE_ONCE(fe->head, head);
		}
	}

	atomic_set(&delivery_kicked, 0);
	atomic_set(&delivery_running, 0);
	atomic_set(&nfq_quiescing, 0);
}
EXPORT_SYMBOL_GPL(dw_quiesce_nfqueue);


/******  this part is only for getting packets statistics ******/

/* -------- sysfs getters for atomic counters -------- */

static int get_st_delivered(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%d\n", atomic_read(&st_delivered));
}

static int get_st_dropped(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%d\n", atomic_read(&st_dropped));
}

static int get_st_pending(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%d\n", atomic_read(&st_pending));
}

static const struct kernel_param_ops st_delivered_ops = { .get = get_st_delivered };
static const struct kernel_param_ops st_dropped_ops   = { .get = get_st_dropped };
static const struct kernel_param_ops st_pending_ops   = { .get = get_st_pending };

module_param_cb(st_delivered, &st_delivered_ops, NULL, 0440);
MODULE_PARM_DESC(st_delivered, "Packets delivered (verdict PASS, reinjected to socket)");
module_param_cb(st_dropped,   &st_dropped_ops,   NULL, 0440);
MODULE_PARM_DESC(st_dropped,   "Packets dropped (verdict DROP or ring overflow)");
module_param_cb(st_pending,   &st_pending_ops,   NULL, 0440);
MODULE_PARM_DESC(st_pending,   "Packets currently in the deferred analysis pipeline");

static int get_st_analysis_total_ns(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n", (long long)atomic64_read(&st_analysis_total_ns));
}
static int get_st_analysis_max_ns(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n", (long long)atomic64_read(&st_analysis_max_ns));
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
static int get_st_spec_workers_total(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n", (long long)atomic64_read(&st_spec_workers_total));
}
static int get_st_spec_workers_used(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n", (long long)atomic64_read(&st_spec_workers_used));
}
static int get_st_spec_workers_wasted(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%lld\n", (long long)atomic64_read(&st_spec_workers_wasted));
}
static int get_st_spec_wrong_permille(char *buf, const struct kernel_param *kp)
{
	u64 total = (u64)atomic64_read(&st_spec_workers_total);
	u64 wasted = (u64)atomic64_read(&st_spec_workers_wasted);
	u64 permille = total ? div64_u64(wasted * 1000ULL, total) : 0;

	return sprintf(buf, "%llu\n", permille);
}
static const struct kernel_param_ops st_analysis_total_ns_ops = { .get = get_st_analysis_total_ns };
static const struct kernel_param_ops st_analysis_max_ns_ops   = { .get = get_st_analysis_max_ns };
static const struct kernel_param_ops st_schedule_delay_total_ns_ops = { .get = get_st_schedule_delay_total_ns };
static const struct kernel_param_ops st_schedule_delay_max_ns_ops = { .get = get_st_schedule_delay_max_ns };
static const struct kernel_param_ops st_schedule_delay_count_ops = { .get = get_st_schedule_delay_count };
static const struct kernel_param_ops st_spec_workers_total_ops = { .get = get_st_spec_workers_total };
static const struct kernel_param_ops st_spec_workers_used_ops = { .get = get_st_spec_workers_used };
static const struct kernel_param_ops st_spec_workers_wasted_ops = { .get = get_st_spec_workers_wasted };
static const struct kernel_param_ops st_spec_wrong_permille_ops = { .get = get_st_spec_wrong_permille };
module_param_cb(st_analysis_total_ns, &st_analysis_total_ns_ops, NULL, 0440);
MODULE_PARM_DESC(st_analysis_total_ns, "Total ns spent in analysis queue+match (multi-worker path)");
module_param_cb(st_analysis_max_ns,   &st_analysis_max_ns_ops,   NULL, 0440);
MODULE_PARM_DESC(st_analysis_max_ns,   "Max single-packet analysis latency ns (multi-worker path)");
module_param_cb(st_schedule_delay_total_ns, &st_schedule_delay_total_ns_ops, NULL, 0440);
MODULE_PARM_DESC(st_schedule_delay_total_ns,
		 "Total ns between deferred work scheduling and execution start");
module_param_cb(st_schedule_delay_max_ns, &st_schedule_delay_max_ns_ops, NULL, 0440);
MODULE_PARM_DESC(st_schedule_delay_max_ns,
		 "Max ns between deferred work scheduling and execution start");
module_param_cb(st_schedule_delay_count, &st_schedule_delay_count_ops, NULL, 0440);
MODULE_PARM_DESC(st_schedule_delay_count,
		 "Deferred work items measured for schedule-to-execute delay");
module_param_cb(st_spec_workers_total, &st_spec_workers_total_ops, NULL, 0440);
MODULE_PARM_DESC(st_spec_workers_total, "Speculative AC worker results scheduled across completed packets");
module_param_cb(st_spec_workers_used, &st_spec_workers_used_ops, NULL, 0440);
MODULE_PARM_DESC(st_spec_workers_used, "Speculative AC worker results consumed by the master path");
module_param_cb(st_spec_workers_wasted, &st_spec_workers_wasted_ops, NULL, 0440);
MODULE_PARM_DESC(st_spec_workers_wasted, "Speculative AC worker results not consumed by the master path");
module_param_cb(st_spec_wrong_permille, &st_spec_wrong_permille_ops, NULL, 0440);
MODULE_PARM_DESC(st_spec_wrong_permille, "Speculative AC miss rate in per-mille: wasted * 1000 / total");

/* -------- module init/exit -------- */



static int hot_state_array[20];
static int hot_state_size = 0;

module_param_array(hot_state_array, int, &hot_state_size, 0660);
module_param(inline_analysis, bool, 0660);
MODULE_PARM_DESC(inline_analysis,
		 "Run UDP payload analysis synchronously in the current networking context");
module_param(single_worker, bool, 0660);
MODULE_PARM_DESC(single_worker,
		 "Run UDP deferred payload analysis through a single queue-draining worker");
module_param(deferred_worker_count, uint, 0660);
MODULE_PARM_DESC(deferred_worker_count,
		 "Split UDP payload analysis into N speculative chunks; chunk 0 starts at root, later chunks start from configured hot states");
module_param(nids_action, charp, 0660);
MODULE_PARM_DESC(nids_action,
		 "NIDS action for malicious UDP payloads: alert accepts packets, enforce drops packets");


static int __init deferred_init(void)
{
	int ret;

	memset(flow_ht, 0, sizeof(flow_ht));
	atomic_set(&nfq_stopping, 0);
	atomic_set(&nfq_quiescing, 0);
	atomic_set(&delivery_running, 0);
	atomic_set(&delivery_kicked, 0);
	atomic_set(&dw_stopping, 0);
	atomic64_set(&st_schedule_delay_total_ns, 0);
	atomic64_set(&st_schedule_delay_max_ns, 0);
	atomic64_set(&st_schedule_delay_count, 0);
	atomic64_set(&st_spec_workers_total, 0);
	atomic64_set(&st_spec_workers_used, 0);
	atomic64_set(&st_spec_workers_wasted, 0);
	INIT_WORK(&skb_single_drain_work, skb_single_drain_workfn);
	INIT_LIST_HEAD(&skb_single_queue);
	skb_single_work_pending = false;
	skb_deferred_worker_active = 0;
	skb_single_depth = 0;
	for (ret = 0; ret < DW_DEFERRED_WORKER_MAX; ret++)
		INIT_WORK(&skb_deferred_worker_work[ret],
			  skb_deferred_worker_drain_workfn);
	INIT_WORK(&payload_single_drain_work, payload_single_drain_workfn);
	INIT_LIST_HEAD(&payload_single_queue);
	payload_single_work_pending = false;
	payload_single_depth = 0;

	dw_wq = alloc_workqueue("dw_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!dw_wq)
		return -ENOMEM;

	skb_direct_work_cache = kmem_cache_create("dw_skb_direct_work",
							 sizeof(struct skb_direct_work), 0,
							 SLAB_HWCACHE_ALIGN, NULL);
	if (!skb_direct_work_cache) {
		destroy_workqueue(dw_wq);
		dw_wq = NULL;
		return -ENOMEM;
	}

	payload_single_work_cache = kmem_cache_create("dw_payload_single_work",
							 sizeof(struct payload_single_work), 0,
							 SLAB_HWCACHE_ALIGN, NULL);
	if (!payload_single_work_cache) {
		kmem_cache_destroy(skb_direct_work_cache);
		skb_direct_work_cache = NULL;
		destroy_workqueue(dw_wq);
		dw_wq = NULL;
		return -ENOMEM;
	}

	state_id = 0;
	dw_ac_root = DFA_build((const void **)dw_ac_patterns, DW_AC_PATTERN_COUNT,hot_state_array,hot_state_size);
	if (!dw_ac_root) {
		if (payload_single_work_cache) {
			kmem_cache_destroy(payload_single_work_cache);
			payload_single_work_cache = NULL;
		}
		if (skb_direct_work_cache) {
			kmem_cache_destroy(skb_direct_work_cache);
			skb_direct_work_cache = NULL;
		}
		destroy_workqueue(dw_wq);
		dw_wq = NULL;
		return -ENOMEM;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &dw_kfunc_ids);
	if (ret) {
		pr_err("register_btf_kfunc_id_set failed: %d\n", ret);
		DFA_free(dw_ac_root);
		dw_ac_root = NULL;
		if (payload_single_work_cache) {
			kmem_cache_destroy(payload_single_work_cache);
			payload_single_work_cache = NULL;
		}
		if (skb_direct_work_cache) {
			kmem_cache_destroy(skb_direct_work_cache);
			skb_direct_work_cache = NULL;
		}
		destroy_workqueue(dw_wq);
		dw_wq = NULL;
		return ret;
	}

	pr_debug("loaded\n");
	return 0;
}

static void __exit deferred_exit(void)
{
	struct pkt_state *st;
	struct meta_ent *me;
	struct flow_ent *fe;
	struct pkt_snap_ent *se;
	int bkt;

	/*
	 * Expected teardown is: detach XDP/eBPF first, then unload netfilter,
	 * and only after that unload deferred_analysis. Mark the module as
	 * stopping and wait for the last in-flight XDP/kfunc users before we
	 * tear down NFQUEUE state, the worker pool and the backing hash tables.
	 */
	atomic_set(&dw_stopping, 1);
	atomic_set(&nfq_stopping, 1);
	synchronize_net();
	synchronize_rcu();
	dw_quiesce_nfqueue();
	if (dw_wq) {
		destroy_workqueue(dw_wq);
		dw_wq = NULL;
	}
	if (payload_single_work_cache) {
		kmem_cache_destroy(payload_single_work_cache);
		payload_single_work_cache = NULL;
	}
	if (skb_direct_work_cache) {
		kmem_cache_destroy(skb_direct_work_cache);
		skb_direct_work_cache = NULL;
	}

	if (dw_ac_root) {
		DFA_free(dw_ac_root);
		dw_ac_root = NULL;
	}

	/* cleanup state_ht */
	for (bkt = 0; bkt < STATE_BUCKETS; bkt++) {
		st = xchg(&state_ht[bkt], NULL);
		while (st) {
			struct pkt_state *next = st->next;
			WRITE_ONCE(st->next, NULL);
			kfree_rcu(st, rcu);
			st = next;
		}
	}

	/* cleanup meta_ht */
	for (bkt = 0; bkt < META_BUCKETS; bkt++) {
		me = xchg(&meta_ht[bkt], NULL);
		while (me) {
			struct meta_ent *next = me->next;
			WRITE_ONCE(me->next, NULL);
			kfree_rcu(me, rcu);
			me = next;
		}
	}

	/* cleanup flow_ht (per-flow buffered items) */
	for (bkt = 0; bkt < FLOW_BUCKETS; bkt++) {
		fe = xchg(&flow_ht[bkt], NULL);
		while (fe) {
			struct flow_ent *next = READ_ONCE(fe->next);
			u32 head = READ_ONCE(fe->head);
			u32 tail = (u32)atomic_read(&fe->tail);

			while (head != tail) {
				struct dw_buf_ent *be = flow_slot_at(fe, head);

				if (smp_load_acquire(&be->ready) && READ_ONCE(be->qent))
					nf_queue_entry_free(be->qent);
				head++;
			}

			kfree(fe);
			fe = next;
		}
	}

	/* cleanup snap_ht (XDP frame snapshots) */
	for (bkt = 0; bkt < SNAP_BUCKETS; bkt++) {
		se = xchg(&snap_ht[bkt], NULL);
		while (se) {
			struct pkt_snap_ent *next = se->next;
			WRITE_ONCE(se->next, NULL);
			snap_put(se);
			se = next;
		}
	}

	pr_debug("unloaded\n");
}

module_init(deferred_init);
module_exit(deferred_exit);
