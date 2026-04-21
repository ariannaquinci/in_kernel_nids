#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <linux/unistd.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

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
	atomic_t req_mask;
	atomic_t done_mask;
	atomic_t hit_mask;  /* bitmask di analisi con match malevolo */
	atomic_t verdict; /* 0 unknown, 1 pass, 2 drop */
	unsigned long last_seen_jiffies;
	struct pkt_state *next;
	struct rcu_head rcu;
};

#define STATE_BITS 12
#define STATE_BUCKETS (1U << STATE_BITS)
static struct pkt_state *state_ht[STATE_BUCKETS];

/* -------- correlation table: fingerprint -> (pkt_id, req_mask) -------- */

struct meta_ent {
	struct dw_pkt_key key;
	u32 pkt_id;
	u32 req_mask;
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
	u32 req_mask;
	u32 pos;
	bool ready;
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

/* -------- stats/debug -------- */

static atomic_t st_pending   = ATOMIC_INIT(0);
static atomic_t st_delivered = ATOMIC_INIT(0);
static atomic_t st_dropped   = ATOMIC_INIT(0);
static atomic_t rr_cpu       = ATOMIC_INIT(0);
static atomic_t delivery_running = ATOMIC_INIT(0);
static atomic_t delivery_kicked  = ATOMIC_INIT(0);
static atomic_t nfq_stopping     = ATOMIC_INIT(0);
static atomic_t nfq_quiescing    = ATOMIC_INIT(0);
static atomic_t dw_stopping      = ATOMIC_INIT(0);

#define DW_DUMMY_NEEDLE "malicious"
#define DW_DUMMY_NEEDLE_LEN (sizeof(DW_DUMMY_NEEDLE) - 1)

static DFA_node *dw_ac_root;

static bool dw_bytes_contains(const u8 *buf, size_t len,
			      const u8 *needle, size_t needle_len)
{
	size_t i;

	if (!buf || !needle || !needle_len || len < needle_len)
		return false;

	for (i = 0; i <= len - needle_len; i++) {
		if (!memcmp(buf + i, needle, needle_len))
			return true;
	}

	return false;
}

static bool dw_ac_match_bytes(DFA_node *root, const u8 *buf, size_t len)
{
	unsigned char *tmp;
	int *match_indices = NULL;
	int matches;

	if (!root || !buf || !len)
		return false;

	tmp = kmalloc(len + 1, GFP_KERNEL);
	if (!tmp)
		return false;

	memcpy(tmp, buf, len);
	tmp[len] = '\0';

	matches = DFA_exec(root, tmp, &match_indices);
	kfree(match_indices);
	kfree(tmp);

	return matches > 0;
}

/* -------- helpers -------- */

struct dw_vlan_hdr {
	__be16 tci;
	__be16 enc_proto;
} __packed;

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

static struct pkt_state *state_alloc(u32 pkt_id, u32 req_mask)
{
	struct pkt_state *st;

	st = kzalloc(sizeof(*st), GFP_ATOMIC);
	if (!st)
		return NULL;

	st->pkt_id = pkt_id;
	atomic_set(&st->req_mask, req_mask & DW_REQ_MASK_3);
	atomic_set(&st->done_mask, 0);
	atomic_set(&st->hit_mask, 0);
	atomic_set(&st->verdict, DW_VERDICT_UNKNOWN);
	st->last_seen_jiffies = jiffies;
	st->next = NULL;
	return st;
}

static __bpf_kfunc int dw_state_init(u32 pkt_id, u32 req_mask)
{
	struct pkt_state *st;
	struct pkt_state *new_st;
	struct pkt_state *head;
	u32 bkt;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!pkt_id || !req_mask)
		return -EINVAL;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st) {
		atomic_or(req_mask & DW_REQ_MASK_3, &st->req_mask);
		WRITE_ONCE(st->last_seen_jiffies, jiffies);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	new_st = state_alloc(pkt_id, req_mask);
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
			atomic_or(req_mask & DW_REQ_MASK_3, &st->req_mask);
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

static void pkt_state_set_drop(struct pkt_state *st)
{
	int verdict;

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

		WRITE_ONCE(e->next, NULL);
		kfree_rcu(e, rcu);
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();
}

static bool frame_udp_payload_contains(const u8 *frame, u32 frame_len, const char *needle)
{
	const struct ethhdr *eth;
	const struct iphdr *iph;
	const struct udphdr *uh;
	const u8 *nh;
	u32 nh_len, l4_off, payload_off, payload_len;
	__be16 h_proto;
	int i;

	if (!frame || !needle || frame_len < sizeof(*eth))
		return false;

	eth = (const struct ethhdr *)frame;
	nh = frame + sizeof(*eth);
	nh_len = frame_len - sizeof(*eth);
	h_proto = eth->h_proto;

	for (i = 0; i < 2; i++) {
		const struct dw_vlan_hdr *vh;

		if (h_proto != htons(ETH_P_8021Q) &&
		    h_proto != htons(ETH_P_8021AD))
			break;

		if (nh_len < sizeof(*vh))
			return false;

		vh = (const struct dw_vlan_hdr *)nh;
		h_proto = vh->enc_proto;
		nh += sizeof(*vh);
		nh_len -= sizeof(*vh);
	}

	if (h_proto != htons(ETH_P_IP) || nh_len < sizeof(*iph))
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

	if (!strcmp(needle, DW_DUMMY_NEEDLE))
		return dw_bytes_contains(frame + payload_off, payload_len,
					 (const u8 *)DW_DUMMY_NEEDLE,
					 DW_DUMMY_NEEDLE_LEN);

	if (payload_len < DW_AC_MIN_LEN)
		return false;

	if (strcmp(needle, DW_AC_PATTERN_LABEL))
		return false;

	return dw_ac_match_bytes(dw_ac_root, frame + payload_off, payload_len);
}

static int snapshot_pkt_payload_contains(u32 pkt_id, const char *needle, bool *found_out)
{
	struct pkt_snap_ent *e;
	bool found;

	if (!found_out)
		return -EINVAL;

	rcu_read_lock();
	e = snap_lookup_rcu(pkt_id);
	if (!e) {
		rcu_read_unlock();
		return -ENOENT;
	}

	found = frame_udp_payload_contains(e->data, e->cap_len, needle);
	rcu_read_unlock();

	*found_out = found;
	return 0;
}

u32 dw_get_done_mask(u32 pkt_id)
{
	struct pkt_state *st;
	u32 v = 0;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st)
		v = (u32)atomic_read(&st->done_mask);
	rcu_read_unlock();

	return v;
}
EXPORT_SYMBOL_GPL(dw_get_done_mask);

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

void dw_note_payload_signature(u32 pkt_id, u32 req_mask, bool is_malicious)
{
	struct pkt_state *st;
	u32 req, done, hits, tracked_req;

	req = req_mask & DW_REQ_MASK_3;
	if (!pkt_id || !req || !is_malicious)
		return;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st) {
		/* Any requested analysis may report a match against the shared AC signature set. */
		atomic_or(req & DW_REQ_MASK_3, &st->hit_mask);
		hits = (u32)atomic_read(&st->hit_mask);
		done = (u32)atomic_read(&st->done_mask);
		tracked_req = (u32)atomic_read(&st->req_mask) & DW_REQ_MASK_3;
		if (hits & tracked_req)
			pkt_state_set_drop(st);
		WRITE_ONCE(st->last_seen_jiffies, jiffies);

		pr_info("payload signature hit pkt_id=%u req=0x%x source=\"%s\" done=0x%x hits=0x%x -> verdict=DROP\n",
			pkt_id, req, DW_AC_PATTERN_LABEL, done, hits);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(dw_note_payload_signature);

bool dw_are_done(u32 pkt_id, u32 req_mask, u32 *done_out)
{
	u32 done = dw_get_done_mask(pkt_id);
	if (done_out)
		*done_out = done;
	return ((done & (req_mask & DW_REQ_MASK_3)) == (req_mask & DW_REQ_MASK_3));
}
EXPORT_SYMBOL_GPL(dw_are_done);

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
static __bpf_kfunc int dw_meta_put(struct dw_pkt_key *key, u32 pkt_id, u32 req_mask)
{
	struct meta_ent *e;
	u32 h;
	u32 bkt;
	struct meta_ent *head;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!key || !pkt_id || !(req_mask & DW_REQ_MASK_3))
		return -EINVAL;

	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return -ENOMEM;

	memcpy(&e->key, key, sizeof(*key));
	e->pkt_id = pkt_id;
	e->req_mask = req_mask & DW_REQ_MASK_3;
	e->ts_jiffies = jiffies;
	e->claimed_jiffies = 0;
	atomic_set(&e->claimed, 0);
	e->next = NULL;

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
	e->next = NULL;
	memcpy(e->data, data, cap_len);

	snap_drop(pkt_id);
	bkt = snap_bucket(pkt_id);
	for (;;) {
		head = READ_ONCE(snap_ht[bkt]);
		WRITE_ONCE(e->next, head);
		if (cmpxchg(&snap_ht[bkt], head, e) == head)
			break;
	}

	if (len > cap_len)
		pr_info("snapshot pkt_id=%u truncated frame_len=%u cap_len=%u\n",
			pkt_id, len, cap_len);

	return (int)cap_len;
}

/* exported API: NF consumes */
bool dw_meta_get_and_del(struct dw_pkt_key *key, u32 *pkt_id_out, u32 *req_mask_out)
{
	struct meta_ent *e;
	u32 h;
	u32 bkt;
	unsigned long now;

	if (!key)
		return false;

	h = jhash(key, sizeof(*key), 0);
	bkt = meta_bucket_hash(h);
	now = jiffies;
	rcu_read_lock();
	for (e = READ_ONCE(meta_ht[bkt]); e; e = READ_ONCE(e->next)) {
		if (!key_equal(&e->key, key))
			continue;

		if (meta_claim_expired(e, now))
			continue;

		if (atomic_cmpxchg(&e->claimed, 0, 1) != 0)
			continue;

		WRITE_ONCE(e->claimed_jiffies, now);
		if (pkt_id_out)
			*pkt_id_out = READ_ONCE(e->pkt_id);
		if (req_mask_out)
			*req_mask_out = READ_ONCE(e->req_mask);
		rcu_read_unlock();
		return true;
	}
	rcu_read_unlock();

	meta_gc_bucket(bkt, now);
	return false;
}
EXPORT_SYMBOL_GPL(dw_meta_get_and_del);

/* -------- deferred analyses -------- */

struct analysis_work {
	struct work_struct work;
	u32 pkt_id;
	u32 bit;
};

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

static void __dw_try_deliver_ready(void)
{
	struct flow_ent *fe;
	struct nf_queue_entry *qent;
	bool stopping;
	int bkt;

	for (bkt = 0; bkt < FLOW_BUCKETS; bkt++) {
		for (fe = READ_ONCE(flow_ht[bkt]); fe; fe = READ_ONCE(fe->next)) {
			u32 head = READ_ONCE(fe->head);

		for (;;) {
			struct dw_buf_ent *be;
			u32 pkt_id, req, done;
			u32 tail;
			int verdict;

			tail = (u32)atomic_read(&fe->tail);
			if (head == tail)
				break;

			be = flow_slot_at(fe, head);
			if (!smp_load_acquire(&be->ready) || READ_ONCE(be->pos) != head)
				break;

			pkt_id = be->pkt_id;
			req = be->req_mask;
			stopping = atomic_read(&nfq_stopping);
			verdict = dw_get_verdict(pkt_id);

			if (stopping) {
				pr_info("deliver flow-head pkt_id=%u req=0x%x teardown -> accept queued packet\n",
					pkt_id, req);
				snap_drop(pkt_id);
				qent = be->qent;
				WRITE_ONCE(be->qent, NULL);
				smp_store_release(&be->ready, false);
				WRITE_ONCE(fe->head, ++head);
				nf_reinject(qent, NF_ACCEPT);
				atomic_dec(&st_pending);
				atomic_inc(&st_delivered);
				WRITE_ONCE(fe->last_seen_jiffies, jiffies);
				continue;
			}

			if (verdict == DW_VERDICT_DROP) {
				pr_info("deliver flow-head pkt_id=%u req=0x%x verdict=DROP -> drop queued packet\n",
					pkt_id, req);
				snap_drop(pkt_id);
				qent = be->qent;
				WRITE_ONCE(be->qent, NULL);
				smp_store_release(&be->ready, false);
				WRITE_ONCE(fe->head, ++head);
				nf_reinject(qent, NF_DROP);
				atomic_dec(&st_pending);
				atomic_inc(&st_dropped);
				WRITE_ONCE(fe->last_seen_jiffies, jiffies);
				continue;
			}

			if (!dw_are_done(pkt_id, req, &done)) {
				pr_info("deliver flow-head pkt_id=%u req=0x%x done=0x%x -> block flow head\n",
					pkt_id, req, done);
				break;
			}

			pr_info("deliver flow-head pkt_id=%u req=0x%x done=0x%x verdict=PASS -> reinject\n",
				pkt_id, req, done);
			snap_drop(pkt_id);

			qent = be->qent;
			WRITE_ONCE(be->qent, NULL);
			smp_store_release(&be->ready, false);
			WRITE_ONCE(fe->head, ++head);
			nf_reinject(qent, NF_ACCEPT);
			atomic_inc(&st_delivered);
			atomic_dec(&st_pending);
			WRITE_ONCE(fe->last_seen_jiffies, jiffies);
		}
	}
	}
}

static void dw_try_deliver_ready(void)
{
	atomic_set(&delivery_kicked, 1);

	if (atomic_cmpxchg(&delivery_running, 0, 1) != 0)
		return;

	for (;;) {
		/*
		 * Only one drainer may walk flow_ht at a time. Even without
		 * per-flow locks, keeping a single consumer preserves the
		 * circular-buffer head invariant for each flow.
		 */
		atomic_set(&delivery_kicked, 0);
		__dw_try_deliver_ready();
		smp_mb__after_atomic();
		if (!atomic_read(&delivery_kicked))
			break;
	}

	atomic_set(&delivery_running, 0);
	smp_mb__after_atomic();

	if (atomic_xchg(&delivery_kicked, 0) &&
	    atomic_cmpxchg(&delivery_running, 0, 1) == 0) {
		for (;;) {
			atomic_set(&delivery_kicked, 0);
			__dw_try_deliver_ready();
			smp_mb__after_atomic();
			if (!atomic_read(&delivery_kicked))
				break;
		}
		atomic_set(&delivery_running, 0);
	}
}

static void analysis_workfn(struct work_struct *w)
{
	struct analysis_work *aw = container_of(w, struct analysis_work, work);
	struct pkt_state *st;
	u32 req_mask, done, hits;
	bool is_malicious = false;
	bool terminal = false;
	int sig_rc;

	/* Signature check reads the XDP snapshot copied at schedule time. */
	
	/* 3 analisi dummy: no false positive da pkt_id beyond the payload marker check above */
	switch (aw->bit) {
	case DW_REQ_A1:
		is_malicious = false;
		break;
	case DW_REQ_A2:
		sig_rc = snapshot_pkt_payload_contains(aw->pkt_id, DW_DUMMY_NEEDLE,
						       &is_malicious);
		if (sig_rc < 0)
			pr_info("analysis pkt_id=%u bit=0x%x snapshot not available rc=%d, continuing\n",
				aw->pkt_id, aw->bit, sig_rc);
		break;
	case DW_REQ_A3:
		sig_rc = snapshot_pkt_payload_contains(aw->pkt_id, DW_AC_PATTERN_LABEL,
						       &is_malicious);
		if (sig_rc < 0)
			pr_info("analysis pkt_id=%u bit=0x%x snapshot not available rc=%d, continuing\n",
				aw->pkt_id, aw->bit, sig_rc);
		break;
	default:
		break;
	}

	rcu_read_lock();
	st = state_lookup_rcu(aw->pkt_id);
	if (st) {
		if (is_malicious)
			atomic_or(aw->bit, &st->hit_mask);

		atomic_or(aw->bit, &st->done_mask);
		done = (u32)atomic_read(&st->done_mask);
		hits = (u32)atomic_read(&st->hit_mask);
		req_mask = (u32)atomic_read(&st->req_mask) & DW_REQ_MASK_3;

		if (hits & req_mask)
			pkt_state_set_drop(st);
		else if ((done & req_mask) == req_mask)
			pkt_state_try_set_pass(st);

		WRITE_ONCE(st->last_seen_jiffies, jiffies);
	}
	rcu_read_unlock();

	if (st) {
		pr_info("analysis pkt_id=%u bit=0x%x done=0x%x/0x%x hits=0x%x verdict=%s\n",
			aw->pkt_id, aw->bit, done, req_mask, hits,
			(hits & req_mask) ? "DROP" :
			(((done & req_mask) == req_mask) ? "PASS" : "PENDING"));

		terminal = (hits & req_mask) || ((done & req_mask) == req_mask);
	}
	if (terminal)
		dw_try_deliver_ready();

	kfree(aw);
}

/* -------- kfunc called by XDP: schedule analyses -------- */

static __bpf_kfunc int dw_register_and_schedule(u32 pkt_id, u32 req_mask)
{
	int id;
	int cpu, ncpus;
	struct pkt_state *st;

	if (dw_module_is_stopping())
		return -ESHUTDOWN;

	if (!req_mask)
		return 0;

	rcu_read_lock();
	st = state_lookup_rcu(pkt_id);
	if (st) {
		atomic_or(req_mask & DW_REQ_MASK_3, &st->req_mask);
		WRITE_ONCE(st->last_seen_jiffies, jiffies);
	}
	rcu_read_unlock();

	if (!st) {
		pr_err("dw_register_and_schedule entry not found pkt_id=%u req=0x%x\n",
		       pkt_id, req_mask & DW_REQ_MASK_3);
		atomic_inc(&st_dropped);
		return -ENOENT;
	}

	ncpus = num_online_cpus();

	for (id = 1; id <= 3; id++) {
		u32 bit = 1u << (id - 1);
		struct analysis_work *aw;

		if (!(req_mask & bit))
			continue;

		aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
		if (!aw) {
			atomic_inc(&st_dropped);
			continue;
		}
		INIT_WORK(&aw->work, analysis_workfn);
		aw->pkt_id = pkt_id;
		aw->bit = bit;

		cpu = atomic_inc_return(&rr_cpu) % ncpus;
		queue_work_on(cpu, dw_wq, &aw->work);
	}

	return 0;
}

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

int dw_buffer_nfqueue_entry(struct nf_queue_entry *entry, u32 pkt_id, u32 req_mask)
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
		pr_info("nfqueue stopping pkt_id=%u req=0x%x -> accept queued packet\n",
			pkt_id, req_mask & DW_REQ_MASK_3);
		snap_drop(pkt_id);
		nf_reinject(entry, NF_ACCEPT);
		atomic_inc(&st_delivered);
		return DW_NFQ_DROPPED;
	}

	verdict = dw_get_verdict(pkt_id);
	if (verdict == DW_VERDICT_DROP) {
		pr_info("nfqueue immediate drop pkt_id=%u req=0x%x verdict=DROP\n",
			pkt_id, req_mask & DW_REQ_MASK_3);
		snap_drop(pkt_id);
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
		pr_info("flow ring full pkt_id=%u req=0x%x -> drop queued packet\n",
			pkt_id, req_mask & DW_REQ_MASK_3);
		snap_drop(pkt_id);
		nf_reinject(entry, NF_DROP);
		atomic_inc(&st_dropped);
		return DW_NFQ_DROPPED;
	}

	if (!nf_queue_entry_get_refs(entry)) {
		atomic_inc(&st_dropped);
		return -EINVAL;
	}

	be = flow_slot_at(fe, pos);
	be->qent = entry;
	be->pkt_id = pkt_id;
	be->req_mask = req_mask & DW_REQ_MASK_3;
	be->pos = pos;
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
		pr_info("nfqueue quiesce already in progress\n");
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

/* -------- module init/exit -------- */

static int __init deferred_init(void)
{
	int ret;

	memset(flow_ht, 0, sizeof(flow_ht));
	atomic_set(&nfq_stopping, 0);
	atomic_set(&nfq_quiescing, 0);
	atomic_set(&delivery_running, 0);
	atomic_set(&delivery_kicked, 0);
	atomic_set(&dw_stopping, 0);

	dw_wq = alloc_workqueue("dw_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!dw_wq)
		return -ENOMEM;

	state_id = 0;
	dw_ac_root = DFA_build((const void **)dw_ac_patterns, DW_AC_PATTERN_COUNT);
	if (!dw_ac_root) {
		destroy_workqueue(dw_wq);
		dw_wq = NULL;
		return -ENOMEM;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &dw_kfunc_ids);
	if (ret) {
		pr_err("register_btf_kfunc_id_set failed: %d\n", ret);
		DFA_free(dw_ac_root);
		dw_ac_root = NULL;
		destroy_workqueue(dw_wq);
		return ret;
	}

	pr_info("loaded\n");
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
			kfree_rcu(se, rcu);
			se = next;
		}
	}

	pr_info("unloaded\n");
}

module_init(deferred_init);
module_exit(deferred_exit);
