#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <linux/unistd.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/udp.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/hashtable.h>

#include <net/ip.h>

#include "deferred_work.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");

/* -------- bypass cb (per reinjection) -------- */

#define DW_BYPASS_MARK  0xDEADDEAD
#define DW_CB_MAGIC     0xDA7ADA7A

struct dw_cb {
	u32 bypass_mark;
	u32 magic;
	u32 pkt_id;
	u32 req_mask;
} __aligned(4);

static inline struct dw_cb *dwcb(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct dw_cb) > sizeof(skb->cb));
	return (struct dw_cb *)skb->cb;
}

/* -------- per-packet analysis state -------- */

struct pkt_state {
	u32 pkt_id;
	u32 req_mask;
	atomic_t done_mask;
	atomic_t hit_mask;  /* bitmask di analisi con match malevolo */
	atomic_t verdict; /* 0 unknown, 1 pass, 2 drop */
	unsigned long last_seen_jiffies;
	struct hlist_node hnode;
};

#define STATE_BITS 12
static DEFINE_HASHTABLE(state_ht, STATE_BITS);
static DEFINE_SPINLOCK(state_lock);

/* -------- correlation table: fingerprint -> (pkt_id, req_mask) -------- */

struct meta_ent {
	struct dw_pkt_key key;
	u32 pkt_id;
	u32 req_mask;
	unsigned long ts_jiffies;
	struct hlist_node hnode;
};

#define META_BITS 12
static DEFINE_HASHTABLE(meta_ht, META_BITS);
static DEFINE_SPINLOCK(meta_lock);

/* -------- buffering queue -------- */

static struct workqueue_struct *dw_wq;
static struct work_struct deliver_work;
static struct sk_buff_head bufq;

/* -------- stats/debug -------- */

static atomic_t st_pending   = ATOMIC_INIT(0);
static atomic_t st_delivered = ATOMIC_INIT(0);
static atomic_t st_dropped   = ATOMIC_INIT(0);
static atomic_t rr_cpu       = ATOMIC_INIT(0);

#define DW_DUMMY_NEEDLE "malicious"

/* -------- helpers -------- */

static struct pkt_state *state_lookup(u32 pkt_id)
{
	struct pkt_state *st;
	hash_for_each_possible(state_ht, st, hnode, pkt_id) {
		if (st->pkt_id == pkt_id)
			return st;
	}
	return NULL;
}

static struct pkt_state *state_get_or_create(u32 pkt_id, u32 req_mask)
{
	struct pkt_state *st;

	st = state_lookup(pkt_id);
	if (st) {
		st->req_mask |= (req_mask & DW_REQ_MASK_3);
		st->last_seen_jiffies = jiffies;
		return st;
	}

	st = kzalloc(sizeof(*st), GFP_ATOMIC);
	if (!st)
		return NULL;

	st->pkt_id = pkt_id;
	st->req_mask = req_mask & DW_REQ_MASK_3;
	atomic_set(&st->done_mask, 0);
	atomic_set(&st->hit_mask, 0);
	atomic_set(&st->verdict, DW_VERDICT_UNKNOWN);
	st->last_seen_jiffies = jiffies;

	hash_add(state_ht, &st->hnode, pkt_id);
	return st;
}

static bool buf_contains_needle(const u8 *buf, size_t len, const char *needle)
{
	size_t i, nlen = strlen(needle);

	if (!buf || !needle || !nlen || len < nlen)
		return false;

	for (i = 0; i + nlen <= len; i++) {
		if (!memcmp(buf + i, needle, nlen))
			return true;
	}

	return false;
}

static bool skb_udp_payload_contains(struct sk_buff *skb, const char *needle)
{
	struct iphdr _iph, *iph;
	struct udphdr _uh, *uh;
	unsigned int l4_off, payload_off, skb_payload_len;
	u16 udp_len;
	u8 *buf;
	bool found = false;

	if (!skb || !needle)
		return false;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return false;

	l4_off = iph->ihl * 4;
	uh = skb_header_pointer(skb, l4_off, sizeof(_uh), &_uh);
	if (!uh)
		return false;

	udp_len = ntohs(uh->len);
	if (udp_len <= sizeof(*uh))
		return false;

	payload_off = l4_off + sizeof(*uh);
	skb_payload_len = skb->len > payload_off ? (skb->len - payload_off) : 0;
	if (!skb_payload_len)
		return false;

	skb_payload_len = min_t(unsigned int, skb_payload_len, udp_len - sizeof(*uh));
	if (!skb_payload_len)
		return false;

	buf = kmalloc(skb_payload_len, GFP_ATOMIC);
	if (!buf)
		return false;

	if (!skb_copy_bits(skb, payload_off, buf, skb_payload_len))
		found = buf_contains_needle(buf, skb_payload_len, needle);

	kfree(buf);
	return found;
}

u32 dw_get_done_mask(u32 pkt_id)
{
	struct pkt_state *st;
	u32 v = 0;

	spin_lock_bh(&state_lock);
	st = state_lookup(pkt_id);
	if (st)
		v = (u32)atomic_read(&st->done_mask);
	spin_unlock_bh(&state_lock);

	return v;
}
EXPORT_SYMBOL_GPL(dw_get_done_mask);

int dw_get_verdict(u32 pkt_id)
{
	struct pkt_state *st;
	int v = DW_VERDICT_UNKNOWN;

	spin_lock_bh(&state_lock);
	st = state_lookup(pkt_id);
	if (st)
		v = atomic_read(&st->verdict);
	spin_unlock_bh(&state_lock);

	return v;
}
EXPORT_SYMBOL_GPL(dw_get_verdict);

void dw_note_payload_signature(struct sk_buff *skb, u32 pkt_id, u32 req_mask)
{
	struct pkt_state *st;
	u32 req, done, hits;
	bool is_malicious;

	req = req_mask & DW_REQ_MASK_3;
	if (!pkt_id || !req || !skb)
		return;

	is_malicious = skb_udp_payload_contains(skb, DW_DUMMY_NEEDLE);
	if (!is_malicious)
		return;

	spin_lock_bh(&state_lock);
	st = state_lookup(pkt_id);
	if (st) {
		/* Dummy behavior: any requested analysis may report the payload marker. */
		atomic_or(req & DW_REQ_MASK_3, &st->hit_mask);
		hits = (u32)atomic_read(&st->hit_mask);
		done = (u32)atomic_read(&st->done_mask);
		if (hits & (st->req_mask & DW_REQ_MASK_3))
			atomic_set(&st->verdict, DW_VERDICT_DROP);
		st->last_seen_jiffies = jiffies;

		pr_info("payload marker hit pkt_id=%u req=0x%x needle=\"%s\" done=0x%x hits=0x%x -> verdict=DROP\n",
			pkt_id, req, DW_DUMMY_NEEDLE, done, hits);
	}
	spin_unlock_bh(&state_lock);
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

/* -------- meta store: used by XDP (put) and NF (get+del) -------- */

static bool key_equal(const struct dw_pkt_key *a, const struct dw_pkt_key *b)
{
	return !memcmp(a, b, sizeof(*a));
}

/* kfunc: correlation put (XDP writes) */
static __bpf_kfunc int dw_meta_put(struct dw_pkt_key *key, u32 pkt_id, u32 req_mask)
{
	struct meta_ent *e;
	u32 h;

	if (!key || !pkt_id || !(req_mask & DW_REQ_MASK_3))
		return -EINVAL;

	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return -ENOMEM;

	memcpy(&e->key, key, sizeof(*key));
	e->pkt_id = pkt_id;
	e->req_mask = req_mask & DW_REQ_MASK_3;
	e->ts_jiffies = jiffies;

	h = jhash(&e->key, sizeof(e->key), 0);

	spin_lock_bh(&meta_lock);
	hash_add(meta_ht, &e->hnode, h);
	spin_unlock_bh(&meta_lock);

	return 0;
}

/* exported API: NF consumes */
bool dw_meta_get_and_del(struct dw_pkt_key *key, u32 *pkt_id_out, u32 *req_mask_out)
{
	struct meta_ent *e;
	u32 h;

	if (!key)
		return false;

	h = jhash(key, sizeof(*key), 0);

	spin_lock_bh(&meta_lock);
	hash_for_each_possible(meta_ht, e, hnode, h) {
		if (key_equal(&e->key, key)) {
			if (pkt_id_out)   *pkt_id_out = e->pkt_id;
			if (req_mask_out) *req_mask_out = e->req_mask;
			hash_del(&e->hnode);
			spin_unlock_bh(&meta_lock);
			kfree(e);
			return true;
		}
	}
	spin_unlock_bh(&meta_lock);
	return false;
}
EXPORT_SYMBOL_GPL(dw_meta_get_and_del);

/* -------- deferred analyses -------- */

struct analysis_work {
	struct work_struct work;
	u32 pkt_id;
	u32 bit;
};

static void analysis_workfn(struct work_struct *w)
{
	struct analysis_work *aw = container_of(w, struct analysis_work, work);
	struct pkt_state *st;
	u32 req_mask, done, hits;
	bool is_malicious = false;

	/* 3 analisi dummy: no false positive da pkt_id, il DROP vero arriva dal marker nel payload */
	switch (aw->bit) {
	case DW_REQ_A1:
		is_malicious = false;
		break;
	case DW_REQ_A2:
		is_malicious = false;
		break;
	case DW_REQ_A3:
		fsleep(2);
		is_malicious = false;
		break;
	default:
		break;
	}

	spin_lock_bh(&state_lock);
	st = state_lookup(aw->pkt_id);
	if (st) {
		if (is_malicious)
			atomic_or(aw->bit, &st->hit_mask);

		atomic_or(aw->bit, &st->done_mask);
		done = (u32)atomic_read(&st->done_mask);
		hits = (u32)atomic_read(&st->hit_mask);
		req_mask = st->req_mask & DW_REQ_MASK_3;

		if (hits & req_mask)
			atomic_set(&st->verdict, DW_VERDICT_DROP);
		else if ((done & req_mask) == req_mask)
			atomic_set(&st->verdict, DW_VERDICT_PASS);

		st->last_seen_jiffies = jiffies;
	}
	spin_unlock_bh(&state_lock);

	if (st) {
		pr_info("analysis pkt_id=%u bit=0x%x done=0x%x/0x%x hits=0x%x verdict=%s\n",
			aw->pkt_id, aw->bit, done, req_mask, hits,
			(hits & req_mask) ? "DROP" :
			(((done & req_mask) == req_mask) ? "PASS" : "PENDING"));
	}

	queue_work(dw_wq, &deliver_work);

	kfree(aw);
}

/* -------- kfunc called by XDP: schedule analyses -------- */

static __bpf_kfunc int dw_register_and_schedule(u32 pkt_id, u32 req_mask)
{
	int id;
	int cpu, ncpus;
	struct pkt_state *st;

	if (!req_mask)
		return 0;

	spin_lock_bh(&state_lock);
	st = state_get_or_create(pkt_id, req_mask);
	spin_unlock_bh(&state_lock);

	if (!st) {
		atomic_inc(&st_dropped);
		return -ENOMEM;
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
BTF_ID_FLAGS(func, dw_register_and_schedule, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, dw_meta_put,              KF_TRUSTED_ARGS)
BTF_SET8_END(dw_kfunc_set)

static const struct btf_kfunc_id_set dw_kfunc_ids = {
	.owner = THIS_MODULE,
	.set   = &dw_kfunc_set,
};

/* -------- API used by Netfilter -------- */

bool dw_is_bypass_skb(struct sk_buff *skb)
{
	return skb && skb->mark == DW_BYPASS_MARK;
}
EXPORT_SYMBOL_GPL(dw_is_bypass_skb);

int dw_buffer_marked_skb(struct sk_buff *skb, u32 pkt_id, u32 req_mask, u32 mark_dummy)
{
	struct sk_buff *nskb;

	nskb = skb_copy(skb, GFP_ATOMIC);
	if (!nskb) {
		atomic_inc(&st_dropped);
		return -ENOMEM;
	}

	memset(nskb->cb, 0, sizeof(nskb->cb));
	dwcb(nskb)->magic = DW_CB_MAGIC;
	dwcb(nskb)->bypass_mark = 0;
	dwcb(nskb)->pkt_id = pkt_id;
	dwcb(nskb)->req_mask = req_mask & DW_REQ_MASK_3;

	nskb->mark = mark_dummy;

	__skb_queue_tail(&bufq, nskb);
	atomic_inc(&st_pending);

	queue_work(dw_wq, &deliver_work);
	return 1;
}
EXPORT_SYMBOL_GPL(dw_buffer_marked_skb);

/* -------- delivery: reinject ready packets -------- */

static void deliver_workfn(struct work_struct *w)
{
	struct net_device *lo;
	struct sk_buff *skb, *nskb;
	unsigned int i, n;

	lo = dev_get_by_name(&init_net, "lo");
	if (!lo) {
		pr_err("loopback not found\n");
		return;
	}

	n = skb_queue_len(&bufq);

	for (i = 0; i < n; i++) {
		u32 pkt_id, req, done;
		int verdict;

		skb = skb_dequeue(&bufq);
		if (!skb)
			break;

		pkt_id = dwcb(skb)->pkt_id;
		req    = dwcb(skb)->req_mask;
		verdict = dw_get_verdict(pkt_id);

		if (verdict == DW_VERDICT_DROP) {
			pr_info("deliver pkt_id=%u req=0x%x verdict=DROP -> free buffered skb\n",
				pkt_id, req);
			kfree_skb(skb);
			atomic_dec(&st_pending);
			atomic_inc(&st_dropped);
			continue;
		}

		if (!dw_are_done(pkt_id, req, &done)) {
			pr_info("deliver pkt_id=%u req=0x%x done=0x%x -> keep buffered\n",
				pkt_id, req, done);
			__skb_queue_tail(&bufq, skb);
			continue;
		}

		/* PASS: reinject */
		pr_info("deliver pkt_id=%u req=0x%x done=0x%x verdict=PASS -> reinject\n",
			pkt_id, req, done);
		nskb = skb_copy(skb, GFP_KERNEL);
		if (!nskb) {
			kfree_skb(skb);
			atomic_dec(&st_pending);
			atomic_inc(&st_dropped);
			continue;
		}

		memset(nskb->cb, 0, sizeof(nskb->cb));
		nskb->mark = DW_BYPASS_MARK;
		nskb->dev = lo;
		nskb->protocol = htons(ETH_P_IP);
		nskb->pkt_type = PACKET_HOST;
		nskb->ip_summed = CHECKSUM_NONE;

		if (netif_receive_skb(nskb) == NET_RX_SUCCESS)
			atomic_inc(&st_delivered);
		else
			atomic_inc(&st_dropped);

		kfree_skb(skb);
		atomic_dec(&st_pending);
	}

	dev_put(lo);
}

/* -------- module init/exit -------- */

static int __init deferred_init(void)
{
	int ret;

	hash_init(state_ht);
	hash_init(meta_ht);
	skb_queue_head_init(&bufq);

	dw_wq = alloc_workqueue("dw_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!dw_wq)
		return -ENOMEM;

	INIT_WORK(&deliver_work, deliver_workfn);

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &dw_kfunc_ids);
	if (ret) {
		pr_err("register_btf_kfunc_id_set failed: %d\n", ret);
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
	struct sk_buff *skb;
	struct hlist_node *tmp;
	int bkt;

	
	destroy_workqueue(dw_wq);

	/* cleanup state_ht */
	spin_lock_bh(&state_lock);
	hash_for_each_safe(state_ht, bkt, tmp, st, hnode) {
		hash_del(&st->hnode);
		kfree(st);
	}
	spin_unlock_bh(&state_lock);

	/* cleanup meta_ht */
	spin_lock_bh(&meta_lock);
	hash_for_each_safe(meta_ht, bkt, tmp, me, hnode) {
		hash_del(&me->hnode);
		kfree(me);
	}
	spin_unlock_bh(&meta_lock);

	/* cleanup bufq */
	while ((skb = skb_dequeue(&bufq)) != NULL)
		kfree_skb(skb);

	pr_info("unloaded\n");
}

module_init(deferred_init);
module_exit(deferred_exit);
