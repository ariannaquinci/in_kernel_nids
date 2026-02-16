#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>

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

/* TTL to avoid stale entries if skb never reaches PREROUTING */
static unsigned int meta_ttl_ms = 200;
module_param(meta_ttl_ms, uint, 0644);
MODULE_PARM_DESC(meta_ttl_ms, "TTL (ms) for XDP->skb correlation entries");

static u32 key_hash(struct dw_pkt_key *k)
{
	/* simple 32-bit mix; good enough here */
	u32 h = 0x9e3779b9;
	h ^= k->saddr + 0x7ed55d16 + (h<<12) + (h>>19);
	h ^= k->daddr + 0xc761c23c + (h<<12) + (h>>19);
	h ^= ((u32)k->sport << 16) | k->dport;
	h ^= ((u32)k->ip_id << 16) | k->udp_len;
	h ^= (u32)k->proto * 0x27d4eb2d;
	return h;
}

static bool key_equal(struct dw_pkt_key *a, struct dw_pkt_key *b)
{
	return !memcmp(a, b, sizeof(*a));
}

static void meta_gc_locked(void)
{
	struct meta_ent *e;
	struct hlist_node *tmp;
	int bkt;
	unsigned long now = jiffies;
	unsigned long ttl = msecs_to_jiffies(meta_ttl_ms);

	hash_for_each_safe(meta_ht, bkt, tmp, e, hnode) {
		if (time_after(now, e->ts_jiffies + ttl)) {
			hash_del(&e->hnode);
			kfree(e);
		}
	}
}

/* called from Netfilter module */
bool dw_meta_get_and_del(struct dw_pkt_key *key, u32 *pkt_id_out, u32 *req_mask_out)
{
	u32 h = key_hash(key);
	struct meta_ent *e;

	spin_lock_bh(&meta_lock);

	/* opportunistic GC */
	meta_gc_locked();

	hash_for_each_possible(meta_ht, e, hnode, h) {
		if (key_equal(&e->key, key)) {
			if (pkt_id_out)  *pkt_id_out  = e->pkt_id;
			if (req_mask_out) *req_mask_out = e->req_mask;
			hash_del(&e->hnode);
			kfree(e);
			spin_unlock_bh(&meta_lock);
			return true;
		}
	}

	spin_unlock_bh(&meta_lock);
	return false;
}
EXPORT_SYMBOL_GPL(dw_meta_get_and_del);

/* -------- buffered packets queue -------- */

static struct sk_buff_head bufq;

/* workqueue */
static struct workqueue_struct *dw_wq;
static atomic_t rr_cpu = ATOMIC_INIT(0);

/* stats */
static atomic_t st_pending = ATOMIC_INIT(0);
static atomic_t st_delivered = ATOMIC_INIT(0);
static atomic_t st_dropped = ATOMIC_INIT(0);

/* forward */
static void deliver_workfn(struct work_struct *w);
static DECLARE_WORK(deliver_work, deliver_workfn);

/* -------- helpers: state lookup/create -------- */

static struct pkt_state *state_get_or_create(u32 pkt_id, u32 req_mask)
{
	struct pkt_state *st;

	hash_for_each_possible(state_ht, st, hnode, pkt_id) {
		if (st->pkt_id == pkt_id) {
			st->req_mask |= (req_mask & 0x7u);
			st->last_seen_jiffies = jiffies;
			return st;
		}
	}

	st = kzalloc(sizeof(*st), GFP_ATOMIC);
	if (!st)
		return NULL;

	st->pkt_id = pkt_id;
	st->req_mask = req_mask & 0x7u;
	atomic_set(&st->done_mask, 0);
	st->last_seen_jiffies = jiffies;

	hash_add(state_ht, &st->hnode, st->pkt_id);
	return st;
}

static struct pkt_state *state_lookup(u32 pkt_id)
{
	struct pkt_state *st;

	hash_for_each_possible(state_ht, st, hnode, pkt_id) {
		if (st->pkt_id == pkt_id)
			return st;
	}
	return NULL;
}

/* -------- analysis work -------- */

struct analysis_work {
	struct work_struct work;
	u32 pkt_id;
	u32 bit; /* 1<<0 .. 1<<2 */
};

static void analysis_workfn(struct work_struct *w)
{
	struct analysis_work *aw = container_of(w, struct analysis_work, work);
	struct pkt_state *st;
	u32 newmask;

	spin_lock_bh(&state_lock);
	st = state_lookup(aw->pkt_id);
	if (st) {
		newmask = (u32)atomic_read(&st->done_mask) | aw->bit;
		atomic_set(&st->done_mask, newmask);
	}
	spin_unlock_bh(&state_lock);

	if (st) {
		u32 req = READ_ONCE(st->req_mask);
		u32 done = (u32)atomic_read(&st->done_mask);
		if ((done & req) == req){
			pr_info("queueing work");
			queue_work(dw_wq, &deliver_work);
		
		}
	}

	// pr_info("analysis done pkt_id=%u bit=0x%x\n", aw->pkt_id, aw->bit);
	kfree(aw);
}

/* -------- kfunc: correlation put (XDP writes) -------- */

static __bpf_kfunc int dw_meta_put(struct dw_pkt_key *key, u32 pkt_id, u32 req_mask)
{
	struct meta_ent *e;
	u32 h;

	if (!key || !pkt_id || !(req_mask & 0x7u))
		return -EINVAL;

	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return -ENOMEM;

	memcpy(&e->key, key, sizeof(*key));
	e->pkt_id = pkt_id;
	e->req_mask = req_mask & 0x7u;
	e->ts_jiffies = jiffies;

	h = key_hash(key);

	spin_lock_bh(&meta_lock);
	/* optional: overwrite existing identical key */
	{
		struct meta_ent *cur;
		hash_for_each_possible(meta_ht, cur, hnode, h) {
			if (key_equal(&cur->key, key)) {
				cur->pkt_id = pkt_id;
				cur->req_mask = req_mask & 0x7u;
				cur->ts_jiffies = jiffies;
				spin_unlock_bh(&meta_lock);
				kfree(e);
				return 0;
			}
		}
	}
	hash_add(meta_ht, &e->hnode, h);
	spin_unlock_bh(&meta_lock);

	return 0;
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

	pr_info("scheduled deferred work pkt_id=%u req=0x%x\n", pkt_id, req_mask & 0x7u);
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
	struct dw_cb *cb = (struct dw_cb *)skb->cb;
	return cb->magic == DW_CB_MAGIC && cb->bypass_mark == DW_BYPASS_MARK;
}
EXPORT_SYMBOL_GPL(dw_is_bypass_skb);

u32 dw_get_done_mask(u32 pkt_id)
{
	struct pkt_state *st;
	u32 done = 0;

	spin_lock_bh(&state_lock);
	st = state_lookup(pkt_id);
	if (st)
		done = (u32)atomic_read(&st->done_mask) & 0x7u;
	spin_unlock_bh(&state_lock);

	return done;
}
EXPORT_SYMBOL_GPL(dw_get_done_mask);

bool dw_are_done(u32 pkt_id, u32 req_mask, u32 *done_out)
{
	struct pkt_state *st;
	u32 done = 0;
	bool ok = false;

	spin_lock_bh(&state_lock);
	st = state_lookup(pkt_id);
	if (st) {
		done = (u32)atomic_read(&st->done_mask) & 0x7u;
		ok = ((done & (req_mask & 0x7u)) == (req_mask & 0x7u));
	}
	spin_unlock_bh(&state_lock);

	if (done_out)
		*done_out = done;

	return ok;
}
EXPORT_SYMBOL_GPL(dw_are_done);

/* buffer skb (copy) for later reinjection */
int dw_buffer_marked_skb(struct sk_buff *skb, u32 pkt_id, u32 req_mask, u32 mark_dummy)
{
	struct sk_buff *nskb;

	nskb = skb_copy((struct sk_buff *)skb, GFP_ATOMIC);
	if (!nskb) {
		atomic_inc(&st_dropped);
		return -ENOMEM;
	}

	memset(nskb->cb, 0, sizeof(nskb->cb));
	dwcb(nskb)->magic = DW_CB_MAGIC;
	dwcb(nskb)->bypass_mark = 0;
	dwcb(nskb)->pkt_id = pkt_id;
	dwcb(nskb)->req_mask = req_mask & 0x7u;

	/* not used anymore for logic, but keep if you want */
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

		skb = skb_dequeue(&bufq);
		if (!skb)
			break;

		pkt_id = dwcb(skb)->pkt_id;
		req    = dwcb(skb)->req_mask;

		if (!dw_are_done(pkt_id, req, &done)) {
			__skb_queue_tail(&bufq, skb);
			continue;
		}

		nskb = skb_copy(skb, GFP_KERNEL);
		if (!nskb) {
			atomic_inc(&st_dropped);
			kfree_skb(skb);
			atomic_dec(&st_pending);
			continue;
		}

		memset(nskb->cb, 0, sizeof(nskb->cb));
		dwcb(nskb)->magic = DW_CB_MAGIC;
		dwcb(nskb)->bypass_mark = DW_BYPASS_MARK;

		nskb->mark = 0;

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

/* -------- init/exit -------- */

static int __init deferred_work_init(void)
{
	int ret;

	skb_queue_head_init(&bufq);

	dw_wq = alloc_workqueue("dw_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!dw_wq)
		return -ENOMEM;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &dw_kfunc_ids);
	if (ret)
		pr_err("kfunc register failed: %d\n", ret);
	else
		pr_info("kfunc registered (XDP)\n");

	pr_info("loaded\n");
	return 0;
}

static void __exit deferred_work_exit(void)
{
	struct pkt_state *st;
	struct hlist_node *tmp;
	int bkt;

	struct meta_ent *me;
	struct hlist_node *tmp2;
	int bkt2;

	flush_workqueue(dw_wq);
	destroy_workqueue(dw_wq);

	skb_queue_purge(&bufq);

	spin_lock_bh(&state_lock);
	hash_for_each_safe(state_ht, bkt, tmp, st, hnode) {
		hash_del(&st->hnode);
		kfree(st);
	}
	spin_unlock_bh(&state_lock);

	spin_lock_bh(&meta_lock);
	hash_for_each_safe(meta_ht, bkt2, tmp2, me, hnode) {
		hash_del(&me->hnode);
		kfree(me);
	}
	spin_unlock_bh(&meta_lock);

	pr_info("unloaded (pending=%d delivered=%d dropped=%d)\n",
		atomic_read(&st_pending),
		atomic_read(&st_delivered),
		atomic_read(&st_dropped));
}

module_init(deferred_work_init);
module_exit(deferred_work_exit);
