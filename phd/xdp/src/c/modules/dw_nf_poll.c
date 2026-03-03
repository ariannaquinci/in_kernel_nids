// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/hashtable.h>

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "deferred_work.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");

#define MARK_MAGIC     0x80000000u
#define MARK_REQ_SHIFT 24
#define MARK_ID_MASK   0x00FFFFFFu

static inline bool mark_is_ours(u32 mark) { return (mark & MARK_MAGIC) != 0; }
static inline u32  mark_req_mask(u32 mark) { return (mark >> MARK_REQ_SHIFT) & 0x7u; }
static inline u32  mark_pkt_id(u32 mark) { return mark & MARK_ID_MASK; }

/* ---- opzionale: tabella pending solo per debug/visibilità ---- */
struct pending_ent {
	u32 pkt_id;
	u32 req_mask;
	unsigned long first_seen;
	unsigned long last_seen;
	struct hlist_node hnode;
};

#define PENDING_BITS 12
static DEFINE_HASHTABLE(pending_ht, PENDING_BITS);
static DEFINE_SPINLOCK(pending_lock);

static unsigned int poll_ms = 50;
static unsigned int pending_timeout_s = 5;

module_param(poll_ms, uint, 0644);
MODULE_PARM_DESC(poll_ms, "Polling interval (ms) for checking deferred work completion");

module_param(pending_timeout_s, uint, 0644);
MODULE_PARM_DESC(pending_timeout_s, "Timeout (s) after which pending entry is dropped");

static void pending_add_or_refresh(u32 pkt_id, u32 req_mask)
{
	struct pending_ent *e;

	hash_for_each_possible(pending_ht, e, hnode, pkt_id) {
		if (e->pkt_id == pkt_id) {
			e->req_mask |= (req_mask & 0x7u);
			e->last_seen = jiffies;
			return;
		}
	}

	e = kzalloc(sizeof(*e), GFP_ATOMIC);
	if (!e)
		return;

	e->pkt_id = pkt_id;
	e->req_mask = req_mask & 0x7u;
	e->first_seen = jiffies;
	e->last_seen = jiffies;
	hash_add(pending_ht, &e->hnode, pkt_id);
}

static void pending_gc(void)
{
	struct pending_ent *e;
	struct hlist_node *tmp;
	int bkt;
	unsigned long now = jiffies;
	unsigned long timeout = pending_timeout_s * HZ;

	hash_for_each_safe(pending_ht, bkt, tmp, e, hnode) {
		if (time_after(now, e->last_seen + timeout)) {
			hash_del(&e->hnode);
			kfree(e);
		}
	}
}

static void poll_workfn(struct work_struct *w);
static DECLARE_DELAYED_WORK(poll_work, poll_workfn);

static void poll_workfn(struct work_struct *w)
{
	spin_lock_bh(&pending_lock);
	pending_gc();
	spin_unlock_bh(&pending_lock);

	schedule_delayed_work(&poll_work, msecs_to_jiffies(poll_ms));
}

/* ---- Netfilter hook ---- */
static unsigned int dw_nf_prerouting(void *priv,
				    struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	u32 mark, pkt_id, req, done;
	int verdict;

	if (!skb)
		return NF_ACCEPT;

	if (dw_is_bypass_skb(skb))
		return NF_ACCEPT;

	mark = skb->mark;
	if (!mark_is_ours(mark))
		return NF_ACCEPT;

	req = mark_req_mask(mark);
	pkt_id = mark_pkt_id(mark);
	if (!req || !pkt_id)
		return NF_ACCEPT;

	/* se già finito: decidi qui (fast-path) */
	if (dw_are_done(pkt_id, req, &done)) {
		verdict = dw_get_verdict(pkt_id);
		if (verdict == 2) /* DROP */
			return NF_DROP;
		return NF_ACCEPT;
	}

	/* non finito: bufferizza una copia e ferma skb */
	if (dw_buffer_marked_skb(skb, pkt_id, req, mark) < 0) {
		pr_err("buffer failed pkt_id=%u req=0x%x\n", pkt_id, req);
		return NF_DROP;
	}

	spin_lock_bh(&pending_lock);
	pending_add_or_refresh(pkt_id, req);
	spin_unlock_bh(&pending_lock);

	return NF_STOLEN;
}

static struct nf_hook_ops nfho = {
	.hook     = dw_nf_prerouting,
	.pf       = PF_INET,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static int __init dw_nf_init(void)
{
	int ret;

	ret = nf_register_net_hook(&init_net, &nfho);
	if (ret) {
		pr_err("nf_register_net_hook failed: %d\n", ret);
		return ret;
	}

	schedule_delayed_work(&poll_work, msecs_to_jiffies(poll_ms));
	pr_info("loaded (poll_ms=%u timeout_s=%u)\n", poll_ms, pending_timeout_s);
	return 0;
}

static void __exit dw_nf_exit(void)
{
	struct pending_ent *e;
	struct hlist_node *tmp;
	int bkt;

	cancel_delayed_work_sync(&poll_work);
	nf_unregister_net_hook(&init_net, &nfho);

	spin_lock_bh(&pending_lock);
	hash_for_each_safe(pending_ht, bkt, tmp, e, hnode) {
		hash_del(&e->hnode);
		kfree(e);
	}
	spin_unlock_bh(&pending_lock);

	pr_info("unloaded\n");
}

module_init(dw_nf_init);
module_exit(dw_nf_exit);
