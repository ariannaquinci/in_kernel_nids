// // SPDX-License-Identifier: GPL-2.0
// #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/kernel.h>

// #include <linux/jiffies.h>
// #include <linux/spinlock.h>
// #include <linux/slab.h>
// #include <linux/hashtable.h>

// #include <linux/skbuff.h>
// #include <linux/netfilter.h>
// #include <linux/netfilter_ipv4.h>

// #include "deferred_work.h"   /* dw_is_bypass_skb, dw_are_done, dw_buffer_marked_skb */


// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("Arianna Quinci");
// /*
//  * Must match your deferred_work.ko layout.
//  * (same defines as in your module)
//  */
// #define MARK_MAGIC     0x80000000u
// #define MARK_REQ_SHIFT 24
// #define MARK_ID_MASK   0x00FFFFFFu

// static inline bool mark_is_ours(u32 mark)
// {
// 	return (mark & MARK_MAGIC) != 0;
// }

// static inline u32 mark_req_mask(u32 mark)
// {
// 	return (mark >> MARK_REQ_SHIFT) & 0x7u;
// }

// static inline u32 mark_pkt_id(u32 mark)
// {
// 	return mark & MARK_ID_MASK;
// }

// /* ---- pending table for periodic polling (optional, for visibility/debug) ---- */

// struct pending_ent {
// 	u32 pkt_id;
// 	u32 req_mask;
// 	unsigned long first_seen;
// 	unsigned long last_seen;
// 	struct hlist_node hnode;
// };

// #define PENDING_BITS 12
// static DEFINE_HASHTABLE(pending_ht, PENDING_BITS);
// static DEFINE_SPINLOCK(pending_lock);

// /* poll interval + timeout */
// static unsigned int poll_ms = 50;        /* configurable via module param */
// static unsigned int pending_timeout_s = 5;

// module_param(poll_ms, uint, 0644);
// MODULE_PARM_DESC(poll_ms, "Polling interval (ms) for checking deferred work completion");

// module_param(pending_timeout_s, uint, 0644);
// MODULE_PARM_DESC(pending_timeout_s, "Timeout (s) after which pending entry is dropped");

// static void pending_add_or_refresh(u32 pkt_id, u32 req_mask)
// {
// 	struct pending_ent *e;

// 	hash_for_each_possible(pending_ht, e, hnode, pkt_id) {
// 		if (e->pkt_id == pkt_id) {
// 			e->req_mask |= (req_mask & 0x7u);
// 			e->last_seen = jiffies;
// 			return;
// 		}
// 	}

// 	e = kzalloc(sizeof(*e), GFP_ATOMIC);
// 	if (!e)
// 		return;

// 	e->pkt_id = pkt_id;
// 	e->req_mask = req_mask & 0x7u;
// 	e->first_seen = jiffies;
// 	e->last_seen = jiffies;
// 	hash_add(pending_ht, &e->hnode, e->pkt_id);
// }

// static void pending_del(u32 pkt_id)
// {
// 	struct pending_ent *e;

// 	hash_for_each_possible(pending_ht, e, hnode, pkt_id) {
// 		if (e->pkt_id == pkt_id) {
// 			hash_del(&e->hnode);
// 			kfree(e);
// 			return;
// 		}
// 	}
// }

// /* ---- periodic poller work ---- */

// static struct delayed_work poll_work;

// static void poll_workfn(struct work_struct *w)
// {
// 	struct pending_ent *e;
// 	struct hlist_node *tmp;
// 	int bkt;

// 	spin_lock_bh(&pending_lock);
// 	hash_for_each_safe(pending_ht, bkt, tmp, e, hnode) {
// 		u32 done = 0;
// 		bool ok;

// 		ok = dw_are_done(e->pkt_id, e->req_mask, &done);

// 		if (ok) {
// 			pr_info("pkt_id=%u done (req=0x%x done=0x%x)\n",
// 				e->pkt_id, e->req_mask, done);
// 			hash_del(&e->hnode);
// 			kfree(e);
// 			continue;
// 		}
// 		pr_info("not done");
// 		/* not done -> timeout handling */
// 		if (time_after(jiffies, e->first_seen + pending_timeout_s * HZ)) {
// 			pr_warn("pkt_id=%u timeout (req=0x%x done=0x%x) dropping tracking\n",
// 				e->pkt_id, e->req_mask, done);
// 			hash_del(&e->hnode);
// 			kfree(e);

// 			/*
// 			 * IMPORTANT:
// 			 * We cannot "re-schedule analyses" from here because dw_register_and_schedule()
// 			 * is a __bpf_kfunc (not exported). If you want re-scheduling, export a wrapper
// 			 * from deferred_work.ko and call it here.
// 			 */
// 		}
// 	}
// 	spin_unlock_bh(&pending_lock);

// 	schedule_delayed_work(&poll_work, msecs_to_jiffies(poll_ms));
// }

// /* ---- Netfilter hook ---- */

// static unsigned int dw_nf_prerouting(void *priv,
// 				    struct sk_buff *skb,
// 				    const struct nf_hook_state *state)
// {
// 	u32 mark, pkt_id, req;

// 	if (!skb)
// 		return NF_ACCEPT;

// 	/* Avoid infinite loop: reinjected skb has bypass CB */
// 	if (dw_is_bypass_skb(skb))
// 		return NF_ACCEPT;

// 	mark = skb->mark;
// 	if (!mark_is_ours(mark))
// 		return NF_ACCEPT;

// 	req = mark_req_mask(mark);
// 	pkt_id = mark_pkt_id(mark);

// 	if (!req || !pkt_id) {
// 		/* malformed mark: let it pass or drop; here: accept */
// 		return NF_ACCEPT;
// 	}

// 	/*
// 	 * Buffer a COPY inside deferred_work.ko and stop this skb.
// 	 * deferred_work.ko will reinject later when analyses are done.
// 	 */
// 	if (dw_buffer_marked_skb(skb, pkt_id, req, mark) < 0) {
// 		pr_err("buffer failed pkt_id=%u req=0x%x\n", pkt_id, req);
// 		return NF_DROP;
// 	}

// 	/* track it for periodic check/logging */
// 	spin_lock_bh(&pending_lock);
// 	pending_add_or_refresh(pkt_id, req);
// 	spin_unlock_bh(&pending_lock);

// 	/* stop original skb: we've copied it, and we'll reinject later */
// 	return NF_STOLEN;
// }

// static struct nf_hook_ops nfho = {
// 	.hook     = dw_nf_prerouting,
// 	.pf       = PF_INET,
// 	.hooknum  = NF_INET_PRE_ROUTING,
// 	.priority = NF_IP_PRI_FIRST,
// };

// /* ---- init/exit ---- */

// static int __init dw_nf_init(void)
// {
// 	int ret;

// 	ret = nf_register_net_hook(&init_net, &nfho);
// 	if (ret) {
// 		pr_err("nf_register_net_hook failed: %d\n", ret);
// 		return ret;
// 	}

// 	INIT_DELAYED_WORK(&poll_work, poll_workfn);
// 	schedule_delayed_work(&poll_work, msecs_to_jiffies(poll_ms));

// 	pr_info("loaded (poll_ms=%u timeout_s=%u)\n", poll_ms, pending_timeout_s);
// 	return 0;
// }

// static void __exit dw_nf_exit(void)
// {
// 	struct pending_ent *e;
// 	struct hlist_node *tmp;
// 	int bkt;

// 	cancel_delayed_work_sync(&poll_work);
// 	nf_unregister_net_hook(&init_net, &nfho);

// 	spin_lock_bh(&pending_lock);
// 	hash_for_each_safe(pending_ht, bkt, tmp, e, hnode) {
// 		hash_del(&e->hnode);
// 		kfree(e);
// 	}
// 	spin_unlock_bh(&pending_lock);

// 	pr_info("unloaded\n");
// }

// MODULE_DESCRIPTION("Netfilter PREROUTING hook that buffers marked packets and polls deferred work completion");

// module_init(dw_nf_init);
// module_exit(dw_nf_exit);


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
