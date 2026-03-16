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
#include <linux/if_ether.h>

#include <linux/skbuff.h>
#include <linux/hashtable.h>
#include <net/netfilter/nf_queue.h>

#include <net/ip.h>

#include "deferred_work.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");

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

/* -------- XDP packet snapshots: pkt_id -> frame copy -------- */

struct pkt_snap_ent {
	u32 pkt_id;
	u32 frame_len;
	u32 cap_len;
	unsigned long ts_jiffies;
	struct hlist_node hnode;
	u8 data[];
};

#define SNAP_BITS 12
static DEFINE_HASHTABLE(snap_ht, SNAP_BITS);
static DEFINE_SPINLOCK(snap_lock);

/* -------- per-flow buffering (FIFO per preservare ordine del flow) -------- */

struct dw_flow_key {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8  proto;
	u8  pad1;
	u16 pad2;
} __aligned(4);

struct flow_ent {
	struct dw_flow_key key;
	struct list_head q;
	unsigned long last_seen_jiffies;
	struct hlist_node hnode;
};

struct dw_buf_ent {
	struct list_head node;
	struct nf_queue_entry *qent;
	u32 pkt_id;
	u32 req_mask;
};

#define FLOW_BITS 12
static DEFINE_HASHTABLE(flow_ht, FLOW_BITS);
static DEFINE_SPINLOCK(flow_lock);

static struct workqueue_struct *dw_wq;
static struct work_struct deliver_work;

/* -------- stats/debug -------- */

static atomic_t st_pending   = ATOMIC_INIT(0);
static atomic_t st_delivered = ATOMIC_INIT(0);
static atomic_t st_dropped   = ATOMIC_INIT(0);
static atomic_t rr_cpu       = ATOMIC_INIT(0);

#define DW_DUMMY_NEEDLE "malicious"

/* -------- helpers -------- */

struct dw_vlan_hdr {
	__be16 tci;
	__be16 enc_proto;
} __packed;

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

static struct pkt_snap_ent *snap_lookup_locked(u32 pkt_id)
{
	struct pkt_snap_ent *e;

	hash_for_each_possible(snap_ht, e, hnode, pkt_id) {
		if (e->pkt_id == pkt_id)
			return e;
	}
	return NULL;
}

static void snap_drop(u32 pkt_id)
{
	struct pkt_snap_ent *e;

	spin_lock_bh(&snap_lock);
	e = snap_lookup_locked(pkt_id);
	if (e)
		hash_del(&e->hnode);
	spin_unlock_bh(&snap_lock);

	kfree(e);
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

	return buf_contains_needle(frame + payload_off, payload_len, needle);
}

static int snapshot_pkt_payload_contains(u32 pkt_id, const char *needle, bool *found_out)
{
	struct pkt_snap_ent *e;
	bool found;

	if (!found_out)
		return -EINVAL;

	spin_lock_bh(&snap_lock);
	e = snap_lookup_locked(pkt_id);
	if (e)
		hash_del(&e->hnode);
	spin_unlock_bh(&snap_lock);

	if (!e)
		return -ENOENT;

	found = frame_udp_payload_contains(e->data, e->cap_len, needle);
	kfree(e);

	*found_out = found;
	return 0;
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

void dw_note_payload_signature(u32 pkt_id, u32 req_mask, bool is_malicious)
{
	struct pkt_state *st;
	u32 req, done, hits;

	req = req_mask & DW_REQ_MASK_3;
	if (!pkt_id || !req || !is_malicious)
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

static struct flow_ent *flow_lookup_locked(const struct dw_flow_key *key, u32 h)
{
	struct flow_ent *fe;

	hash_for_each_possible(flow_ht, fe, hnode, h) {
		if (flow_key_equal(&fe->key, key))
			return fe;
	}
	return NULL;
}

static struct flow_ent *flow_get_or_create_locked(const struct dw_flow_key *key, u32 h)
{
	struct flow_ent *fe;

	fe = flow_lookup_locked(key, h);
	if (fe) {
		fe->last_seen_jiffies = jiffies;
		return fe;
	}

	fe = kzalloc(sizeof(*fe), GFP_ATOMIC);
	if (!fe)
		return NULL;

	memcpy(&fe->key, key, sizeof(*key));
	INIT_LIST_HEAD(&fe->q);
	fe->last_seen_jiffies = jiffies;
	hash_add(flow_ht, &fe->hnode, h);

	return fe;
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

static __bpf_kfunc int dw_pkt_snapshot_put(const u8 *data, u32 len, u32 pkt_id)
{
	struct pkt_snap_ent *e, *old;
	u32 cap_len;

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
	memcpy(e->data, data, cap_len);

	old = NULL;
	spin_lock_bh(&snap_lock);
	old = snap_lookup_locked(pkt_id);
	if (old)
		hash_del(&old->hnode);
	hash_add(snap_ht, &e->hnode, pkt_id);
	spin_unlock_bh(&snap_lock);

	kfree(old);

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

static void dw_try_deliver_ready(void)
{
	struct flow_ent *fe;
	struct dw_buf_ent *be;
	struct hlist_node *tmp;
	struct nf_queue_entry *qent;
	int bkt;

	spin_lock_bh(&flow_lock);
	hash_for_each_safe(flow_ht, bkt, tmp, fe, hnode) {
		for (;;) {
			u32 pkt_id, req, done;
			int verdict;

			be = list_first_entry_or_null(&fe->q, struct dw_buf_ent, node);
			if (!be)
				break;

			pkt_id = be->pkt_id;
			req = be->req_mask;
			verdict = dw_get_verdict(pkt_id);

			if (verdict == DW_VERDICT_DROP) {
				list_del(&be->node);
				pr_info("deliver flow-head pkt_id=%u req=0x%x verdict=DROP -> drop queued packet\n",
					pkt_id, req);
				spin_unlock_bh(&flow_lock);
				snap_drop(pkt_id);
				nf_reinject(be->qent, NF_DROP);
				kfree(be);
				atomic_dec(&st_pending);
				atomic_inc(&st_dropped);
				spin_lock_bh(&flow_lock);
				fe->last_seen_jiffies = jiffies;
				continue;
			}

			if (!dw_are_done(pkt_id, req, &done)) {
				pr_info("deliver flow-head pkt_id=%u req=0x%x done=0x%x -> block flow head\n",
					pkt_id, req, done);
				break;
			}

			list_del(&be->node);
			pr_info("deliver flow-head pkt_id=%u req=0x%x done=0x%x verdict=PASS -> reinject\n",
				pkt_id, req, done);
			spin_unlock_bh(&flow_lock);
			snap_drop(pkt_id);

			qent = be->qent;
			nf_reinject(qent, NF_ACCEPT);
			atomic_inc(&st_delivered);
			kfree(be);
			atomic_dec(&st_pending);

			spin_lock_bh(&flow_lock);
			fe->last_seen_jiffies = jiffies;
		}

		if (list_empty(&fe->q)) {
			hash_del(&fe->hnode);
			kfree(fe);
		}
	}
	spin_unlock_bh(&flow_lock);
}

static void deliver_workfn(struct work_struct *w)
{
	dw_try_deliver_ready();
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
		is_malicious = false;
		break;
	case DW_REQ_A3:
		//fsleep(10);
		if(aw->pkt_id%5==0){
			printk("DELAIED PACKET");
			fsleep(10);
		}
		sig_rc = snapshot_pkt_payload_contains(aw->pkt_id, DW_DUMMY_NEEDLE,
						       &is_malicious);
		if (sig_rc < 0)
			pr_info("analysis pkt_id=%u bit=0x%x snapshot not available rc=%d, continuing\n",
				aw->pkt_id, aw->bit, sig_rc);
		if (!sig_rc)
			dw_note_payload_signature(aw->pkt_id, aw->bit, is_malicious);
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

		terminal = (hits & req_mask) || ((done & req_mask) == req_mask);
	}
	if (terminal)
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
BTF_ID_FLAGS(func, dw_pkt_snapshot_put,      0)
BTF_SET8_END(dw_kfunc_set)

static const struct btf_kfunc_id_set dw_kfunc_ids = {
	.owner = THIS_MODULE,
	.set   = &dw_kfunc_set,
};

/* -------- API used by Netfilter -------- */

int dw_buffer_nfqueue_entry(struct nf_queue_entry *entry, u32 pkt_id, u32 req_mask)
{
	struct dw_buf_ent *be;
	struct dw_flow_key fkey;
	u32 h;
	struct flow_ent *fe;
	int verdict;

	if (!entry || !entry->skb)
		return -EINVAL;

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

	be = kzalloc(sizeof(*be), GFP_ATOMIC);
	if (!be) {
		atomic_inc(&st_dropped);
		return -ENOMEM;
	}
	be->qent = entry;
	be->pkt_id = pkt_id;
	be->req_mask = req_mask & DW_REQ_MASK_3;

	h = jhash(&fkey, sizeof(fkey), 0);
	spin_lock_bh(&flow_lock);
	fe = flow_get_or_create_locked(&fkey, h);
	if (!fe) {
		spin_unlock_bh(&flow_lock);
		kfree(be);
		atomic_inc(&st_dropped);
		return -ENOMEM;
	}
	if (!nf_queue_entry_get_refs(entry)) {
		spin_unlock_bh(&flow_lock);
		kfree(be);
		atomic_inc(&st_dropped);
		return -EINVAL;
	}
	list_add_tail(&be->node, &fe->q);
	fe->last_seen_jiffies = jiffies;
	spin_unlock_bh(&flow_lock);

	atomic_inc(&st_pending);
	queue_work(dw_wq, &deliver_work);
	return DW_NFQ_BUFFERED;
}
EXPORT_SYMBOL_GPL(dw_buffer_nfqueue_entry);

/* -------- module init/exit -------- */

static int __init deferred_init(void)
{
	int ret;

	hash_init(state_ht);
	hash_init(meta_ht);
	hash_init(flow_ht);
	hash_init(snap_ht);

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
	struct flow_ent *fe;
	struct dw_buf_ent *be, *be_tmp;
	struct pkt_snap_ent *se;
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

	/* cleanup flow_ht (per-flow buffered items) */
	spin_lock_bh(&flow_lock);
	hash_for_each_safe(flow_ht, bkt, tmp, fe, hnode) {
		hash_del(&fe->hnode);
		list_for_each_entry_safe(be, be_tmp, &fe->q, node) {
			list_del(&be->node);
			nf_queue_entry_free(be->qent);
			kfree(be);
		}
		kfree(fe);
	}
	spin_unlock_bh(&flow_lock);

	/* cleanup snap_ht (XDP frame snapshots) */
	spin_lock_bh(&snap_lock);
	hash_for_each_safe(snap_ht, bkt, tmp, se, hnode) {
		hash_del(&se->hnode);
		kfree(se);
	}
	spin_unlock_bh(&snap_lock);

	pr_info("unloaded\n");
}

module_init(deferred_init);
module_exit(deferred_exit);
