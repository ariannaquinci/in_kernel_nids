// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_queue.h>
#include <net/net_namespace.h>
#include <linux/nsproxy.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>

#include "deferred_work.h"
#include "dw_print.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("UDP Netfilter LOCAL_IN path: buffer until deferred analyses complete, drop on malicious verdict");

static const unsigned int dw_nf_queue_num = 0;
static bool dw_queue_handler_registered;
static bool dw_pernet_registered;

#define DW_NFQ_CB_MAGIC 0xC0DEF00D

struct dw_nfq_cb {
	u32 magic;
	u32 pkt_id;
} __aligned(4);

static inline struct dw_nfq_cb *dw_nfqcb(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct dw_nfq_cb) > sizeof(skb->cb));
	return (struct dw_nfq_cb *)skb->cb;
}

static int dw_nfqueue_outfn(struct nf_queue_entry *entry, unsigned int queuenum)
{
	struct sk_buff *skb;
	struct dw_nfq_cb meta;
	int rc;

	if (!entry || !entry->skb) {
		pr_err("nfqueue entry invalid on queue=%u\n", queuenum);
		return 0;
	}

	skb = entry->skb;
	meta = *dw_nfqcb(skb);
	if (meta.magic != DW_NFQ_CB_MAGIC) {
		pr_err("nfqueue entry missing metadata on queue=%u -> accept\n", queuenum);
		nf_reinject(entry, NF_ACCEPT);
		return 0;
	}

	memset(skb->cb, 0, sizeof(skb->cb));

	rc = dw_buffer_nfqueue_entry(entry, meta.pkt_id);
	if (rc < 0) {
		pr_err("nfqueue buffer failed pkt_id=%u rc=%d\n",
		       meta.pkt_id, rc);
		dw_udp_cleanup_packet(meta.pkt_id);
		nf_reinject(entry, NF_DROP);
		return 0;
	}
	if (rc == DW_NFQ_DROPPED) {
		pr_debug("nfqueue immediate drop pkt_id=%u: verdict already DROP\n",
			meta.pkt_id);
		return 0;
	}

	if (!dw_analysis_done(meta.pkt_id))
		pr_debug("nfqueue buffered pkt_id=%u: analysis not finished yet\n",
			meta.pkt_id);
	else
		pr_debug("nfqueue buffered pkt_id=%u: queued for ordered delivery\n",
			meta.pkt_id);

	return 0;
}

static void dw_nfqueue_hook_drop(struct net *net)
{
	/*
	 * nf_unregister_net_hook() expects a valid nf_hook_drop callback while
	 * a queue handler is registered. Keep it non-recursive here and let the
	 * explicit dw_quiesce_nfqueue() in module exit drain queued packets.
	 */
	dw_begin_nfqueue_stop();
}

static const struct nf_queue_handler dw_qh = {
	.outfn = dw_nfqueue_outfn,
	.nf_hook_drop = dw_nfqueue_hook_drop,
};

static bool skb_build_key_ipv4_udp(struct sk_buff *skb, struct dw_pkt_key *key)
{
	struct iphdr _iph, *iph;
	struct udphdr _uh, *uh;
	unsigned int l4_off;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return false;

	l4_off = iph->ihl * 4;
	uh = skb_header_pointer(skb, l4_off, sizeof(_uh), &_uh);
	if (!uh)
		return false;

	memset(key, 0, sizeof(*key));
	key->saddr   = iph->saddr;
	key->daddr   = iph->daddr;
	key->sport   = uh->source;
	key->dport   = uh->dest;
	key->ip_id   = iph->id;
	key->udp_len = uh->len;
	key->proto   = iph->protocol;
	return true;
}

static bool skb_is_reassembled_ipv4_fragment(const struct sk_buff *skb)
{
	const struct inet_skb_parm *ipcb;

	if (!skb)
		return false;

	ipcb = IPCB(skb);
	return (ipcb->flags & IPSKB_FRAG_COMPLETE) || ipcb->frag_max_size;
}

static unsigned int dw_nf_local_in(void *priv,
				   struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	struct dw_pkt_key key;
	const struct net_device *in_dev = state ? state->in : NULL;
	u32 pkt_id;
	int verdict;

	if (!skb)
		return NF_ACCEPT;

	/* solo IPv4/UDP */
	if (!skb_build_key_ipv4_udp(skb, &key))
		return NF_ACCEPT;

	/* consuma correlazione prodotta in XDP/netif_receive */
	if (!dw_meta_get_and_del(&key, &pkt_id)) {
		int rc;

		rc = dw_schedule_skb_ref_deferred_nometa(skb, &pkt_id);
		if (rc < 0) {
			pr_debug("corr miss zero-copy fallback schedule failed if=%s ifindex=%d flags=0x%x frag_max=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u rc=%d -> accept\n",
				in_dev ? in_dev->name : "?",
				in_dev ? in_dev->ifindex : -1,
				IPCB(skb)->flags, IPCB(skb)->frag_max_size,
				ntohl(key.saddr), ntohl(key.daddr),
				ntohs(key.sport), ntohs(key.dport),
				ntohs(key.ip_id), ntohs(key.udp_len), key.proto,
				rc);
			return NF_ACCEPT;
		}

		pr_debug("%s zero-copy fallback scheduled pkt_id=%u flags=0x%x frag_max=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
			skb_is_reassembled_ipv4_fragment(skb) ? "fragment" : "corr miss",
			pkt_id, IPCB(skb)->flags,
			IPCB(skb)->frag_max_size,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
		goto correlated;
	}

	pr_debug("corr hit pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
		pkt_id,
		ntohl(key.saddr), ntohl(key.daddr),
		ntohs(key.sport), ntohs(key.dport),
		ntohs(key.ip_id), ntohs(key.udp_len), key.proto);

correlated:
	if (dw_nfqueue_is_stopping()) {
		pr_debug("nf teardown stopping pkt_id=%u -> accept without queue\n",
			pkt_id);
		dw_udp_cleanup_packet(pkt_id);
		return NF_ACCEPT;
	}

	verdict = dw_get_verdict(pkt_id);
	if (verdict == DW_VERDICT_DROP) {
		pr_debug("nf verdict DROP pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u (drop immediato)\n",
			pkt_id,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
		dw_udp_cleanup_packet(pkt_id);
		return NF_DROP;
	}

	if (dw_udp_try_fast_accept_done(skb, pkt_id)) {
		pr_debug("nf fast PASS pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u -> accept\n",
			pkt_id,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
		return NF_ACCEPT;
	}

	/*
	 * Preserve per-flow order: all correlated non-DROP packets are buffered.
	 * Delivery worker drains each flow FIFO only from the flow head.
	 */
	if (dw_analysis_done(pkt_id))
		pr_debug("nf analysis done pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u verdict=PASS -> queue (ordered delivery)\n",
			pkt_id,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
	else
		pr_debug("nf analysis pending pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u -> queue\n",
			pkt_id,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);

	memset(skb->cb, 0, sizeof(skb->cb));
	dw_nfqcb(skb)->magic = DW_NFQ_CB_MAGIC;
	dw_nfqcb(skb)->pkt_id = pkt_id;

	return NF_QUEUE_NR(dw_nf_queue_num);
}

static struct nf_hook_ops nfho = {
	.hook     = dw_nf_local_in,
	.pf       = PF_INET,
	.hooknum  = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
};

static struct net *dw_registered_net;

static int __init netfilter_hook_init(void)
{
	int ret;

	nf_register_queue_handler(&dw_qh);
	dw_queue_handler_registered = true;

	dw_registered_net = get_net(current->nsproxy->net_ns);
	ret = nf_register_net_hook(dw_registered_net, &nfho);
	if (ret) {
		if (dw_queue_handler_registered) {
			nf_unregister_queue_handler();
			dw_queue_handler_registered = false;
		}
		put_net(dw_registered_net);
		dw_registered_net = NULL;
		pr_err("nf_register_net_hook failed: %d\n", ret);
		return ret;
	}
	dw_pernet_registered = true;
	pr_debug("loaded net=%p\n", dw_registered_net);
	return 0;
}

static void __exit netfilter_hook_exit(void)
{
	pr_debug("unload: entered netfilter_hook_exit\n");
	pr_debug("unload: begin nfqueue stop\n");
	dw_begin_nfqueue_stop();
	pr_debug("unload: completed dw_begin_nfqueue_stop\n");

	if (dw_pernet_registered) {
		pr_debug("unload: before nf_unregister_net_hook net=%p\n", dw_registered_net);
		nf_unregister_net_hook(dw_registered_net, &nfho);
		pr_debug("unload: after nf_unregister_net_hook\n");
		dw_pernet_registered = false;
		put_net(dw_registered_net);
		dw_registered_net = NULL;

		pr_debug("unload: before synchronize_net\n");
		synchronize_net();
		pr_debug("unload: after synchronize_net\n");
	}

	if (dw_queue_handler_registered) {
		pr_debug("unload: before dw_quiesce_nfqueue\n");
		dw_quiesce_nfqueue();
		pr_debug("unload: after dw_quiesce_nfqueue\n");

		pr_debug("unload: before nf_unregister_queue_handler\n");
		nf_unregister_queue_handler();
		pr_debug("unload: after nf_unregister_queue_handler\n");
		dw_queue_handler_registered = false;
	}

	pr_debug("unload: leaving netfilter_hook_exit\n");
	pr_debug("unloaded\n");
}

module_init(netfilter_hook_init);
module_exit(netfilter_hook_exit);
