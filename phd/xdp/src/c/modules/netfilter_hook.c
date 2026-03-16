// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_queue.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include "deferred_work.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("Netfilter PREROUTING: buffer until deferred analyses complete, drop on malicious verdict");

static const unsigned int dw_nf_queue_num = 0;

#define DW_NFQ_CB_MAGIC 0xC0DEF00D

struct dw_nfq_cb {
	u32 magic;
	u32 pkt_id;
	u32 req_mask;
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
	u32 done = 0;
	int rc;

	if (!entry || !entry->skb)
		return -EINVAL;

	skb = entry->skb;
	meta = *dw_nfqcb(skb);
	if (meta.magic != DW_NFQ_CB_MAGIC) {
		pr_err("nfqueue entry missing metadata on queue=%u -> drop\n", queuenum);
		return -EINVAL;
	}

	memset(skb->cb, 0, sizeof(skb->cb));

	rc = dw_buffer_nfqueue_entry(entry, meta.pkt_id, meta.req_mask);
	if (rc < 0) {
		pr_err("nfqueue buffer failed pkt_id=%u req=0x%x rc=%d\n",
		       meta.pkt_id, meta.req_mask, rc);
		nf_reinject(entry, NF_DROP);
		return 0;
	}
	if (rc == DW_NFQ_DROPPED) {
		pr_info("nfqueue immediate drop pkt_id=%u req=0x%x: verdict already DROP\n",
			meta.pkt_id, meta.req_mask);
		return 0;
	}

	if (!dw_are_done(meta.pkt_id, meta.req_mask, &done))
		pr_info("nfqueue buffered pkt_id=%u req=0x%x done=0x%x: analyses not finished yet\n",
			meta.pkt_id, meta.req_mask, done);
	else
		pr_info("nfqueue buffered pkt_id=%u req=0x%x done=0x%x: queued for ordered delivery\n",
			meta.pkt_id, meta.req_mask, done);

	return 0;
}

static const struct nf_queue_handler dw_qh = {
	.outfn = dw_nfqueue_outfn,
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

static unsigned int dw_nf_prerouting(void *priv,
				    struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	struct dw_pkt_key key;
	const struct net_device *in_dev = state ? state->in : NULL;
	u32 pkt_id, req_mask;
	int verdict;

	if (!skb)
		return NF_ACCEPT;

	/* solo IPv4/UDP */
	if (!skb_build_key_ipv4_udp(skb, &key))
		return NF_ACCEPT;

	/* consuma correlazione prodotta in XDP */
	if (!dw_meta_get_and_del(&key, &pkt_id, &req_mask)) {
		pr_info("corr miss if=%s ifindex=%d key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
			in_dev ? in_dev->name : "?",
			in_dev ? in_dev->ifindex : -1,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
		return NF_ACCEPT;
	}

	pr_info("corr hit pkt_id=%u req=0x%x key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
		pkt_id, req_mask,
		ntohl(key.saddr), ntohl(key.daddr),
		ntohs(key.sport), ntohs(key.dport),
		ntohs(key.ip_id), ntohs(key.udp_len), key.proto);

	verdict = dw_get_verdict(pkt_id);
	if (verdict == DW_VERDICT_DROP) {
		pr_info("nf verdict DROP pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u (drop immediato)\n",
			pkt_id,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
		return NF_DROP;
	}

	/*
	 * Preserve per-flow order: all correlated non-DROP packets are buffered.
	 * Delivery worker drains each flow FIFO only from the flow head.
	 */
	if (dw_are_done(pkt_id, req_mask, NULL))
		pr_info("nf analyses done pkt_id=%u req=0x%x key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u verdict=PASS -> queue (ordered delivery)\n",
			pkt_id, req_mask,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
	else
		pr_info("nf analyses pending pkt_id=%u req=0x%x key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u -> queue\n",
			pkt_id, req_mask,
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);

	memset(skb->cb, 0, sizeof(skb->cb));
	dw_nfqcb(skb)->magic = DW_NFQ_CB_MAGIC;
	dw_nfqcb(skb)->pkt_id = pkt_id;
	dw_nfqcb(skb)->req_mask = req_mask & DW_REQ_MASK_3;

	return NF_QUEUE_NR(dw_nf_queue_num);
}

static struct nf_hook_ops nfho = {
	.hook     = dw_nf_prerouting,
	.pf       = PF_INET,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static int __init netfilter_hook_init(void)
{
	int ret;

	nf_register_queue_handler(&dw_qh);

	ret = nf_register_net_hook(&init_net, &nfho);
	if (ret) {
		nf_unregister_queue_handler();
		pr_err("nf_register_net_hook failed: %d\n", ret);
		return ret;
	}
	pr_info("loaded\n");
	return 0;
}

static void __exit netfilter_hook_exit(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	nf_unregister_queue_handler();
	pr_info("unloaded\n");
}

module_init(netfilter_hook_init);
module_exit(netfilter_hook_exit);
