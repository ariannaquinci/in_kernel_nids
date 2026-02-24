// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include "deferred_work.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("Netfilter PREROUTING: buffer until deferred analyses complete, drop on malicious verdict");

static atomic_t nf_bypass_seen = ATOMIC_INIT(0);
static const char * const corr_miss_log_ifname = "enp7s0";

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

	/* reinjected packets bypass all logic */
	if (dw_is_bypass_skb(skb)) {
		int n = atomic_inc_return(&nf_bypass_seen);
		pr_info("bypass reinjected skb count=%d mark=0x%x -> accept\n", n, skb->mark);
		skb->mark = 0;
		return NF_ACCEPT;
	}

	/* solo IPv4/UDP */
	if (!skb_build_key_ipv4_udp(skb, &key))
		return NF_ACCEPT;

	/* consuma correlazione prodotta in XDP */
	if (!dw_meta_get_and_del(&key, &pkt_id, &req_mask)) {
		if (in_dev && !strcmp(in_dev->name, corr_miss_log_ifname))
			pr_info("corr miss if=%s ifindex=%d key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
				in_dev->name, in_dev->ifindex,
				ntohl(key.saddr), ntohl(key.daddr),
				ntohs(key.sport), ntohs(key.dport),
				ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
		return NF_ACCEPT;
	}

	pr_info("corr hit key -> pkt_id=%u req=0x%x\n", pkt_id, req_mask);

	verdict = dw_get_verdict(pkt_id);
	if (verdict == DW_VERDICT_DROP) {
		pr_info("nf verdict DROP pkt_id=%u (drop immediato)\n", pkt_id);
		return NF_DROP;
	}

	/*
	 * Preserve per-flow order: all correlated non-DROP packets are buffered.
	 * Delivery worker drains each flow FIFO only from the flow head.
	 */
	if (dw_are_done(pkt_id, req_mask, NULL))
		pr_info("nf analyses done pkt_id=%u req=0x%x verdict=PASS -> buffering (ordered delivery)\n",
			pkt_id, req_mask);
	else
		pr_info("nf analyses pending pkt_id=%u req=0x%x -> buffering\n", pkt_id, req_mask);

	if (dw_buffer_marked_skb(skb, pkt_id, req_mask, 0) < 0) {
		pr_err("nf buffer failed pkt_id=%u req=0x%x\n", pkt_id, req_mask);
		return NF_DROP;
	}

	return NF_STOLEN;
}

static struct nf_hook_ops nfho = {
	.hook     = dw_nf_prerouting,
	.pf       = PF_INET,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static int __init netfilter_hook_init(void)
{
	int ret = nf_register_net_hook(&init_net, &nfho);
	if (ret) {
		pr_err("nf_register_net_hook failed: %d\n", ret);
		return ret;
	}
	pr_info("loaded\n");
	return 0;
}

static void __exit netfilter_hook_exit(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	pr_info("unloaded\n");
}

module_init(netfilter_hook_init);
module_exit(netfilter_hook_exit);
