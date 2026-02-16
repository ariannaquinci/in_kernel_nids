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
MODULE_DESCRIPTION("Netfilter PREROUTING: consumes XDP correlation and buffers skb until deferred work completes");

/* optional: verbose */
static bool verbose = true;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Enable verbose pr_info logs");

/* Extract the same key from skb */
static bool skb_build_key_ipv4_udp(struct sk_buff *skb, struct dw_pkt_key *key)
{
	struct iphdr _iph, *iph;
	struct udphdr _uh, *uh;
	unsigned int ip_off;
	unsigned int l4_off;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph)
		return false;

	if (iph->version != 4)
		return false;

	if (iph->protocol != IPPROTO_UDP)
		return false;

	ip_off = 0;
	l4_off = ip_off + (iph->ihl * 4);

	uh = skb_header_pointer(skb, l4_off, sizeof(_uh), &_uh);
	if (!uh)
		return false;

	/* fill key */
	memset(key, 0, sizeof(struct dw_pkt_key));
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
	u32 pkt_id, req_mask;

	if (!skb)
		return NF_ACCEPT;

	/* avoid loops: reinjected packets bypass */
	if (dw_is_bypass_skb(skb))
		return NF_ACCEPT;

	/* only IPv4/UDP packets are correlated in this design */
	if (!skb_build_key_ipv4_udp(skb, &key))
		return NF_ACCEPT;

	/* Try to consume correlation produced in XDP */
	if (!dw_meta_get_and_del(&key, &pkt_id, &req_mask))
		return NF_ACCEPT;

	/*
	 * We found a correlated pkt_id/req_mask:
	 * buffer a copy in deferred_analysis and stop original skb.
	 */
	if (dw_buffer_marked_skb(skb, pkt_id, req_mask, 0 /* mark unused */) < 0) {
		pr_err("buffer failed pkt_id=%u req=0x%x\n", pkt_id, req_mask);
		return NF_DROP;
	}

	if (verbose)
		pr_info("buffered pkt_id=%u req=0x%x\n", pkt_id, req_mask);

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
