// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <asm/ptrace.h>

#include "deferred_work.h"
#include "dw_print.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("UDP skb receive producer: schedule deferred analysis without XDP packet snapshot");

#define DW_NETIF_RX_SYMBOL "__netif_receive_skb_one_core"

#define DW_IP_MF 0x2000
#define DW_IP_OFFSET 0x1fff

static bool skb_parse_ipv4_udp_at_off(struct sk_buff *skb, unsigned int ip_off,
				      struct dw_pkt_key *key,
				      unsigned int *ip_off_out)
{
	struct iphdr _iph, *iph;
	struct udphdr _uh, *uh;
	unsigned int l4_off;

	iph = skb_header_pointer(skb, ip_off, sizeof(_iph), &_iph);
	if (!iph || iph->version != 4)
		return false;

	if (ntohs(iph->frag_off) & (DW_IP_MF | DW_IP_OFFSET))
		return false;

	if (iph->protocol == IPPROTO_TCP) {
		key->proto = IPPROTO_TCP;
		*ip_off_out = ip_off;
		return true;
	}

	if (iph->protocol != IPPROTO_UDP)
		return false;

	l4_off = ip_off + iph->ihl * 4;
	if (iph->ihl * 4 < sizeof(*iph))
		return false;

	uh = skb_header_pointer(skb, l4_off, sizeof(_uh), &_uh);
	if (!uh || ntohs(uh->len) <= sizeof(*uh))
		return false;

	key->saddr = iph->saddr;
	key->daddr = iph->daddr;
	key->sport = uh->source;
	key->dport = uh->dest;
	key->ip_id = iph->id;
	key->udp_len = uh->len;
	key->proto = iph->protocol;
	*ip_off_out = ip_off;
	return true;
}

static bool skb_xdp_udp_parse(struct sk_buff *skb, struct dw_pkt_key *key,
			      unsigned int *ip_off_out)
{
	struct ethhdr _eth, *eth;
	unsigned int nh_off;

	if (!skb || !key || !ip_off_out)
		return false;

	memset(key, 0, sizeof(*key));

	/*
	 * At __netif_receive_skb_one_core(), skb->data is commonly already at
	 * the network header. XDP saw the Ethernet frame earlier; skb->protocol
	 * is the stack's equivalent of the L2 protocol decision after that.
	 */
	if (skb->protocol == htons(ETH_P_IP)) {
		nh_off = skb_network_offset(skb);
		if (skb_parse_ipv4_udp_at_off(skb, nh_off, key, ip_off_out))
			return true;
	}

	if (skb->protocol != htons(ETH_P_IP))
		return false;

	eth = skb_header_pointer(skb, 0, sizeof(_eth), &_eth);
	if (!eth)
		return false;

	if (eth->h_proto != htons(ETH_P_IP))
		return false;

	nh_off = sizeof(*eth);
	return skb_parse_ipv4_udp_at_off(skb, nh_off, key, ip_off_out);
}

static bool skb_prepare_linear_udp_payload(struct sk_buff *skb, unsigned int ip_off)
{
	struct iphdr _iph, *iph;
	unsigned int pull_len;

	iph = skb_header_pointer(skb, ip_off, sizeof(_iph), &_iph);
	if (!iph)
		return false;

	pull_len = ip_off + iph->ihl * 4 + sizeof(struct udphdr);
	if (!pskb_may_pull(skb, pull_len))
		return false;

	skb_set_network_header(skb, ip_off);
	return true;
}

static int dw_netif_receive_skb_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (struct sk_buff *)regs->di;
	struct dw_pkt_key key;
	unsigned int ip_off = 0;
	u32 pkt_id;
	int rc;

	if (!skb_xdp_udp_parse(skb, &key, &ip_off)) {
		pr_debug_ratelimited("skb producer skip len=%u headlen=%u proto=0x%04x net_off=%u mac_off=%u\n",
				    skb ? skb->len : 0,
				    skb ? skb_headlen(skb) : 0,
				    skb ? ntohs(skb->protocol) : 0,
				    skb ? skb_network_offset(skb) : 0,
				    skb ? skb_mac_offset(skb) : 0);
		return 0;
	}

	if (key.proto != IPPROTO_UDP)
		return 0;

	if (!skb_prepare_linear_udp_payload(skb, ip_off)) {
		pr_debug_ratelimited("skb producer linearize header failed ip_off=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
				    ip_off, ntohl(key.saddr), ntohl(key.daddr),
				    ntohs(key.sport), ntohs(key.dport),
				    ntohs(key.ip_id), ntohs(key.udp_len),
				    key.proto);
		return 0;
	}

	rc = dw_schedule_skb_ref_deferred(skb, &key, &pkt_id);
	if (rc < 0) {
		pr_debug_ratelimited("skb producer schedule failed rc=%d key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
				    rc, ntohl(key.saddr), ntohl(key.daddr),
				    ntohs(key.sport), ntohs(key.dport),
				    ntohs(key.ip_id), ntohs(key.udp_len),
				    key.proto);
		return 0;
	}

	if (ntohs(key.sport) == 5005 || ntohs(key.dport) == 5005)
		pr_debug("skb producer scheduled pkt_id=%u ip_off=%u headlen=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
			pkt_id, ip_off, skb_headlen(skb),
			ntohl(key.saddr), ntohl(key.daddr),
			ntohs(key.sport), ntohs(key.dport),
			ntohs(key.ip_id), ntohs(key.udp_len), key.proto);

	pr_debug_ratelimited("skb producer scheduled pkt_id=%u key s=%08x d=%08x sp=%u dp=%u id=%u len=%u proto=%u\n",
			    pkt_id, ntohl(key.saddr), ntohl(key.daddr),
			    ntohs(key.sport), ntohs(key.dport),
			    ntohs(key.ip_id), ntohs(key.udp_len), key.proto);
	return 0;
}

static struct kprobe dw_netif_receive_skb_probe = {
	.symbol_name = DW_NETIF_RX_SYMBOL,
	.pre_handler = dw_netif_receive_skb_pre,
};

static int __init netif_receive_udp_hook_init(void)
{
	int ret;

	ret = register_kprobe(&dw_netif_receive_skb_probe);
	if (ret) {
		pr_err("register_kprobe(%s) failed: %d\n", DW_NETIF_RX_SYMBOL, ret);
		return ret;
	}

	pr_debug("loaded kprobe %s\n", DW_NETIF_RX_SYMBOL);
	return 0;
}

static void __exit netif_receive_udp_hook_exit(void)
{
	unregister_kprobe(&dw_netif_receive_skb_probe);
	pr_debug("unloaded\n");
}

module_init(netif_receive_udp_hook_init);
module_exit(netif_receive_udp_hook_exit);
