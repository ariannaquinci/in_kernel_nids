// udp_nfqueue_gate.c
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/printk.h>

#include "dw_print.h"
#include "nids_shared.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");

#define Q_ORDER 10
#define Q_SIZE  (1U << Q_ORDER)
#define Q_MASK  (Q_SIZE - 1)

#define TIMEOUT_MS 1000
#define POLL_MS    10

enum slot_state {
    SLOT_EMPTY = 0,
    SLOT_BUSY  = 1,
    SLOT_FULL  = 2,
};

struct pkt_slot {
    u32 state;                /* cmpxchg su questo */
    u32 key;
    unsigned long timeout;
    struct sk_buff *skb;      /* clone posseduto dal gate */
};

static struct pkt_slot ring[Q_SIZE];
static atomic64_t prod_idx;

static struct workqueue_struct *gate_wq;
static void gate_worker(struct work_struct *work);
static DECLARE_DELAYED_WORK(gate_dwork, gate_worker);

static inline bool ring_has_full(void)
{
    int i;
    for (i = 0; i < Q_SIZE; i++) {
        if (READ_ONCE(ring[i].state) == SLOT_FULL)
            return true;
    }
    return false;
}

static void gate_worker(struct work_struct *work)
{
    int i;
    bool again = false;

    for (i = 0; i < Q_SIZE; i++) {
        struct pkt_slot *s = &ring[i];
        struct sk_buff *skb;
        u32 key;
        struct nids_status st;
        int ret;
        bool expired;

        /* Prova a “prendere” lo slot: FULL -> BUSY */
        if (cmpxchg(&s->state, SLOT_FULL, SLOT_BUSY) != SLOT_FULL)
            continue;

        /* Ora lo slot è nostro (consumer) */
        skb = s->skb;
        key = s->key;
        expired = time_after(jiffies, s->timeout);

        if (!skb) {
            /* slot corrotto: libera e continua */
            WRITE_ONCE(s->skb, NULL);
            smp_store_release(&s->state, SLOT_EMPTY);
            continue;
        }

        if (expired) {
            kfree_skb(skb);
            nids_status_consume(key, NULL);
            WRITE_ONCE(s->skb, NULL);
            smp_store_release(&s->state, SLOT_EMPTY);
            continue;
        }

        ret = nids_status_peek(key, &st);
        if (ret == 0 && st.analyses_done >= 3) {
            /* Consuma PRIMA: così quando reinietti, il hook vede “non tracciato” e ACCEPT */
            nids_status_consume(key, NULL);

            if (st.is_malicious) {
                kfree_skb(skb);
            } else {
                /* Reinietta nello stack RX; netif_rx() è reso invocabile in più contesti. */
                netif_rx(skb);
            }

            WRITE_ONCE(s->skb, NULL);
            smp_store_release(&s->state, SLOT_EMPTY);
            continue;
        }

        /* Non pronto: rimetti lo slot a FULL (release) */
        s->skb = skb;
        smp_store_release(&s->state, SLOT_FULL);
        again = true;
    }

    if (!again)
        again = ring_has_full();

    if (again)
        queue_delayed_work(gate_wq, &gate_dwork, msecs_to_jiffies(POLL_MS));
}

static unsigned int gate_nf_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    u32 key;
    struct nids_status st;
    int ret;

    if (!skb)
        return NF_ACCEPT;

    key = skb_get_hash(skb);
    if (!key)
        return NF_ACCEPT;

    /* Se il kfunc module non ha entry -> non bloccare traffico */
    ret = nids_status_peek(key, &st);
    if (ret != 0)
        return NF_ACCEPT;

    /* Se pronto: verdict immediato */
    if (st.analyses_done >= 3)
        return st.is_malicious ? NF_DROP : NF_ACCEPT;

    /* Non pronto: enqueue lockless */
    {
        struct sk_buff *cl = skb_clone(skb, GFP_ATOMIC);
        u64 pi;
        struct pkt_slot *s;

        if (!cl)
            return NF_DROP;

        pi = (u64)atomic64_fetch_inc(&prod_idx);
        s = &ring[pi & Q_MASK];

        /* Claim slot: EMPTY -> BUSY */
        if (cmpxchg(&s->state, SLOT_EMPTY, SLOT_BUSY) != SLOT_EMPTY) {
            /* Ring pieno: droppa clone (e originale viene droppato sotto) */
            kfree_skb(cl);
            return NF_DROP;
        }

        /* Scrivi dati slot */
        s->key = key;
        s->timeout = jiffies + msecs_to_jiffies(TIMEOUT_MS);
        s->skb = cl;

        /* Pubblica: BUSY -> FULL con release */
        smp_store_release(&s->state, SLOT_FULL);

        queue_delayed_work(gate_wq, &gate_dwork, 0);
    }

    /* Droppiamo originale: reiniettiamo il clone quando pronto */
    return NF_DROP;
}

static struct nf_hook_ops nfho = {
    .hook     = gate_nf_hook,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init gate_init(void)
{
    int ret;
    int i;

    for (i = 0; i < Q_SIZE; i++) {
        ring[i].state = SLOT_EMPTY;
        ring[i].skb = NULL;
    }
    atomic64_set(&prod_idx, 0);

    gate_wq = alloc_workqueue("nids_gate_wq", WQ_UNBOUND, 1);
    if (!gate_wq)
        return -ENOMEM;

    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret) {
        destroy_workqueue(gate_wq);
        return ret;
    }

    pr_info("udp_nfqueue_gate loaded (lockless ring, Q=%u)\n", Q_SIZE);
    return 0;
}

static void __exit gate_exit(void)
{
    int i;

    nf_unregister_net_hook(&init_net, &nfho);
    cancel_delayed_work_sync(&gate_dwork);

    if (gate_wq)
        destroy_workqueue(gate_wq);

    /* Drain ring */
    for (i = 0; i < Q_SIZE; i++) {
        struct sk_buff *skb = ring[i].skb;
        ring[i].skb = NULL;
        ring[i].state = SLOT_EMPTY;
        if (skb)
            kfree_skb(skb);
    }

    pr_info("udp_nfqueue_gate unloaded\n");
}

module_init(gate_init);
module_exit(gate_exit);
