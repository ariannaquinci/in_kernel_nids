// dummy_kfunc.c
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <uapi/linux/bpf.h>

#include "nids_shared.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");

#define STATUS_BITS 10

struct status_entry {
    __u32 key;
    __u32 analyses_done;
    __u32 is_malicious;
    __u32 w0;
    __u32 w1;
    struct hlist_node hnode;
};

static DEFINE_HASHTABLE(status_table, STATUS_BITS);
static DEFINE_SPINLOCK(status_lock);
static struct workqueue_struct *nids_wq;

struct analysis_work {
    struct work_struct work;
    __u32 key;
    __u8  which;   /* 1..3 */
};

static struct status_entry *status_lookup_nolock(__u32 key)
{
    struct status_entry *e;
    hash_for_each_possible(status_table, e, hnode, key) {
        if (e->key == key)
            return e;
    }
    return NULL;
}

static void do_one_analysis(struct status_entry *e, __u8 which)
{
    /* FINTA: usa w0/w1 come contenuto pacchetto */
    if (which == 1) {
        if (e->w0 == 0xDEADBEEF)
            e->is_malicious = 1;
    } else if (which == 2) {
        if (e->w1 == 0x909090C3)
            e->is_malicious = 1;
    } else if (which == 3) {
        if ((e->w0 ^ e->w1) == 0xCAFEBABE)
            e->is_malicious = 1;
    }

    if (e->analyses_done < 3)
        e->analyses_done++;
}

static void analysis_work_func(struct work_struct *w)
{
    struct analysis_work *aw = container_of(w, struct analysis_work, work);
    unsigned long flags;
    struct status_entry *e;

    spin_lock_irqsave(&status_lock, flags);
    e = status_lookup_nolock(aw->key);
    if (e)
        do_one_analysis(e, aw->which);
    spin_unlock_irqrestore(&status_lock, flags);

    kfree(aw);
}

/* kfunc chiamata da XDP */
__bpf_kfunc int nids_schedule_analyses_kfunc(__u32 key, __u32 w0, __u32 w1)
{
    unsigned long flags;
    struct status_entry *e;
    int i;

    spin_lock_irqsave(&status_lock, flags);
    e = status_lookup_nolock(key);
    if (!e) {
        e = kzalloc(sizeof(*e), GFP_ATOMIC);
        if (!e) {
            spin_unlock_irqrestore(&status_lock, flags);
            return -ENOMEM;
        }
        e->key = key;
        hash_add(status_table, &e->hnode, key);
    }
    e->w0 = w0;
    e->w1 = w1;
    spin_unlock_irqrestore(&status_lock, flags);

    for (i = 1; i <= 3; i++) {
        struct analysis_work *aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
        if (!aw)
            continue;
        INIT_WORK(&aw->work, analysis_work_func);
        aw->key   = key;
        aw->which = i;
        queue_work(nids_wq, &aw->work);
    }

    return 0;
}

/* BTF kfunc set */
BTF_SET8_START(nids_kfunc_ids)
BTF_ID_FLAGS(func, nids_schedule_analyses_kfunc, KF_TRUSTED_ARGS)
BTF_SET8_END(nids_kfunc_ids)

static const struct btf_kfunc_id_set nids_kfunc_idset = {
    .owner = THIS_MODULE,
    .set   = &nids_kfunc_ids,
};

/* API per netfilter: solo chiavi, nessuna macro hashtable dal suo lato */
int nids_status_peek(__u32 key, struct nids_status *out)
{
    unsigned long flags;
    struct status_entry *e;
    int ret = -ENOENT;

    spin_lock_irqsave(&status_lock, flags);
    e = status_lookup_nolock(key);
    if (e) {
        if (out) {
            out->analyses_done = e->analyses_done;
            out->is_malicious  = e->is_malicious;
        }
        ret = 0;
    }
    spin_unlock_irqrestore(&status_lock, flags);
    return ret;
}
EXPORT_SYMBOL_GPL(nids_status_peek);

int nids_status_consume(__u32 key, struct nids_status *out)
{
    unsigned long flags;
    struct status_entry *e;
    int ret = -ENOENT;

    spin_lock_irqsave(&status_lock, flags);
    e = status_lookup_nolock(key);
    if (e) {
        if (out) {
            out->analyses_done = e->analyses_done;
            out->is_malicious  = e->is_malicious;
        }
        hash_del(&e->hnode);
        kfree(e);
        ret = 0;
    }
    spin_unlock_irqrestore(&status_lock, flags);
    return ret;
}
EXPORT_SYMBOL_GPL(nids_status_consume);

static int __init nids_kfunc_init(void)
{
    int ret;

    nids_wq = alloc_workqueue("nids_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
    if (!nids_wq)
        return -ENOMEM;

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &nids_kfunc_idset);
    if (ret) {
        destroy_workqueue(nids_wq);
        return ret;
    }

    pr_info("nids kfunc module loaded\n");
    return 0;
}

static void __exit nids_kfunc_exit(void)
{
    struct status_entry *e;
    struct hlist_node *tmp;
    int bkt;

    if (nids_wq) {
        flush_workqueue(nids_wq);
        destroy_workqueue(nids_wq);
    }

    hash_for_each_safe(status_table, bkt, tmp, e, hnode) {
        hash_del(&e->hnode);
        kfree(e);
    }

    pr_info("nids kfunc module unloaded\n");
}

module_init(nids_kfunc_init);
module_exit(nids_kfunc_exit);
