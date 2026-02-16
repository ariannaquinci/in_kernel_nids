typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* tc action */
#define TC_ACT_OK 0

#define META_MAGIC 0x4D455441u /* "META" */

#define MARK_MAGIC     0x80000000u
#define MARK_REQ_SHIFT 24
#define MARK_ID_MASK   0x00FFFFFFu

struct meta {
    __u32 magic;
    __u8  req_mask;
    __u8  ip_proto;
    __be16 dport;
    __u32 pkt_id;
} __attribute__((aligned(4)));

SEC("tc")
int tc_ingress_meta_to_mark(struct __sk_buff *skb)
{
    void *data      = (void *)(long)skb->data;
    void *data_meta = (void *)(long)skb->data_meta;

    if (data_meta + sizeof(struct meta) > data)
        return TC_ACT_OK;

    struct meta *m = data_meta;
    if (m->magic != META_MAGIC)
        return TC_ACT_OK;

    __u32 mark = MARK_MAGIC |
                (((__u32)m->req_mask & 0x7u) << MARK_REQ_SHIFT) |
                (m->pkt_id & MARK_ID_MASK);

    skb->mark = mark;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
