// nids_shared.h
#ifndef NIDS_SHARED_H
#define NIDS_SHARED_H

#include <linux/types.h>

struct nids_status {
    __u32 analyses_done;   // 0..3
    __u32 is_malicious;    // 0/1
};

/* API esportate dal modulo kfunc, usate dal netfilter interceptor */
int nids_status_peek(__u32 key, struct nids_status *out);
int nids_status_consume(__u32 key, struct nids_status *out);

/* kfunc chiamata dal programma XDP */
int nids_schedule_analyses_kfunc(__u32 key, __u32 w0, __u32 w1);

#endif
