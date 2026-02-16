/* common.h */
#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8   proto;
    __u8   padding[3]; // Padding per allineamento a 4 byte (buona pratica BPF)
};

/* Valori per la mappa */
#define ACTION_PASS    0
#define ACTION_ANALYZE 1

#endif
