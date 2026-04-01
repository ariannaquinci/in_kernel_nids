// SPDX-License-Identifier: GPL-2.0
#ifndef __DEFERRED_WORK_TCP_H__
#define __DEFERRED_WORK_TCP_H__

#include <net/sock.h>

int dw_tcp_enqueue_stream(struct sock *sk);
bool dw_tcp_is_drop_armed(struct sock *sk);

#endif
