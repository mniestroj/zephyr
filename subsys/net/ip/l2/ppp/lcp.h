/*
 * Copyright (c) 2018 Grinn
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NET_PPP_LCP_H__
#define __NET_PPP_LCP_H__

#include <zephyr/types.h>

#include <net/buf.h>

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

enum net_verdict net_ppp_lcp_recv(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos);
int lcp_proto_reject_send(struct ppp_context *ppp, struct net_pkt *pkt);

void lcp_open(struct ppp_context *ppp);
void lcp_close(struct ppp_context *ppp);

void lcp_init(struct ppp_context *ppp);

#ifdef __cplusplus
}
#endif

#endif /* __NET_PPP_LCP_H__ */
