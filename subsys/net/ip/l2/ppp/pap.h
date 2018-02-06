/*
 * Copyright (c) 2018 Grinn
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NET_PPP_PAP_H__
#define __NET_PPP_PAP_H__

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

enum net_verdict net_ppp_pap_recv(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos);

void pap_open(struct ppp_context *ppp);

void pap_init(struct ppp_context *ppp);

#ifdef __cplusplus
}
#endif

#endif /* __NET_PPP_PAP_H__ */
