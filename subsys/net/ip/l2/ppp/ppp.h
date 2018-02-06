/*
 * Copyright (c) 2018 Grinn
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NET_PPP_H__
#define __NET_PPP_H__

#include <net/net_pkt.h>
#include <net/net_l2.h>
#include <net/ppp.h>

#define PPP_PROTO_LCP		0xC021
#define PPP_PROTO_IP		0x0021
#define PPP_PROTO_PAP		0xC023
#define PPP_PROTO_CHAP		0xC223
#define PPP_PROTO_IPCP		0x8021

#define PPP_CONF_REQ		1
#define PPP_CONF_ACK		2
#define PPP_CONF_NACK		3
#define PPP_CONF_REJECT		4
#define PPP_TERM_REQ		5
#define PPP_TERM_ACK		6
#define PPP_CODE_REJECT		7
#define PPP_PROTO_REJECT	8
#define PPP_ECHO_REQ		9
#define PPP_ECHO_REPLY		10
#define PPP_DISCARD_REQ		11

const char *ppp_code_to_str(u8_t code);

int ppp_send_data(struct net_if *iface, u16_t protocol, u8_t code,
		u8_t identifier, u16_t len, u8_t *data);
static inline int ppp_send_simple(struct net_if *iface, u16_t protocol,
			u8_t code, u8_t identifier)
{
	return ppp_send_data(iface, protocol, code, identifier, 0, NULL);
}
int ppp_send_copy(struct net_pkt *pkt, struct net_buf *frag, u16_t pos,
		u16_t protocol, u8_t code, u8_t identifier, u16_t len);

bool net_pkt_copy_chunk(struct net_pkt *dst_pkt, struct net_buf **dst_frag,
			u16_t *dst_pos, struct net_buf **src_frag, u16_t *src_pos,
			size_t len);

void ppp_link_opened(struct ppp_context *ppp);
void ppp_link_authenticated(struct ppp_context *ppp);
void ppp_link_closed(struct ppp_context *ppp);

static inline void ppp_network_opened(struct ppp_context *ppp)
{
	ppp->active_network_protocols++;
}
void ppp_network_closed(struct ppp_context *ppp);

void ppp_init(struct ppp_context *ppp);

#endif /* __NET_PPP_H__ */
