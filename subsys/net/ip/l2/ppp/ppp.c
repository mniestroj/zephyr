/*
 * Copyright (c) 2018 Grinn
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define NET_SYS_LOG_LEVEL CONFIG_PPP_L2_LOG_LEVEL

#if defined(CONFIG_PPP_L2_DEBUG)
#define SYS_LOG_DOMAIN "net/ppp_l2"
#define NET_LOG_ENABLED 1
#endif

#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/net_l2.h>

#include <net_private.h>

#include "ipcp.h"
#include "lcp.h"
#include "pap.h"
#include "ppp.h"

const char *ppp_code_to_str(u8_t code)
{
	switch (code) {
	case PPP_CONF_REQ:
		return "CONF_REQ";
	case PPP_CONF_ACK:
		return "CONF_ACK";
	case PPP_CONF_NACK:
		return "CONF_NACK";
	case PPP_CONF_REJECT:
		return "CONF_REJECT";
	case PPP_TERM_REQ:
		return "TERM_REQ";
	case PPP_TERM_ACK:
		return "TERM_ACK";
	case PPP_CODE_REJECT:
		return "CODE_REJECT";
	case PPP_PROTO_REJECT:
		return "PROTO_REJECT";
	case PPP_ECHO_REQ:
		return "ECHO_REQ";
	case PPP_ECHO_REPLY:
		return "ECHO_REPLY";
	case PPP_DISCARD_REQ:
		return "DISCARD_REQ";
	}

	return "<unknown>";
}

int ppp_send_data(struct net_if *iface, u16_t protocol, u8_t code,
		u8_t identifier, u16_t len, u8_t *data)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	u16_t pos;

	pkt = net_pkt_get_reserve_tx(0, K_FOREVER);
	if (!pkt) {
		NET_ERR("Failed to get new packet");
		return -ENOMEM;
	}

	frag = net_pkt_get_frag(pkt, K_FOREVER);
	if (!frag) {
		NET_ERR("Failed to get new frag");
		goto unref_pkt;
	}

	net_pkt_frag_add(pkt, frag);
	net_pkt_set_iface(pkt, iface);

	frag = net_pkt_write_be16(pkt, frag, 0, &pos, protocol);
	frag = net_pkt_write_u8(pkt, frag, pos, &pos, code);
	frag = net_pkt_write_u8(pkt, frag, pos, &pos, identifier);
	frag = net_pkt_write_be16(pkt, frag, pos, &pos, len + 4);
	frag = net_pkt_write(pkt, frag, pos, &pos, len, data, K_FOREVER);

	if (!frag) {
		NET_ERR("Failed to write packet");
		goto unref_pkt;
	}

	net_if_queue_tx(iface, pkt);

	return 0;

unref_pkt:
	net_pkt_unref(pkt);

	return -ENOMEM;
}

bool net_pkt_copy_chunk(struct net_pkt *dst_pkt, struct net_buf **dst_frag,
			u16_t *dst_pos, struct net_buf **src_frag, u16_t *src_pos,
			size_t len)
{
	bool last = false;

	__ASSERT(src_frag, "No src_frag specified");
	__ASSERT(*src_frag, "No *src_frag specified");
	__ASSERT(*src_pos < (*src_frag)->len, "Src offset is bigger than its length");

	while (*src_frag && len) {
		u16_t copy_len = (*src_frag)->len - *src_pos;

		if (copy_len >= len)
			copy_len = len;
		else
			last = true;

		*dst_frag = net_pkt_write(dst_pkt, *dst_frag, *dst_pos, dst_pos,
					copy_len, (*src_frag)->data + *src_pos,
					K_FOREVER);
		if (!(*dst_frag)) {
			NET_ERR("Failed to create new fragment");
			return false;
		}

		if (last) {
			*src_pos = copy_len;
			return true;
		}

		*src_frag = (*src_frag)->frags;
		len -= copy_len;
		*src_pos = 0;
	}

	if (len) {
		NET_ERR("Didn't copy all data: %d", (int) len);
		return false;
	}

	return true;
}

int ppp_send_copy(struct net_pkt *pkt, struct net_buf *frag, u16_t pos,
		u16_t protocol, u8_t code, u8_t identifier, u16_t len)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct net_pkt *out_pkt;
	struct net_buf *out_frag;
	u16_t out_pos;

	out_pkt = net_pkt_get_reserve_tx(0, K_FOREVER);
	if (!out_pkt) {
		NET_ERR("Failed to get new packet");
		return NET_DROP;
	}

	out_frag = net_pkt_get_frag(out_pkt, K_FOREVER);
	if (!out_frag) {
		NET_ERR("Failed to get new frag");
		goto unref_pkt;
	}

	net_pkt_frag_add(out_pkt, out_frag);
	net_pkt_set_iface(out_pkt, iface);

	out_frag = net_pkt_write_be16(out_pkt, out_frag, 0, &out_pos, protocol);
	out_frag = net_pkt_write_u8(out_pkt, out_frag, out_pos, &out_pos, code);
	out_frag = net_pkt_write_u8(out_pkt, out_frag, out_pos, &out_pos, identifier);
	out_frag = net_pkt_write_be16(out_pkt, out_frag, out_pos, &out_pos, len + 4);

	if (!net_pkt_copy_chunk(out_pkt, &out_frag, &out_pos, &frag, &pos, len)) {
		NET_ERR("Failed to copy packet content");
		goto unref_pkt;
	}

	net_if_queue_tx(iface, out_pkt);

	return 0;

unref_pkt:
	net_pkt_unref(out_pkt);

	return -ENOMEM;
}

static inline const char *ppp_protocol_to_str(u16_t protocol)
{
	switch (protocol) {
	case PPP_PROTO_LCP:
		return "LCP";
	case PPP_PROTO_IP:
		return "IP";
	case PPP_PROTO_PAP:
		return "PAP";
	case PPP_PROTO_CHAP:
		return "CHAP";
	case PPP_PROTO_IPCP:
		return "IPCP";
	}

	return "<unknown>";
}

static enum net_verdict net_ppp_recv(struct net_if *iface, struct net_pkt *pkt)
{
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct net_buf *frag = pkt->frags;
	u16_t pos = 0;
	u16_t protocol;

	NET_DBG("iface %p pkt %p len %zu",
		iface, pkt, net_pkt_get_len(pkt));

#if defined(CONFIG_PPP_L2_DEBUG_DUMP)
	net_hexdump_frags("Received PPP packet", pkt, false);
#endif

	frag = net_frag_read_be16(frag, pos, &pos, &protocol);
	if (!frag && pos)
		return NET_DROP;

	NET_DBG("protocol %04x (%s)",
		(unsigned int) protocol,
		ppp_protocol_to_str(protocol));

	switch (protocol) {
	case PPP_PROTO_LCP:
		return net_ppp_lcp_recv(pkt, frag, pos);
	case PPP_PROTO_IPCP:
		return net_ppp_ipcp_recv(pkt, frag, pos);
	case PPP_PROTO_PAP:
		return net_ppp_pap_recv(pkt, frag, pos);
	case PPP_PROTO_IP:
		return net_ppp_ip_recv(pkt, frag, pos);
	}

	if (ppp->lcp.state == LCP_OPENED)
		lcp_proto_reject_send(ppp, pkt);

	return NET_DROP;
}

static inline void ppp_pkt_set_proto(struct net_pkt *pkt, u16_t proto)
{
	u8_t *header = net_pkt_ll(pkt);

	header[0] = proto << 8;
	header[1] = proto;
}

static enum net_verdict net_ppp_send(struct net_if *iface, struct net_pkt *pkt)
{
	struct net_buf *frag = pkt->frags;

	NET_DBG("iface %p pkt %p len %zu",
		iface, pkt, net_pkt_get_len(pkt));

	if (net_buf_headroom(frag) != 2) {
		NET_ERR("Not enough headroom: %d",
			(int) net_buf_headroom(frag));
		return NET_DROP;
	}

	switch (net_pkt_family(pkt)) {
	case AF_INET:
		ppp_pkt_set_proto(pkt, PPP_PROTO_IP);
		net_if_queue_tx(iface, pkt);
		return NET_OK;
	default:
		return NET_DROP;
	}
}

static u16_t net_ppp_reserve(struct net_if *iface, void *unused)
{
	ARG_UNUSED(iface);
	ARG_UNUSED(unused);

	return 2;
}

static int net_ppp_enable(struct net_if *iface, bool state)
{
	NET_DBG("iface %p %s", iface, state ? "up" : "down");

	return 0;
}

NET_L2_INIT(PPP_L2, net_ppp_recv, net_ppp_send, net_ppp_reserve, net_ppp_enable);

void ppp_link_opened(struct ppp_context *ppp)
{
	if (!ppp->auth_type) {
		ppp->network_phase = true;
		ipcp_open(ppp);
	} else {
		pap_open(ppp);
	}
}

void ppp_link_authenticated(struct ppp_context *ppp)
{
	ppp->network_phase = true;
	ipcp_open(ppp);

	if (ppp->user_data->up)
		ppp->user_data->up(ppp);
}

void ppp_link_closed(struct ppp_context *ppp)
{
	if (!ppp->network_phase)
		return;

	ppp->network_phase = false;
	ipcp_close(ppp);

	if (ppp->user_data->down)
		ppp->user_data->down(ppp);
}

void ppp_network_closed(struct ppp_context *ppp)
{
	if (!ppp->active_network_protocols) {
		NET_ERR("Trying to close more network protocols were opened");
		return;
	}

	ppp->active_network_protocols--;

	if (ppp->lcp.state != LCP_OPENED)
		return;

	if (!ppp->active_network_protocols) {
		/*
		 * There are no more active network protocols, so there is
		 * no reason to keep LCP opened.
		 */
		NET_INFO("There are no more active network protocols");
		lcp_close(ppp);
	}
}

void ppp_init(struct ppp_context *ppp)
{
	lcp_init(ppp);
	pap_init(ppp);
	ipcp_init(ppp);
}
