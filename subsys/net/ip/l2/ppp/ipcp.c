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

#include <net/net_pkt.h>

#include "ipcp.h"
#include "options.h"

#define CONF_REQ_MAX_RETRIES	5

#define IPCP_OPT_COMP_PROTO	2
#define IPCP_OPT_IP_ADDR	3
#define IPCP_OPT_VJ_HEAD_COMP	4

struct ipcp_ack_state {
	bool ipaddr_valid;
	struct in_addr ipaddr;
};

static inline int ipcp_send_simple(struct net_if *iface, u8_t code,
				u8_t identifier)
{
	return ppp_send_simple(iface, PPP_PROTO_IPCP, code, identifier);
}

static inline int ipcp_send_data(struct net_if *iface, u8_t code,
				u8_t identifier, u16_t len, u8_t *data)
{
	return ppp_send_data(iface, PPP_PROTO_IPCP, code, identifier,
			len, data);
}

static inline int ipcp_send_copy(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos, u8_t code, u8_t identifier,
                                u16_t len)
{
	return ppp_send_copy(pkt, frag, pos, PPP_PROTO_IPCP, code, identifier,
			len);
}

static bool ipcp_is_supported_option(struct net_buf *frag, u16_t pos,
				u8_t type, u8_t len, void *data)
{
	struct ppp_option_validate_state *state = data;

	switch (type) {
	case IPCP_OPT_IP_ADDR:
		if (len != 4)
			return false;
		return true;
	default:
		state->reject_len += len + 2;
		return true;
	}
}

static bool ipcp_reject_option(struct net_buf *frag, u16_t pos,
			u8_t type, u8_t len, void *data)
{
	struct ppp_option_reject_state *state = data;

	switch (type) {
	case IPCP_OPT_IP_ADDR:
		return true;
	default:
		state->frag = net_pkt_write_u8(state->pkt, state->frag,
					state->pos, &state->pos, type);
		state->frag = net_pkt_write_u8(state->pkt, state->frag,
					state->pos, &state->pos, len + 2);
		if (!state->frag)
			return false;

		return net_pkt_copy_chunk(state->pkt, &state->frag,
					&state->pos, &frag, &pos, len);
	}
}

static bool ipcp_req_ack_option(struct net_buf *frag, u16_t pos,
			u8_t type, u8_t len, void *data)
{
	struct ipcp_ack_state *state = data;

	switch (type) {
	case IPCP_OPT_IP_ADDR:
		frag = net_frag_read(frag, pos, &pos,
				sizeof(state->ipaddr.s4_addr),
				state->ipaddr.s4_addr);
		if (!frag && pos)
			return false;

		state->ipaddr_valid = true;
		return true;
	default:
		return true;
	}
}

static enum net_verdict ipcp_conf_req_ack(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct ipcp_ack_state state = {};

	NET_DBG("%s", __func__);

	if (!ppp_options_iterate(frag, pos, length, ipcp_req_ack_option, &state))
		return NET_DROP;

	ipcp_send_copy(pkt, frag, pos, PPP_CONF_ACK, identifier, length);

	net_pkt_unref(pkt);

	if (state.ipaddr_valid) {
		NET_INFO("Peer IP address: %d.%d.%d.%d",
			(int) state.ipaddr.s4_addr[0],
			(int) state.ipaddr.s4_addr[1],
			(int) state.ipaddr.s4_addr[2],
			(int) state.ipaddr.s4_addr[3]);
		net_if_ipv4_set_gw(net_pkt_iface(pkt), &state.ipaddr);
	}

	return NET_OK;
}

static int ipcp_conf_req_send(struct ppp_context *ppp)
{
	struct ipcp_context *ipcp = &ppp->ipcp;
	u8_t ipaddr[6] = {IPCP_OPT_IP_ADDR, 6,
			  ipcp->ipaddr.s4_addr[0],
			  ipcp->ipaddr.s4_addr[1],
			  ipcp->ipaddr.s4_addr[2],
			  ipcp->ipaddr.s4_addr[3]};

	NET_DBG("%s", __func__);

	if (++ipcp->conf_req_counter > CONF_REQ_MAX_RETRIES) {
		NET_INFO("Conf-Req max retries reached!");
		ipcp_close(ppp);
		return 0;
	}

	ipcp->conf_req_identifier++;

	k_delayed_work_submit_to_queue(&ppp->workq, &ipcp->conf_req_timer,
				K_SECONDS(3));

	return ipcp_send_data(ppp->iface, PPP_CONF_REQ,
			ipcp->conf_req_identifier,
			sizeof(ipaddr), ipaddr);
}

static void ipcp_conf_req_resend(struct k_work *work)
{
	struct ppp_context *ppp = CONTAINER_OF(work, struct ppp_context, ipcp.conf_req_timer);

	ipcp_conf_req_send(ppp);
}

static enum net_verdict ipcp_conf_req_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct ppp_option_validate_state state = {};

	NET_DBG("%s", __func__);

	if (!ppp_options_iterate(frag, pos, length, ipcp_is_supported_option, &state))
		return NET_DROP;

	NET_DBG("reject_len %d", (int) state.reject_len);

	if (state.reject_len)
		return ppp_conf_req_reject(pkt, frag, pos, identifier, length,
					PPP_PROTO_IPCP,
					state.reject_len, ipcp_reject_option);

	return ipcp_conf_req_ack(pkt, frag, pos, identifier, length);
}

static enum net_verdict ipcp_conf_ack_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct ipcp_context *ipcp = &ppp->ipcp;

	if (identifier != ipcp->conf_req_identifier)
		return NET_DROP;

	k_delayed_work_cancel(&ipcp->conf_req_timer);

	net_pkt_unref(pkt);

	NET_INFO("My IP address: %d.%d.%d.%d",
		(int) ipcp->ipaddr.s4_addr[0], (int) ipcp->ipaddr.s4_addr[1],
		(int) ipcp->ipaddr.s4_addr[2], (int) ipcp->ipaddr.s4_addr[3]);

	if (!net_if_ipv4_addr_add(iface, &ipcp->ipaddr, NET_ADDR_AUTOCONF, 0))
		NET_ERR("Failed to assign IP address to interface");

	return NET_OK;
}

static bool ipcp_nack_option(struct net_buf *frag, u16_t pos,
			u8_t type, u8_t len, void *data)
{
	struct ipcp_ack_state *state = data;

	switch (type) {
	case IPCP_OPT_IP_ADDR:
		frag = net_frag_read(frag, pos, &pos,
				sizeof(state->ipaddr.s4_addr),
				state->ipaddr.s4_addr);
		if (!frag && pos)
			return false;

		state->ipaddr_valid = true;
		return true;
	default:
		return true;
	}
}

static enum net_verdict ipcp_conf_nack_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct ipcp_context *ipcp = &ppp->ipcp;
	struct ipcp_ack_state state = {};

	if (identifier != ipcp->conf_req_identifier)
		return NET_DROP;

	k_delayed_work_cancel(&ipcp->conf_req_timer);

	if (!ppp_options_iterate(frag, pos, length, ipcp_nack_option, &state))
		return NET_DROP;

	net_pkt_unref(pkt);

	if (state.ipaddr_valid) {
		ipcp->ipaddr = state.ipaddr;
		ipcp_conf_req_send(ppp);
	}

	return NET_OK;
}

static inline int ipcp_code_reject_send(struct net_pkt *pkt)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;

	return ipcp_send_copy(pkt, pkt->frags, 0, PPP_CODE_REJECT,
			ppp->lcp.code_reject_identifier++,
			net_pkt_get_len(pkt));
}

enum net_verdict net_ppp_ipcp_recv(struct net_pkt *pkt,
				struct net_buf *frag, u16_t pos)
{
	u8_t code;
	u8_t identifier;
	u16_t length;

	frag = net_frag_read_u8(frag, pos, &pos, &code);
	frag = net_frag_read_u8(frag, pos, &pos, &identifier);
	frag = net_frag_read_be16(frag, pos, &pos, &length);

	if (!frag && pos)
		return NET_DROP;

	length -= 4;

	NET_DBG("IPCP: code %02x (%s)",
		(unsigned int) code, ppp_code_to_str(code));

	switch (code) {
	case PPP_CONF_REQ:
		return ipcp_conf_req_recv(pkt, frag, pos, identifier, length);
	case PPP_CONF_ACK:
		return ipcp_conf_ack_recv(pkt, frag, pos, identifier, length);
	case PPP_CONF_NACK:
		return ipcp_conf_nack_recv(pkt, frag, pos, identifier, length);
	}

	ipcp_code_reject_send(pkt);
	net_pkt_unref(pkt);
	return NET_OK;
}

void ipcp_open(struct ppp_context *ppp)
{
	struct ipcp_context *ipcp = &ppp->ipcp;

	if (ipcp->opened)
		return;

	ipcp->opened = true;
	ppp_network_opened(ppp);

	ipcp->conf_req_counter = 0;
	ipcp->ipaddr.s_addr = 0;
	ipcp_conf_req_send(ppp);
}

void ipcp_close(struct ppp_context *ppp)
{
	struct ipcp_context *ipcp = &ppp->ipcp;
	struct in_addr gw = {};

	if (!ipcp->opened)
		return;

	k_delayed_work_cancel(&ipcp->conf_req_timer);

	if (ipcp->ipaddr.s_addr) {
		if (!net_if_ipv4_addr_rm(ppp->iface, &ipcp->ipaddr)) {
			NET_ERR("Failed to remove My IP address %d.%d.%d.%d",
				(int) ipcp->ipaddr.s4_addr[0],
				(int) ipcp->ipaddr.s4_addr[1],
				(int) ipcp->ipaddr.s4_addr[2],
				(int) ipcp->ipaddr.s4_addr[3]);
		}

		ipcp->ipaddr.s_addr = 0;
	}

	net_if_ipv4_set_gw(ppp->iface, &gw);

	ipcp->opened = false;
	ppp_network_closed(ppp);
}

void ipcp_init(struct ppp_context *ppp)
{
	struct ipcp_context *ipcp = &ppp->ipcp;

	ipcp->ipaddr.s_addr = 0;
	k_delayed_work_init(&ipcp->conf_req_timer, ipcp_conf_req_resend);
}

enum net_verdict net_ppp_ip_recv(struct net_pkt *pkt,
				struct net_buf *frag, u16_t pos)
{
	NET_DBG("%s", __func__);

	net_pkt_set_ll_reserve(pkt, pos);
	net_buf_pull(frag, pos);
	net_pkt_set_family(pkt, AF_INET);

	return NET_CONTINUE;
}
