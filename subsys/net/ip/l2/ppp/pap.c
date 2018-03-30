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

#include "lcp.h"
#include "pap.h"

#define AUTH_REQ_MAX_RETRIES	5

#define PAP_AUTH_REQ	1
#define PAP_AUTH_ACK	2
#define PAP_AUTH_NACK	3

static inline int pap_send_copy(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos, u8_t code, u8_t identifier,
				u16_t len)
{
	return ppp_send_copy(pkt, frag, pos, PPP_PROTO_PAP, code, identifier,
			len);
}

static int pap_send_req(struct net_if *iface, u8_t identifier,
			const char *user, const char *pass)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	u16_t pos;
	u8_t user_len = strlen(user);
	u8_t pass_len = strlen(pass);

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

	frag = net_pkt_write_be16(pkt, frag, 0, &pos, PPP_PROTO_PAP);
	frag = net_pkt_write_u8(pkt, frag, pos, &pos, PAP_AUTH_REQ);
	frag = net_pkt_write_u8(pkt, frag, pos, &pos, identifier);
	frag = net_pkt_write_be16(pkt, frag, pos, &pos, user_len + pass_len + 2 + 4);

	frag = net_pkt_write_u8(pkt, frag, pos, &pos, user_len);
	frag = net_pkt_write(pkt, frag, pos, &pos, user_len, (u8_t *) user, K_FOREVER);
	frag = net_pkt_write_u8(pkt, frag, pos, &pos, pass_len);
	frag = net_pkt_write(pkt, frag, pos, &pos, pass_len, (u8_t *) pass, K_FOREVER);

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

static int pap_auth_req_send(struct ppp_context *ppp)
{
	struct pap_context *pap = &ppp->pap;

	NET_DBG("%s", __func__);

	if (++pap->auth_req_counter > AUTH_REQ_MAX_RETRIES) {
		NET_INFO("Auth-Req max retries reached!");
		if (ppp->lcp.state == LCP_OPENED)
			lcp_close(ppp);
		return 0;
	}

	pap->auth_req_identifier++;

	k_delayed_work_submit_to_queue(&ppp->workq, &pap->auth_req_timer,
				K_SECONDS(3));

	return pap_send_req(ppp->iface, pap->auth_req_identifier,
			ppp->user_data->user, ppp->user_data->password);
}

static void pap_auth_req_resend(struct k_work *work)
{
	struct ppp_context *ppp = CONTAINER_OF(work, struct ppp_context, pap.auth_req_timer);

	pap_auth_req_send(ppp);
}

static enum net_verdict pap_auth_ack_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct pap_context *pap = &ppp->pap;

	if (identifier != pap->auth_req_identifier)
		return NET_DROP;

	k_delayed_work_cancel(&pap->auth_req_timer);

	net_pkt_unref(pkt);

	ppp_link_authenticated(ppp);

	return NET_OK;
}

static enum net_verdict pap_auth_nack_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct pap_context *pap = &ppp->pap;

	if (identifier != pap->auth_req_identifier)
		return NET_DROP;

	k_delayed_work_cancel(&pap->auth_req_timer);

	net_pkt_unref(pkt);

	/* TODO: check if we need to take some action as peer */

	return NET_OK;
}

static inline int pap_code_reject_send(struct net_pkt *pkt)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;

	return pap_send_copy(pkt, pkt->frags, 0, PPP_CODE_REJECT,
			ppp->lcp.code_reject_identifier++,
			net_pkt_get_len(pkt));
}

enum net_verdict net_ppp_pap_recv(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos)
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

	NET_DBG("PAP: code %02x", (unsigned int) code);

	switch (code) {
	case PAP_AUTH_ACK:
		return pap_auth_ack_recv(pkt, frag, pos, identifier, length);
	case PAP_AUTH_NACK:
		return pap_auth_nack_recv(pkt, frag, pos, identifier, length);
	}

	pap_code_reject_send(pkt);
	net_pkt_unref(pkt);
	return NET_OK;
}

void pap_open(struct ppp_context *ppp)
{
	struct pap_context *pap = &ppp->pap;

	pap->auth_req_counter = 0;
	pap_auth_req_send(ppp);
}

void pap_init(struct ppp_context *ppp)
{
	struct pap_context *pap = &ppp->pap;

	k_delayed_work_init(&pap->auth_req_timer, pap_auth_req_resend);
}
