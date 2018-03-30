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

#include "lcp.h"
#include "options.h"

#define LCP_OPT_RESERVED	0
#define LCP_OPT_MRU		1
#define LCP_OPT_AUTH_PROTO	3
#define LCP_OPT_QUALITY_PROTO	4
#define LCP_OPT_MAGIC_NUMBER	5
#define LCP_OPT_PF_COMP		7
#define LCP_OPT_AFCF_COMP	8

#define CONF_REQ_MAX_RETRIES	10
#define CONF_REQ_ACK_TIMEOUT	K_SECONDS(3)

#define TERM_REQ_MAX_RETRIES	2
#define TERM_REQ_ACK_TIMEOUT	K_SECONDS(3)

#define ECHO_MAX_RETRIES	5
#define ECHO_REPLY_TIMEOUT	K_SECONDS(3)
#define ECHO_INTERVAL		K_SECONDS(30)

struct lcp_ack_state {
	u16_t auth_type;
};

static inline int lcp_send_simple(struct net_if *iface, u8_t code,
				u8_t identifier)
{
	return ppp_send_simple(iface, PPP_PROTO_LCP, code, identifier);
}

static inline int lcp_send_data(struct net_if *iface, u8_t code,
				u8_t identifier, u16_t len, u8_t *data)
{
	return ppp_send_data(iface, PPP_PROTO_LCP, code, identifier, len, data);
}

static inline int lcp_send_copy(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos, u8_t code, u8_t identifier,
                                u16_t len)
{
	return ppp_send_copy(pkt, frag, pos, PPP_PROTO_LCP, code, identifier,
			len);
}

static inline const char *lcp_state_to_str(enum lcp_state state)
{
	switch (state) {
	case LCP_INITIAL:
		return "INITIAL";
	case LCP_STARTING:
		return "STARTING";
	case LCP_CLOSED:
		return "CLOSED";
	case LCP_STOPPED:
		return "STOPPED";
	case LCP_CLOSING:
		return "CLOSING";
	case LCP_STOPPING:
		return "STOPPING";
	case LCP_REQ_SENT:
		return "REQ_SENT";
	case LCP_ACK_RCVD:
		return "ACK_RCVD";
	case LCP_ACK_SENT:
		return "ACK_SENT";
	case LCP_OPENED:
		return "OPENED";
	}

	return "<unknown>";
}

static inline void lcp_set_state(struct lcp_context *lcp, enum lcp_state state)
{
	NET_INFO("LCP state %s", lcp_state_to_str(state));

	lcp->state = state;
}

static void lcp_set_opened(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	lcp_set_state(lcp, LCP_OPENED);

	/* Start echoing */
	lcp->echo_req_identifier = 0;
	lcp->echo_reply_identifier = 0xff;
	lcp->echo_fail_counter = 0;
	k_delayed_work_submit_to_queue(&ppp->workq, &lcp->echo_req_timer,
				ECHO_INTERVAL);

	/* Notify PPP layer about opened state */
	ppp_link_opened(ppp);
}

static void lcp_exit_opened(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	/* Stop echoing */
	k_delayed_work_cancel(&lcp->echo_req_timer);

	/* Notify PPP layer about closed state */
	ppp_link_closed(ppp);
}

static void lcp_finished(struct ppp_context *ppp)
{
	NET_DBG("%s", __func__);

	if (ppp->finished)
		ppp->finished(ppp);

	if (ppp->user_data->finished)
		ppp->user_data->finished(ppp);
}

static bool lcp_is_supported_option(struct net_buf *frag, u16_t pos,
			u8_t type, u8_t len, void *data)
{
	struct ppp_option_validate_state *state = data;
	u16_t auth_type;

	switch (type) {
	case LCP_OPT_AUTH_PROTO:
		if (len < 2)
			return false;

		frag = net_frag_read_be16(frag, pos, &pos, &auth_type);
		if (!frag && pos)
			return false;

		if (auth_type != PPP_PROTO_PAP)
			state->nack_len += len + 2;
		return true;
	default:
		state->reject_len += len + 2;
		return true;
	}
}

static bool lcp_reject_option(struct net_buf *frag, u16_t pos,
			u8_t type, u8_t len, void *data)
{
	struct ppp_option_reject_state *state = data;

	switch (type) {
	case LCP_OPT_AUTH_PROTO:
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

static bool lcp_req_ack_option(struct net_buf *frag, u16_t pos,
			u8_t type, u8_t len, void *data)
{
	struct lcp_ack_state *state = data;

	switch (type) {
	case LCP_OPT_AUTH_PROTO:
		frag = net_frag_read_be16(frag, pos, &pos,
				&state->auth_type);
		if (!frag && pos)
			return false;

		return true;
	default:
		return true;
	}
}

static void lcp_conf_req_send(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	if (lcp->state != LCP_REQ_SENT && lcp->state != LCP_ACK_RCVD &&
	    lcp->state != LCP_ACK_SENT)
		return;

	if (++lcp->conf_req_counter > CONF_REQ_MAX_RETRIES) {
		NET_INFO("Conf-Req max retries reached!");
		k_delayed_work_cancel(&lcp->conf_req_timer);
		lcp_set_state(lcp, LCP_STOPPED);
		lcp_finished(ppp);
		return;
	}

	if (lcp->state == LCP_ACK_RCVD)
		lcp_set_state(lcp, LCP_REQ_SENT);

	lcp->conf_req_identifier++;

	k_delayed_work_submit_to_queue(&ppp->workq, &lcp->conf_req_timer,
				CONF_REQ_ACK_TIMEOUT);

	lcp_send_simple(ppp->iface, PPP_CONF_REQ,
			lcp->conf_req_identifier);
}

static void lcp_conf_req_send_first(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	lcp->conf_req_counter = 0;
	lcp_conf_req_send(ppp);
}

static void lcp_conf_req_resend(struct k_work *work)
{
	struct ppp_context *ppp = CONTAINER_OF(work, struct ppp_context,
					lcp.conf_req_timer);

	lcp_conf_req_send(ppp);
}

static void lcp_term_req_send(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	if (lcp->state != LCP_CLOSING && lcp->state != LCP_STOPPING)
		return;

	if (++lcp->term_req_counter > TERM_REQ_MAX_RETRIES) {
		NET_INFO("Term-Req max retries reached!");

		if (lcp->state == LCP_CLOSING)
			lcp_set_state(lcp, LCP_CLOSED);
		else
			lcp_set_state(lcp, LCP_STOPPED);

		lcp_finished(ppp);
		return;
	}

	lcp->term_req_identifier++;

	k_delayed_work_submit_to_queue(&ppp->workq, &lcp->term_req_timer,
				TERM_REQ_ACK_TIMEOUT);

	lcp_send_simple(ppp->iface, PPP_TERM_REQ,
			lcp->term_req_identifier);
}

static void lcp_term_req_send_first(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	lcp->term_req_counter = 0;
	lcp_term_req_send(ppp);
}

static void lcp_term_req_resend(struct k_work *work)
{
	struct ppp_context *ppp = CONTAINER_OF(work, struct ppp_context,
					lcp.term_req_timer);

	lcp_term_req_send(ppp);
}

static void lcp_echo_req_send(struct k_work *work)
{
	struct ppp_context *ppp = CONTAINER_OF(work, struct ppp_context,
					lcp.echo_req_timer);
	struct lcp_context *lcp = &ppp->lcp;
	static const u32_t magic = 0;

	if (lcp->state != LCP_OPENED)
		return;

	if (lcp->echo_req_identifier != lcp->echo_reply_identifier) {
		/* Timeout occured */
		if (++lcp->echo_fail_counter >= ECHO_MAX_RETRIES) {
			NET_INFO("Echo max fails reached!");
			lcp_exit_opened(ppp);
			lcp_set_state(lcp, LCP_STOPPED);
			lcp_finished(ppp);
			return;
		}
	}

	lcp->echo_req_identifier++;

	k_delayed_work_submit_to_queue(&ppp->workq, &lcp->echo_req_timer,
				ECHO_REPLY_TIMEOUT);

	lcp_send_data(ppp->iface, PPP_ECHO_REQ,
		lcp->echo_req_identifier, sizeof(magic), (u8_t *) &magic);
}

static enum net_verdict lcp_echo_reply_recv(struct net_pkt *pkt, struct net_buf *frag,
					u16_t pos, u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct lcp_context *lcp = &ppp->lcp;

	if (lcp->state != LCP_OPENED)
		return NET_DROP;

	net_pkt_unref(pkt);

	lcp->echo_reply_identifier = identifier;
	lcp->echo_fail_counter = 0;
	k_delayed_work_submit_to_queue(&ppp->workq, &lcp->echo_req_timer,
				ECHO_INTERVAL);

	return NET_OK;
}

static enum net_verdict lcp_conf_req_ack(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct lcp_context *lcp = &ppp->lcp;
	struct lcp_ack_state state = {};

	if (!ppp_options_iterate(frag, pos, length, lcp_req_ack_option, &state))
		return NET_DROP;

	if (state.auth_type && state.auth_type != PPP_PROTO_PAP) {
		NET_ERR("Wrong authentication protocol required: %x",
			(unsigned int) state.auth_type);
		return NET_DROP;
	}

	ppp->auth_type = state.auth_type;

	switch (lcp->state) {
	case LCP_REQ_SENT:
		lcp_set_state(lcp, LCP_ACK_SENT);
		break;
	case LCP_ACK_RCVD:
		lcp_set_opened(ppp);
		break;
	case LCP_ACK_SENT:
		break;
	default:
		NET_ERR("Unhandled Conf-Req: lcp.state %d",
			(int) lcp->state);
		return NET_DROP;
	}

	lcp_send_copy(pkt, frag, pos, PPP_CONF_ACK, identifier, length);

	net_pkt_unref(pkt);

	return NET_OK;
}

static int lcp_term_ack_send(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	return lcp_send_simple(ppp->iface, PPP_TERM_ACK,
		++lcp->term_ack_identifier);
}

static enum net_verdict lcp_conf_req_nack(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	NET_DBG("%s", __func__);

	return NET_DROP;
}

static enum net_verdict lcp_conf_req_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct lcp_context *lcp = &ppp->lcp;
	struct ppp_option_validate_state state = {};

	switch (lcp->state) {
	case LCP_CLOSED:
		lcp_term_ack_send(ppp);
		return NET_DROP;
	case LCP_STOPPED:
		lcp_set_state(lcp, LCP_REQ_SENT);
		lcp_conf_req_send_first(ppp);
		break;
	case LCP_REQ_SENT:
	case LCP_ACK_RCVD:
	case LCP_ACK_SENT:
		break;
	case LCP_OPENED:
		lcp_set_state(lcp, LCP_REQ_SENT);
		lcp_exit_opened(ppp);
		lcp_conf_req_send(ppp);
		break;
	default:
		return NET_DROP;
	}

	if (!ppp_options_iterate(frag, pos, length, lcp_is_supported_option, &state))
		return NET_DROP;

	NET_DBG("nack_len %d reject_len %d",
		(int) state.nack_len, (int) state.reject_len);

	if (state.reject_len)
		return ppp_conf_req_reject(pkt, frag, pos, identifier, length,
					PPP_PROTO_LCP,
					state.reject_len, lcp_reject_option);

	if (state.nack_len)
		return lcp_conf_req_nack(pkt, frag, pos, identifier, length);

	return lcp_conf_req_ack(pkt, frag, pos, identifier, length);
}

static enum net_verdict lcp_conf_ack_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct lcp_context *lcp = &ppp->lcp;

	if (identifier != lcp->conf_req_identifier)
		return NET_DROP;

	net_pkt_unref(pkt);

	switch (lcp->state) {
	case LCP_REQ_SENT:
		lcp->conf_req_counter = 0;
		lcp_set_state(lcp, LCP_ACK_RCVD);
		break;
	case LCP_ACK_SENT:
		k_delayed_work_cancel(&lcp->conf_req_timer);
		lcp_set_opened(ppp);
		break;
	default:
		NET_ERR("Unhandled Conf-Ack: lcp.state %d",
			(int) lcp->state);
		break;
	}

	return NET_OK;
}

static enum net_verdict lcp_term_ack_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct lcp_context *lcp = &ppp->lcp;

	if (identifier != lcp->term_req_identifier)
		return NET_DROP;

	k_delayed_work_cancel(&lcp->term_req_timer);

	switch (lcp->state) {
	case LCP_CLOSING:
		lcp_set_state(lcp, LCP_CLOSED);
		lcp_finished(ppp);
		break;
	case LCP_STOPPING:
		lcp_finished(ppp);
	case LCP_REQ_SENT:
	case LCP_ACK_RCVD:
	case LCP_ACK_SENT:
		lcp_set_state(lcp, LCP_STOPPED);
		break;
	default:
		break;
	}

	net_pkt_unref(pkt);
	return NET_OK;
}

static enum net_verdict lcp_conf_nack_recv(struct net_pkt *pkt,
					struct net_buf *frag, u16_t pos,
					u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct lcp_context *lcp = &ppp->lcp;

	if (identifier != lcp->conf_req_identifier)
		return NET_DROP;

	net_pkt_unref(pkt);

	switch (lcp->state) {
	case LCP_REQ_SENT:
	case LCP_ACK_SENT:
		lcp_close(ppp);
		break;
	default:
		NET_ERR("Unhandled Conf-Nak/Conf-Rej: lcp.state %d",
			(int) lcp->state);
		break;
	}

	return NET_OK;
}

static enum net_verdict lcp_echo_req_recv(struct net_pkt *pkt, struct net_buf *frag,
					u16_t pos, u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;

	if (ppp->lcp.state != LCP_OPENED)
		return NET_DROP;

	lcp_send_copy(pkt, frag, pos, PPP_ECHO_REPLY, identifier, length);
	net_pkt_unref(pkt);
	return NET_OK;
}

static enum net_verdict lcp_term_req_recv(struct net_pkt *pkt, struct net_buf *frag,
					u16_t pos, u8_t identifier, u16_t length)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct lcp_context *lcp = &ppp->lcp;

	NET_DBG("%s", __func__);

	switch (lcp->state) {
	case LCP_CLOSED:
	case LCP_STOPPED:
	case LCP_CLOSING:
	case LCP_STOPPING:
	case LCP_REQ_SENT:
		break;
	case LCP_ACK_RCVD:
	case LCP_ACK_SENT:
		lcp_set_state(lcp, LCP_REQ_SENT);
		break;
	case LCP_OPENED:
		lcp_set_state(lcp, LCP_STOPPING);
		k_delayed_work_submit_to_queue(&ppp->workq,
					&lcp->stopping_timer, K_SECONDS(2));
		lcp_exit_opened(ppp);
		break;
	default:
		NET_ERR("Unhandled Term-Req: lcp.state %d",
			(int) lcp->state);
		break;
	}

	lcp_send_copy(pkt, frag, pos, PPP_TERM_ACK, identifier, length);
	net_pkt_unref(pkt);
	return NET_OK;
}

static inline int lcp_code_reject_send(struct net_pkt *pkt)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;

	return lcp_send_copy(pkt, pkt->frags, 0, PPP_CODE_REJECT,
			ppp->lcp.code_reject_identifier++,
			net_pkt_get_len(pkt));
}

enum net_verdict net_ppp_lcp_recv(struct net_pkt *pkt, struct net_buf *frag,
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

	NET_DBG("LCP: code %02x (%s)",
		(unsigned int) code, ppp_code_to_str(code));

	switch (code) {
	case PPP_CONF_REQ:
		return lcp_conf_req_recv(pkt, frag, pos, identifier, length);
	case PPP_CONF_ACK:
		return lcp_conf_ack_recv(pkt, frag, pos, identifier, length);
	case PPP_CONF_NACK:
	case PPP_CONF_REJECT:
		return lcp_conf_nack_recv(pkt, frag, pos, identifier, length);
	case PPP_TERM_REQ:
		return lcp_term_req_recv(pkt, frag, pos, identifier, length);
	case PPP_TERM_ACK:
		return lcp_term_ack_recv(pkt, frag, pos, identifier, length);
	case PPP_ECHO_REQ:
		return lcp_echo_req_recv(pkt, frag, pos, identifier, length);
	case PPP_ECHO_REPLY:
		return lcp_echo_reply_recv(pkt, frag, pos, identifier, length);
	}

	lcp_code_reject_send(pkt);
	net_pkt_unref(pkt);
	return NET_OK;
}

int lcp_proto_reject_send(struct ppp_context *ppp, struct net_pkt *pkt)
{
	return lcp_send_copy(pkt, pkt->frags, 0, PPP_PROTO_REJECT,
			ppp->lcp.proto_reject_identifier++,
			net_pkt_get_len(pkt));
}

void lcp_open(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	NET_DBG("%s", __func__);

	if (lcp->state != LCP_CLOSED) {
		NET_ERR("=========");
		NET_ERR("INVALID STATE %d", (int) lcp->state);
		NET_ERR("=========");
		return;
	}

	/* TODO: For now we only handle CLOSED state */
	lcp_set_state(lcp, LCP_REQ_SENT);
	lcp_conf_req_send_first(ppp);
}

void lcp_close(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	NET_DBG("%s", __func__);

	switch (lcp->state) {
	case LCP_STARTING:
		lcp_set_state(lcp, LCP_INITIAL);
		lcp_finished(ppp);
		break;
	case LCP_STOPPED:
		lcp_set_state(lcp, LCP_CLOSED);
		break;
	case LCP_OPENED:
		lcp_exit_opened(ppp);
		/* FALLTHROUGH */
	case LCP_REQ_SENT:
	case LCP_ACK_SENT:
		k_delayed_work_cancel(&lcp->conf_req_timer);
		/* FALLTHROUGH */
	case LCP_ACK_RCVD:
		lcp_set_state(lcp, LCP_CLOSING);
		lcp_term_req_send_first(ppp);
		break;
	case LCP_STOPPING:
		lcp_set_state(lcp, LCP_CLOSING);
		lcp_term_req_send(ppp);
		break;
	case LCP_INITIAL:
	case LCP_CLOSED:
	case LCP_CLOSING:
		break;
	}
}

static void lcp_stopping_timeout(struct k_work *work)
{
	struct ppp_context *ppp = CONTAINER_OF(work, struct ppp_context,
					lcp.stopping_timer);
	struct lcp_context *lcp = &ppp->lcp;

	if (lcp->state != LCP_CLOSING && lcp->state != LCP_STOPPING)
		return;

	if (lcp->state == LCP_CLOSING)
		lcp_set_state(lcp, LCP_CLOSED);
	else
		lcp_set_state(lcp, LCP_STOPPED);

	lcp_finished(ppp);
}

void lcp_init(struct ppp_context *ppp)
{
	struct lcp_context *lcp = &ppp->lcp;

	lcp_set_state(lcp, LCP_CLOSED);
	k_delayed_work_init(&lcp->conf_req_timer, lcp_conf_req_resend);
	k_delayed_work_init(&lcp->term_req_timer, lcp_term_req_resend);
	k_delayed_work_init(&lcp->stopping_timer, lcp_stopping_timeout);
	k_delayed_work_init(&lcp->echo_req_timer, lcp_echo_req_send);
}
