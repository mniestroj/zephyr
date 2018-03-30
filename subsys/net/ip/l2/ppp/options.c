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

#include "options.h"

bool ppp_options_iterate(struct net_buf *frag, u16_t pos,
			u16_t length, ppp_option_step_t step,
			void *data)
{
	u8_t type;
	u8_t len;

	while (length >= 2) {
		frag = net_frag_read_u8(frag, pos, &pos, &type);
		frag = net_frag_read_u8(frag, pos, &pos, &len);

		if (!frag && pos) {
			return false;
		}

		if (len > length || len < 2) {
			return false;
		}

		if (!step(frag, pos, type, len - 2, data)) {
			return false;
		}

		frag = net_frag_skip(frag, pos, &pos, len - 2);
		if (!frag && pos && len > 2) {
			return false;
		}

		length -= len;
	}

	if (length) {
		return false;
	}

	return true;
}

enum net_verdict ppp_conf_req_reject(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos, u8_t identifier, u16_t length,
				u16_t code, u16_t reject_len,
				ppp_option_step_t step)
{
	struct net_if *iface = net_pkt_iface(pkt);
	struct ppp_option_reject_state out = {};

	NET_DBG("%s", __func__);

	out.pkt = net_pkt_get_reserve_tx(0, K_FOREVER);
	if (!out.pkt) {
		NET_ERR("Failed to get new packet");
		return NET_DROP;
	}

	out.frag = net_pkt_get_frag(out.pkt, K_FOREVER);
	if (!out.frag) {
		NET_ERR("Failed to get new frag");
		goto unref_pkt;
	}

	net_pkt_frag_add(out.pkt, out.frag);
	net_pkt_set_iface(out.pkt, iface);

	out.frag = net_pkt_write_be16(out.pkt, out.frag, 0, &out.pos, code);
	out.frag = net_pkt_write_u8(out.pkt, out.frag, out.pos, &out.pos,
                                    PPP_CONF_REJECT);
	out.frag = net_pkt_write_u8(out.pkt, out.frag, out.pos, &out.pos,
                                    identifier);
	out.frag = net_pkt_write_be16(out.pkt, out.frag, out.pos, &out.pos,
				reject_len + 4);

	if (!ppp_options_iterate(frag, pos, length, step, &out)) {
		NET_ERR("Failed to iterate rejected options");
		goto unref_pkt;
	}

	if (!out.frag) {
		NET_ERR("Failed to write packet");
		goto unref_pkt;
	}

	net_pkt_unref(pkt);

	net_if_queue_tx(iface, out.pkt);

	return NET_OK;

unref_pkt:
	net_pkt_unref(out.pkt);

	return NET_DROP;
}

