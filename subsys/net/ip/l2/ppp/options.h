/*
 * Copyright (c) 2018 Grinn
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NET_PPP_OPTIONS_H__
#define __NET_PPP_OPTIONS_H__

#include "ppp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ppp_option_validate_state {
	u16_t nack_len;
	u16_t reject_len;
};

struct ppp_option_reject_state {
	struct net_pkt *pkt;
	struct net_buf *frag;
	u16_t pos;
};

typedef bool (*ppp_option_step_t)(struct net_buf *frag, u16_t pos,
				u8_t type, u8_t len, void *data);

bool ppp_options_iterate(struct net_buf *frag, u16_t pos,
			u16_t length, ppp_option_step_t step,
			void *data);

enum net_verdict ppp_conf_req_reject(struct net_pkt *pkt, struct net_buf *frag,
				u16_t pos, u8_t identifier, u16_t length,
				u16_t code, u16_t reject_len,
				ppp_option_step_t step);

#ifdef __cplusplus
}
#endif

#endif /* __NET_PPP_OPTIONS_H__ */
