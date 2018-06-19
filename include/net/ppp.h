/*
 * Copyright (c) 2018 Grinn
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __PPP_H
#define __PPP_H

#include <kernel.h>
#include <net/net_ip.h>
#include <stdbool.h>
#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lcp_state {
	LCP_INITIAL,
	LCP_STARTING,
	LCP_CLOSED,
	LCP_STOPPED,
	LCP_CLOSING,
	LCP_STOPPING,
	LCP_REQ_SENT,
	LCP_ACK_RCVD,
	LCP_ACK_SENT,
	LCP_OPENED,
};

struct ppp_context;

struct ppp_user_data {
	const char *user;
	const char *password;
	void (*up)(struct ppp_context *ppp);
	void (*down)(struct ppp_context *ppp);
	void (*finished)(struct ppp_context *ppp);
};

struct ppp_context {
	struct net_if *iface;
	void *data;
	void (*finished)(struct ppp_context *ppp);
	struct k_work_q workq;

	u16_t auth_type;
	u16_t active_network_protocols;
	bool network_phase;

	const struct ppp_user_data *user_data;

	struct lcp_context {
		enum lcp_state state;

		struct k_delayed_work conf_req_timer;
		u8_t conf_req_identifier;
		u8_t conf_req_counter;

		struct k_delayed_work conf_req_ack_timer;

		struct k_delayed_work term_req_timer;
		u8_t term_req_identifier;
		u8_t term_req_counter;
		u8_t term_ack_identifier;

		struct k_delayed_work stopping_timer;

		struct k_delayed_work echo_req_timer;
		u8_t echo_req_identifier;
		u8_t echo_reply_identifier;
		u8_t echo_fail_counter;

		u8_t proto_reject_identifier;
		u8_t code_reject_identifier;
	} lcp;

	struct ipcp_context {
		struct k_delayed_work conf_req_timer;
		u8_t conf_req_identifier;
		u8_t conf_req_counter;
		struct in_addr ipaddr;
		bool opened;
	} ipcp;

	struct pap_context {
		struct k_delayed_work auth_req_timer;
		u8_t auth_req_identifier;
		u8_t auth_req_counter;
	} pap;
};

#ifdef CONFIG_PPP_L2_SERIAL

struct ppps_user_data {
	int (*connect)(struct ppp_context *ppp);
	void (*connect_fail)(struct ppp_context *ppp, int err);
	int (*disconnect)(struct ppp_context *ppp);
	void (*recv)(struct ppp_context *ppp, u8_t *data, size_t len);

	struct ppp_user_data ppp_user_data;
};

#define PPP_UART_RECV_BUF_LEN 256

struct ppps_context {
	struct ppp_context *ppp;

	struct device *uart_dev;
	bool first;
	u8_t uart_buf[PPP_UART_RECV_BUF_LEN];
	struct net_pkt *rx;
	struct net_buf *last;
	u8_t *ptr;
	u8_t state;
	u16_t fcs;
	u16_t out_fcs;

	const struct ppps_user_data *user_data;
	struct k_work open_work;
	struct k_work close_work;
};

void ppps_open(const struct ppps_user_data *user_data);
void ppps_close(void);

#endif /* CONFIG_PPP_L2_SERIAL */

#ifdef __cplusplus
}
#endif

#endif /* __PPP_H */
