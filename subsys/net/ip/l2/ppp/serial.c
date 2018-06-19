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

#include <device.h>
#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/net_l2.h>
#include <uart.h>

#include <net_private.h>

#include "ppp.h"
#include "lcp.h"

#define PPP_FLAG	0x7e
#define PPP_ESC		0x7d
#define PPP_MOD		0x20

#define PPP_INITFCS	0xffff
#define PPP_GOODFCS	0xf0b8

enum ppps_state {
	STATE_GARBAGE,
	STATE_OK,
	STATE_ESC,
};

static u16_t crc16_byte(u16_t crc, u8_t c)
{
	u16_t t;

	t = crc ^ c;
	t = (t ^ (t << 4)) & 0xff;
	t = (t << 8) ^ (t << 3) ^ (t >> 4);

	return ((crc >> 8) ^ t);
}

static struct net_pkt *ppps_poll_handler(struct ppps_context *ppps)
{
	if (ppps->last && ppps->last->len) {
		return ppps->rx;
	}

	return NULL;
}

static bool validate_msg(struct ppps_context *ppps)
{
	if (ppps->fcs == PPP_GOODFCS)
		return true;

	NET_ERR("Invalid FCS %x", (unsigned int) ppps->fcs);

	return false;
}

static void net_pkt_simple_trunc(struct net_pkt *pkt, size_t len)
{
	struct net_buf *parent = NULL;
	struct net_buf *frag = pkt->frags;

	while (frag->frags) {
		parent = frag;
		frag = frag->frags;
	}

	if (frag->len > len) {
		frag->len -= len;
		return;
	}

	len -= frag->len;

	net_pkt_frag_del(pkt, parent, frag);

	parent->len -= len;
}

static void process_msg(struct ppp_context *ppp)
{
	struct ppps_context *ppps = ppp->data;
	struct net_pkt *pkt;

	pkt = ppps_poll_handler(ppps);
	if (!pkt || !pkt->frags)
		return;

	ppps->rx = NULL;
	ppps->last = NULL;

	if (!validate_msg(ppps))
		goto fail;

	/* We get rid of FCS, so higher layer does not have to worry about
	 * unnecessary bytes */
	net_pkt_simple_trunc(pkt, 2);

	if (net_recv_data(ppp->iface, pkt) < 0)
		goto fail;

	return;

fail:
	net_pkt_unref(pkt);
}

static int ppps_input_byte(struct ppps_context *ppps,
			unsigned char c)
{
	switch (ppps->state) {
	case STATE_GARBAGE:
		if (c == PPP_FLAG)
			ppps->state = STATE_OK;
		return 0;
	case STATE_ESC:
		if (c == PPP_FLAG) {
			ppps->state = STATE_GARBAGE;
			return 0;
		}
		c = c ^ PPP_MOD;
		ppps->state = STATE_OK;
		break;
	case STATE_OK:
		if (c == PPP_ESC) {
			ppps->state = STATE_ESC;
			return 0;
		}

		if (c == PPP_FLAG) {
			ppps->first = false;

			if (ppps->rx)
				return 1;

			return 0;
		}

		if (ppps->first && !ppps->rx) {
			/* We have missed buffer allocation on first byte. */
			NET_ERR("Missed buffer allocation on first byte");
			return 0;
		}

		if (!ppps->first) {
			ppps->first = true;
			ppps->fcs = PPP_INITFCS;

			ppps->rx = net_pkt_get_reserve_rx(0, K_NO_WAIT);
			if (!ppps->rx) {
				NET_ERR("[%p] cannot allocate pkt", ppps);
				return 0;
			}

			ppps->last = net_pkt_get_frag(ppps->rx, K_NO_WAIT);
			if (!ppps->last) {
				NET_ERR("[%p] cannot allocate 1st data frag",
					ppps);
				net_pkt_unref(ppps->rx);
				ppps->rx = NULL;
				return 0;
			}

			net_pkt_frag_add(ppps->rx, ppps->last);
			ppps->ptr = net_pkt_ip_data(ppps->rx);
		}

		break;
	}

	if (!ppps->last) {
		NET_ERR("No last first=%d c=%02x", (int) ppps->first, (unsigned int) c);
		return 0;
	}

	if (!net_buf_tailroom(ppps->last)) {
		/* We need to allocate a new fragment */
		struct net_buf *frag;

		frag = net_pkt_get_reserve_rx_data(0, K_NO_WAIT);
		if (!frag) {
			NET_ERR("[%p] cannot allocate next data frag",
				ppps);
			net_pkt_unref(ppps->rx);
			ppps->rx = NULL;
			ppps->last = NULL;
			ppps->fcs = PPP_INITFCS;

			return 0;
		}

		net_buf_frag_insert(ppps->last, frag);
		ppps->last = frag;
		ppps->ptr = ppps->last->data;
	}

	ppps->fcs = crc16_byte(ppps->fcs, c);

	/* Discard Address Field and Control Field */
	if (ppps->ptr == net_pkt_ip_data(ppps->rx) &&
		(c == 0xff || c == 0x03))
		return 0;

	/* The net_buf_add_u8() cannot add data to ll header so we need
	 * a way to do it.
	 */
	if (ppps->ptr < ppps->last->data)
		*ppps->ptr = c;
	else
		ppps->ptr = net_buf_add_u8(ppps->last, c);

	ppps->ptr++;

	return 0;
}

static struct ppp_context ppp_context_data;

static void uart_isr(struct device *uart_dev)
{
	struct ppp_context *ppp = &ppp_context_data;
	struct ppps_context *ppps = ppp->data;

	while (uart_irq_update(uart_dev) && uart_irq_rx_ready(uart_dev)) {
		int rx;
		int i;

		if (!uart_irq_rx_ready(uart_dev))
			continue;

		rx = uart_fifo_read(uart_dev, ppps->uart_buf,
				sizeof(ppps->uart_buf));
		if (!rx)
			continue;

		if (rx < 0) {
			NET_ERR("Failed read UART FIFO");
			uart_irq_rx_disable(uart_dev);
			break;
		}

		/* TODO: stop uart in case of overrun issue */
		if (ppp->lcp.state == LCP_CLOSED) {
			if (ppps->user_data && ppps->user_data->recv)
				ppps->user_data->recv(ppp, ppps->uart_buf, rx);
		} else {
			for (i = 0; i < rx; i++) {
				if (ppps_input_byte(ppps, ppps->uart_buf[i]))
					process_msg(ppp);
			}
		}
	}
}

static void ppps_open_handler(struct k_work *work)
{
	struct ppps_context *ppps = CONTAINER_OF(work, struct ppps_context,
						open_work);
	struct ppp_context *ppp = ppps->ppp;
	struct lcp_context *lcp = &ppp->lcp;
	u8_t c;
	int err;

	NET_DBG("%s", __func__);

	if (lcp->state != LCP_CLOSED) {
		NET_ERR("Tried to open not closed connection!");
		ppps->user_data->connect_fail(ppp, -EBUSY);
		return;
	}

	/* Drain the fifo */
	while (uart_fifo_read(ppps->uart_dev, &c, 1))
		;

	uart_irq_callback_set(ppps->uart_dev, uart_isr);
	uart_irq_rx_enable(ppps->uart_dev);

	if (ppps->user_data->connect) {
		err = ppps->user_data->connect(ppp);
		if (err) {
			uart_irq_rx_disable(ppps->uart_dev);
			NET_INFO("Connect script failed");
			ppps->user_data->connect_fail(ppp, err);
			return;
		}
	}

	lcp_open(ppp);
}

static void ppps_close_handler(struct k_work *work)
{
	struct ppps_context *ppps = CONTAINER_OF(work, struct ppps_context,
						close_work);
	struct ppp_context *ppp = ppps->ppp;

	NET_DBG("%s", __func__);

	lcp_close(ppp);
}

static void ppps_finished(struct ppp_context *ppp)
{
	struct ppps_context *ppps = ppp->data;

	NET_DBG("%s", __func__);

	if (ppps->user_data->disconnect) {
		int err;

		err = ppps->user_data->disconnect(ppp);
		if (err)
			NET_ERR("Failed to disconnect: %d\n", err);
	}

	uart_irq_rx_disable(ppps->uart_dev);
}

static int ppps_init(struct device *dev)
{
	struct ppp_context *ppp = dev->driver_data;
	struct ppps_context *ppps = ppp->data;
	const char *uart_name = dev->config->config_info;

	SYS_LOG_DBG("[%p] dev %p", ppps, dev);

	ppps->ppp = ppp;
	ppps->state = STATE_OK;
	ppps->rx = NULL;
	ppps->first = false;

	ppps->uart_dev = device_get_binding(uart_name);
	if (!ppps->uart_dev)
		return -EINVAL;

	k_work_init(&ppps->open_work, ppps_open_handler);
	k_work_init(&ppps->close_work, ppps_close_handler);

	ppp_init(ppp);

	return 0;
}

static void ppps_iface_init(struct net_if *iface)
{
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;

	atomic_set_bit(iface->flags, NET_IF_POINTOPOINT);
	net_if_set_link_addr(iface, "\x00\x00\x00\x00\x00\x00", 6,
			NET_LINK_PPP);

	ppp->iface = iface;
}

static void ppps_writeb(struct ppps_context *ppps, u8_t c)
{
	uart_poll_out(ppps->uart_dev, c);
}

static void ppps_writeb_esc(struct ppps_context *ppps, u8_t c)
{
	if (c < 0x20 || c == PPP_FLAG || c == PPP_ESC) {
		ppps_writeb(ppps, PPP_ESC);
		c ^= PPP_MOD;
	}

	ppps_writeb(ppps, c);
}

static void ppps_writeb_fcs(struct ppps_context *ppps, u8_t c)
{
	ppps->out_fcs = crc16_byte(ppps->out_fcs, c);

	ppps_writeb_esc(ppps, c);
}

static int ppps_iface_send(struct net_if *iface, struct net_pkt *pkt)
{
	struct ppp_context *ppp = net_if_get_device(iface)->driver_data;
	struct ppps_context *ppps = ppp->data;
	struct net_buf *frag;
	u8_t *ll_p;

#if defined(CONFIG_PPP_L2_DEBUG_DUMP)
	net_hexdump_frags("Sending PPP packet", pkt, true);
#endif

	if (!pkt->frags) {
		/* No data? */
		return -ENODATA;
	}

	ppps->out_fcs = PPP_INITFCS;

	ppps_writeb(ppps, PPP_FLAG);
	ppps_writeb_fcs(ppps, 0xff);
	ppps_writeb_fcs(ppps, 0x03);

	for (ll_p = net_pkt_ll(pkt); ll_p != net_pkt_ip_data(pkt); ll_p++)
		ppps_writeb_fcs(ppps, *ll_p);

	for (frag = pkt->frags; frag != NULL; frag = frag->frags) {
		u8_t *ptr = frag->data;
		u8_t *end = ptr + frag->len;

		for (; ptr < end; ptr++)
			ppps_writeb_fcs(ppps, *ptr);
	}

	net_pkt_unref(pkt);

	ppps->out_fcs ^= 0xffff;
	ppps_writeb_esc(ppps, ppps->out_fcs);
	ppps_writeb_esc(ppps, (ppps->out_fcs >> 8));
	ppps_writeb(ppps, PPP_FLAG);

	return 0;
}

static struct ppps_context ppps_context_data;

static struct ppp_context ppp_context_data = {
	.data = &ppps_context_data,
	.finished = ppps_finished,
};

void ppps_open(const struct ppps_user_data *user_data)
{
	struct ppps_context *ppps = &ppps_context_data;
	struct ppp_context *ppp = &ppp_context_data;

	ppp->user_data = &user_data->ppp_user_data;
	ppps->user_data = user_data;
	k_work_submit(&ppps->open_work);
}

void ppps_close(void)
{
	struct ppps_context *ppps = &ppps_context_data;

	k_work_submit(&ppps->close_work);
}

static struct net_if_api ppps_if_api = {
	.init = ppps_iface_init,
	.send = ppps_iface_send,
};

NET_DEVICE_INIT(ppp, "net_ppp", ppps_init, &ppp_context_data,
		CONFIG_PPP_L2_SERIAL_DEV_NAME,
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, &ppps_if_api,
		PPP_L2, NET_L2_GET_CTX_TYPE(PPP_L2), 1500);
