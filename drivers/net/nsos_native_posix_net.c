/**
 * Copyright (c) 2026 Marcin Niestroj
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 *
 * POSIX networking wrappers for NSOS with CONFIG_NATIVE_LIBC.
 *
 * When CONFIG_NATIVE_LIBC is set, the POSIX portability layer is not compiled,
 * so POSIX socket functions (getaddrinfo, socket, connect, etc.) resolve to the
 * host libc. This breaks socket offloading because:
 *   1. The calls bypass the Zephyr socket offload mechanism entirely.
 *   2. The app uses Zephyr constant values (e.g., AF_INET=1) which differ from
 *      the host libc values (e.g., AF_INET=2 on Linux).
 *
 * This file provides POSIX networking function wrappers that redirect to Zephyr's
 * zsock_* implementations when NSOS is used with native libc.
 */

#include <zephyr/net/socket.h>

int getaddrinfo(const char *host, const char *service,
		const struct zsock_addrinfo *hints,
		struct zsock_addrinfo **res)
{
	return zsock_getaddrinfo(host, service, hints, res);
}

void freeaddrinfo(struct zsock_addrinfo *ai)
{
	zsock_freeaddrinfo(ai);
}

const char *gai_strerror(int errcode)
{
	return zsock_gai_strerror(errcode);
}

int socket(int family, int type, int proto)
{
	return zsock_socket(family, type, proto);
}

int close(int fd)
{
	return zsock_close(fd);
}

int connect(int sock, const struct net_sockaddr *addr, net_socklen_t addrlen)
{
	return zsock_connect(sock, (const struct sockaddr *)addr, (socklen_t)addrlen);
}

ssize_t send(int sock, const void *buf, size_t len, int flags)
{
	return zsock_send(sock, buf, len, flags);
}

ssize_t recv(int sock, void *buf, size_t max_len, int flags)
{
	return zsock_recv(sock, buf, max_len, flags);
}

int setsockopt(int sock, int level, int optname,
	       const void *optval, net_socklen_t optlen)
{
	return zsock_setsockopt(sock, level, optname, optval, (socklen_t)optlen);
}

int bind(int sock, const struct net_sockaddr *addr, net_socklen_t addrlen)
{
	return zsock_bind(sock, (const struct sockaddr *)addr, (socklen_t)addrlen);
}

int listen(int sock, int backlog)
{
	return zsock_listen(sock, backlog);
}

int accept(int sock, struct net_sockaddr *addr, net_socklen_t *addrlen)
{
	return zsock_accept(sock, (struct sockaddr *)addr, (socklen_t *)addrlen);
}

ssize_t sendto(int sock, const void *buf, size_t len, int flags,
	       const struct net_sockaddr *dest_addr, net_socklen_t addrlen)
{
	return zsock_sendto(sock, buf, len, flags,
			    (const struct sockaddr *)dest_addr, (socklen_t)addrlen);
}

ssize_t recvfrom(int sock, void *buf, size_t max_len, int flags,
		 struct net_sockaddr *src_addr, net_socklen_t *addrlen)
{
	return zsock_recvfrom(sock, buf, max_len, flags,
			      (struct sockaddr *)src_addr, (socklen_t *)addrlen);
}
