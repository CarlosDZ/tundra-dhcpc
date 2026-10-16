#include "udpsock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

int udpsock_open(struct udpsock *us, const char *ifname) {
	us->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (us->fd < 0) {
		perror("socket(AF_INET) error");
		return -1;
	}

	int on = 1;
	if (setsockopt(us->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 ||
	    setsockopt(us->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		perror("setsockopt error");
		udpsock_close(us);
		return -1;
	}
	if (setsockopt(us->fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
	               (socklen_t)strlen(ifname)) < 0) {
		perror("SO_BINDTODEVICE error");
		udpsock_close(us);
		return -1;
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(DHCP_CLIENT_PORT);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(us->fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind error");
		udpsock_close(us);
		return -1;
	}
	return 0;
}

void udpsock_close(struct udpsock *us) {
	if (us->fd >= 0) {
		close(us->fd);
		us->fd = -1;
	}
}

int udpsock_send(const struct udpsock *us, uint32_t dst, const void *payload,
                 size_t len) {
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(DHCP_SERVER_PORT);
	sin.sin_addr.s_addr = dst;

	if (sendto(us->fd, payload, len, 0, (struct sockaddr *)&sin, sizeof(sin)) <
	    0) {
		perror("sendto error");
		return -1;
	}
	return 0;
}

int udpsock_recv(const struct udpsock *us, uint8_t *buf, size_t cap,
                 size_t *len) {
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	ssize_t n = recvfrom(us->fd, buf, cap, MSG_DONTWAIT,
	                     (struct sockaddr *)&from, &fromlen);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return 0;
		perror("recvfrom error");
		return -1;
	}
	if (ntohs(from.sin_port) != DHCP_SERVER_PORT)
		return 0;

	*len = (size_t)n;
	return 1;
}
