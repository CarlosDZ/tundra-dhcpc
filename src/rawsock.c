#include "rawsock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define UDP_MAX_PAYLOAD (1500 - 20 - 8)

struct ipv4_hdr {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum;
	uint32_t saddr;
	uint32_t daddr;
} __attribute__((packed));

struct udp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t csum;
} __attribute__((packed));

_Static_assert(sizeof(struct ipv4_hdr) == 20, "ipv4_hdr must be 20 bytes");
_Static_assert(sizeof(struct udp_hdr) == 8, "udp_hdr must be 8 bytes");

static uint16_t inet_csum(const void *data, size_t len) {
	const uint8_t *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += (uint32_t)p[0] << 8 | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)p[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons((uint16_t)~sum);
}

static int parse_datagram(const uint8_t *buf, size_t n, const uint8_t **payload,
                          size_t *len) {
	struct ipv4_hdr ip;
	if (n < sizeof(ip))
		return -1;
	memcpy(&ip, buf, sizeof(ip));

	if ((ip.ver_ihl >> 4) != 4)
		return -1;
	size_t ihl = (size_t)(ip.ver_ihl & 0x0f) * 4;
	if (ihl < sizeof(ip) || ihl > n)
		return -1;
	if (inet_csum(buf, ihl) != 0)
		return -1;
	if (ip.proto != IPPROTO_UDP)
		return -1;
	if (ntohs(ip.frag_off) & 0x3fff)
		return -1;

	struct udp_hdr udp;
	size_t tot = ntohs(ip.tot_len);
	if (tot > n || tot < ihl + sizeof(udp))
		return -1;

	memcpy(&udp, buf + ihl, sizeof(udp));
	if (ntohs(udp.sport) != DHCP_SERVER_PORT ||
	    ntohs(udp.dport) != DHCP_CLIENT_PORT)
		return -1;
	size_t ulen = ntohs(udp.len);
	if (ulen < sizeof(udp) || ihl + ulen > tot)
		return -1;

	*payload = buf + ihl + sizeof(udp);
	*len = ulen - sizeof(udp);
	return 0;
}

int rawsock_open(struct rawsock *rs, const char *ifname) {
	rs->fd = -1;

	unsigned int idx = if_nametoindex(ifname);
	if (!idx) {
		fprintf(stderr, "%s: %s\n", ifname, strerror(errno));
		return -1;
	}
	rs->ifindex = (int)idx;

	rs->fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
	if (rs->fd < 0) {
		perror("socket(AF_PACKET) error");
		return -1;
	}

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = rs->ifindex;
	if (bind(rs->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind error");
		rawsock_close(rs);
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(rs->fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("SIOCGIFHWADDR error");
		rawsock_close(rs);
		return -1;
	}
	memcpy(rs->mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

void rawsock_close(struct rawsock *rs) {
	if (rs->fd >= 0) {
		close(rs->fd);
		rs->fd = -1;
	}
}

int rawsock_send(const struct rawsock *rs, const void *payload, size_t len) {
	if (len > UDP_MAX_PAYLOAD) {
		fprintf(stderr, "payload too large: %zu bytes\n", len);
		return -1;
	}

	struct udp_hdr udp;
	memset(&udp, 0, sizeof(udp));
	udp.sport = htons(DHCP_CLIENT_PORT);
	udp.dport = htons(DHCP_SERVER_PORT);
	udp.len = htons((uint16_t)(sizeof(udp) + len));

	struct ipv4_hdr ip;
	size_t total = sizeof(ip) + sizeof(udp) + len;
	memset(&ip, 0, sizeof(ip));
	ip.ver_ihl = 0x45;
	ip.tot_len = htons((uint16_t)total);
	ip.ttl = 64;
	ip.proto = IPPROTO_UDP;
	ip.saddr = htonl(INADDR_ANY);
	ip.daddr = htonl(INADDR_BROADCAST);
	ip.csum = inet_csum(&ip, sizeof(ip));

	uint8_t frame[sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) +
	              UDP_MAX_PAYLOAD];
	memcpy(frame, &ip, sizeof(ip));
	memcpy(frame + sizeof(ip), &udp, sizeof(udp));
	memcpy(frame + sizeof(ip) + sizeof(udp), payload, len);

	struct sockaddr_ll dst;
	memset(&dst, 0, sizeof(dst));
	dst.sll_family = AF_PACKET;
	dst.sll_protocol = htons(ETH_P_IP);
	dst.sll_ifindex = rs->ifindex;
	dst.sll_halen = ETH_ALEN;
	memset(dst.sll_addr, 0xff, ETH_ALEN);

	if (sendto(rs->fd, frame, total, 0, (struct sockaddr *)&dst, sizeof(dst)) <
	    0) {
		perror("sendto error");
		return -1;
	}
	return 0;
}

int rawsock_recv(const struct rawsock *rs, uint8_t *buf, size_t cap,
                 int timeout_ms, const uint8_t **payload, size_t *len) {
	struct pollfd pfd = {.fd = rs->fd, .events = POLLIN};
	int r = poll(&pfd, 1, timeout_ms);
	if (r < 0) {
		if (errno == EINTR)
			return 0;
		perror("poll error");
		return -1;
	}
	if (r == 0)
		return 0;

	ssize_t n = recv(rs->fd, buf, cap, 0);
	if (n < 0) {
		if (errno == EINTR)
			return 0;
		perror("recv error");
		return -1;
	}

	if (parse_datagram(buf, (size_t)n, payload, len) < 0)
		return 0;
	return 1;
}
