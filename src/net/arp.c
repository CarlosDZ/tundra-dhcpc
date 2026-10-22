#include "arp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ARP_REQUEST 1

struct arp_pkt {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper;
	uint8_t sha[ETH_ALEN];
	uint32_t spa;
	uint8_t tha[ETH_ALEN];
	uint32_t tpa;
} __attribute__((packed));

_Static_assert(sizeof(struct arp_pkt) == 28, "ARP packet must be 28 bytes");

int arp_open(int ifindex) {
	int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_ARP));
	if (fd < 0) {
		perror("socket(AF_PACKET) error");
		return -1;
	}

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind error");
		close(fd);
		return -1;
	}
	return fd;
}

int arp_request(int fd, int ifindex, const unsigned char mac[ETH_ALEN],
                uint32_t spa, uint32_t tpa) {
	struct arp_pkt p;
	memset(&p, 0, sizeof(p));
	p.htype = htons(1);
	p.ptype = htons(ETH_P_IP);
	p.hlen = ETH_ALEN;
	p.plen = 4;
	p.oper = htons(ARP_REQUEST);
	memcpy(p.sha, mac, ETH_ALEN);
	p.spa = spa;
	p.tpa = tpa;

	struct sockaddr_ll dst;
	memset(&dst, 0, sizeof(dst));
	dst.sll_family = AF_PACKET;
	dst.sll_protocol = htons(ETH_P_ARP);
	dst.sll_ifindex = ifindex;
	dst.sll_halen = ETH_ALEN;
	memset(dst.sll_addr, 0xff, ETH_ALEN);

	if (sendto(fd, &p, sizeof(p), 0, (struct sockaddr *)&dst, sizeof(dst)) <
	    0) {
		perror("sendto error");
		return -1;
	}
	return 0;
}

int arp_read(int fd, struct arp_msg *m) {
	struct arp_pkt p;
	ssize_t n = recv(fd, &p, sizeof(p), MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return 0;
		perror("recv error");
		return -1;
	}
	if ((size_t)n < sizeof(p) || p.htype != htons(1) ||
	    p.ptype != htons(ETH_P_IP) || p.hlen != ETH_ALEN || p.plen != 4)
		return 0;

	m->oper = ntohs(p.oper);
	memcpy(m->sha, p.sha, ETH_ALEN);
	m->spa = p.spa;
	m->tpa = p.tpa;
	return 1;
}
