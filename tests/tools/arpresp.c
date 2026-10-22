#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

struct frame {
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t type;
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

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "usage: arpresp <if>\n");
		return 2;
	}

	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (fd < 0) {
		perror("socket error");
		return 1;
	}
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = (int)if_nametoindex(argv[1]);
	if (!sll.sll_ifindex ||
	    bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind error");
		return 1;
	}

	for (;;) {
		struct frame f;
		ssize_t n = recv(fd, &f, sizeof(f), 0);
		if (n < 0) {
			perror("recv error");
			return 1;
		}
		if ((size_t)n < sizeof(f) || f.oper != htons(1) || f.spa != 0)
			continue;

		uint8_t mac[ETH_ALEN];
		if (getrandom(mac, sizeof(mac), 0) != sizeof(mac))
			continue;
		mac[0] = (uint8_t)((mac[0] & 0xfe) | 0x02);

		struct frame r = f;
		memcpy(r.dst, f.sha, ETH_ALEN);
		memcpy(r.src, mac, ETH_ALEN);
		r.oper = htons(2);
		memcpy(r.sha, mac, ETH_ALEN);
		r.spa = f.tpa;
		memcpy(r.tha, f.sha, ETH_ALEN);
		r.tpa = 0;
		send(fd, &r, sizeof(r), 0);
	}
}
