#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

static int parse_mac(const char *s, uint8_t mac[ETH_ALEN]) {
	int n = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
	               &mac[2], &mac[3], &mac[4], &mac[5]);
	return n == 6 ? 0 : -1;
}

int main(int argc, char *argv[]) {
	if (argc < 5 || argc > 7) {
		fprintf(stderr, "usage: arpsend <if> <sha> <spa> <tpa> [eth-src] "
		                "[eth-dst]\n");
		return 2;
	}

	struct frame f;
	memset(&f, 0, sizeof(f));
	struct in_addr spa, tpa;
	if (parse_mac(argv[2], f.sha) < 0 ||
	    inet_pton(AF_INET, argv[3], &spa) != 1 ||
	    inet_pton(AF_INET, argv[4], &tpa) != 1) {
		fprintf(stderr, "invalid arguments\n");
		return 2;
	}
	memcpy(f.src, f.sha, ETH_ALEN);
	memset(f.dst, 0xff, ETH_ALEN);
	if ((argc > 5 && parse_mac(argv[5], f.src) < 0) ||
	    (argc > 6 && parse_mac(argv[6], f.dst) < 0)) {
		fprintf(stderr, "invalid MAC\n");
		return 2;
	}
	f.type = htons(ETH_P_ARP);
	f.htype = htons(1);
	f.ptype = htons(ETH_P_IP);
	f.hlen = ETH_ALEN;
	f.plen = 4;
	f.oper = htons(2);
	f.spa = spa.s_addr;
	f.tpa = tpa.s_addr;

	int fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0) {
		perror("socket error");
		return 1;
	}
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = (int)if_nametoindex(argv[1]);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, f.dst, ETH_ALEN);
	if (!sll.sll_ifindex) {
		perror("if_nametoindex error");
		return 1;
	}
	if (sendto(fd, &f, sizeof(f), 0, (struct sockaddr *)&sll, sizeof(sll)) <
	    0) {
		perror("sendto error");
		return 1;
	}
	close(fd);
	return 0;
}
