#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	if (argc != 3) {
		fprintf(stderr, "usage: dhcpsecs <if> <count>\n");
		return 2;
	}
	int count = atoi(argv[2]);

	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0) {
		perror("socket error");
		return 1;
	}
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = (int)if_nametoindex(argv[1]);
	if (!sll.sll_ifindex ||
	    bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind error");
		return 1;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	while (count > 0) {
		uint8_t buf[1500];
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			perror("recv error");
			return 1;
		}
		if (n < 20 || buf[9] != IPPROTO_UDP)
			continue;
		size_t ihl = (size_t)(buf[0] & 0x0f) * 4;
		if ((size_t)n < ihl + 8 + 12 || buf[ihl + 2] != 0 || buf[ihl + 3] != 67)
			continue;
		const uint8_t *msg = buf + ihl + 8;
		if (msg[0] != 1)
			continue;
		printf("%u\n", (unsigned int)(msg[8] << 8 | msg[9]));
		count--;
	}
	close(fd);
	return 0;
}
