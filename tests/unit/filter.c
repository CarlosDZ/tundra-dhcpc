#include "net/rawsock.c"
#include "test.h"

static size_t datagram(uint8_t *pkt, uint8_t proto, uint16_t dport,
                       uint16_t frag, int ihl) {
	memset(pkt, 0, 64);
	pkt[0] = (uint8_t)(0x40 | ihl);
	pkt[9] = proto;
	uint16_t f = htons(frag);
	memcpy(pkt + 6, &f, 2);
	uint16_t d = htons(dport);
	memcpy(pkt + ihl * 4 + 2, &d, 2);
	return (size_t)(ihl * 4 + 8 + 4);
}

static int passes(int rx, int tx, const uint8_t *pkt, size_t len) {
	uint8_t buf[64];
	if (send(tx, pkt, len, 0) < 0)
		return -1;
	return recv(rx, buf, sizeof(buf), MSG_DONTWAIT) > 0;
}

int main(void) {
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0 || attach_filter(sv[0]) < 0)
		return 1;

	uint8_t pkt[64];
	size_t n;

	n = datagram(pkt, IPPROTO_UDP, DHCP_CLIENT_PORT, 0, 5);
	CHECK(passes(sv[0], sv[1], pkt, n) == 1, "accepts UDP to port 68");
	n = datagram(pkt, IPPROTO_UDP, DHCP_CLIENT_PORT, 0, 6);
	CHECK(passes(sv[0], sv[1], pkt, n) == 1,
	      "accepts UDP to port 68 after IP options");
	n = datagram(pkt, IPPROTO_UDP, DHCP_SERVER_PORT, 0, 5);
	CHECK(passes(sv[0], sv[1], pkt, n) == 0, "drops UDP to another port");
	n = datagram(pkt, IPPROTO_TCP, DHCP_CLIENT_PORT, 0, 5);
	CHECK(passes(sv[0], sv[1], pkt, n) == 0, "drops TCP");
	n = datagram(pkt, IPPROTO_UDP, DHCP_CLIENT_PORT, 0x2000, 5);
	CHECK(passes(sv[0], sv[1], pkt, n) == 0, "drops a first fragment");
	n = datagram(pkt, IPPROTO_UDP, DHCP_CLIENT_PORT, 0x0010, 5);
	CHECK(passes(sv[0], sv[1], pkt, n) == 0, "drops a later fragment");
	n = datagram(pkt, IPPROTO_UDP, DHCP_CLIENT_PORT, 0x4000, 5);
	CHECK(passes(sv[0], sv[1], pkt, n) == 1, "accepts the don't-fragment flag");

	close(sv[0]);
	close(sv[1]);
	return test_summary();
}
