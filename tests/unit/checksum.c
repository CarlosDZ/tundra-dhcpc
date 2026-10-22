#include "net/rawsock.c"
#include "test.h"

struct pseudo_hdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
} __attribute__((packed));

static void build(uint8_t *pkt, size_t payload) {
	struct ipv4_hdr ip;
	memset(&ip, 0, sizeof(ip));
	ip.ver_ihl = 0x45;
	ip.tot_len = htons((uint16_t)(28 + payload));
	ip.ttl = 64;
	ip.proto = IPPROTO_UDP;
	ip.saddr = inet_addr("10.0.0.1");
	ip.daddr = inet_addr("10.0.0.5");
	ip.csum = inet_csum(&ip, sizeof(ip));

	struct udp_hdr udp = {htons(DHCP_SERVER_PORT), htons(DHCP_CLIENT_PORT),
	                      htons((uint16_t)(8 + payload)), 0};
	memcpy(pkt, &ip, sizeof(ip));
	memcpy(pkt + 20, &udp, sizeof(udp));
	memset(pkt + 28, 0xab, payload);

	struct pseudo_hdr ph = {ip.saddr, ip.daddr, 0, IPPROTO_UDP, udp.len};
	uint32_t sum = csum_add(0, &ph, sizeof(ph));
	uint16_t c = csum_fold(csum_add(sum, pkt + 20, 8 + payload));
	memcpy(pkt + 26, &c, 2);
}

int main(void) {
	uint8_t pkt[64];
	const uint8_t *p;
	size_t len;

	build(pkt, 13);
	CHECK(parse_datagram(pkt, 41, 0, &p, &len) == 0 && len == 13,
	      "accepts a valid datagram with an odd payload");
	CHECK(parse_datagram(pkt, 60, 0, &p, &len) == 0 && len == 13,
	      "ignores Ethernet padding after the datagram");

	pkt[30] ^= 1;
	CHECK(parse_datagram(pkt, 41, 0, &p, &len) < 0,
	      "rejects a corrupted payload");
	CHECK(parse_datagram(pkt, 41, 1, &p, &len) == 0,
	      "trusts a checksum the kernel marked as valid or pending");
	memset(pkt + 26, 0, 2);
	CHECK(parse_datagram(pkt, 41, 0, &p, &len) == 0,
	      "accepts UDP checksum 0 (not computed)");

	build(pkt, 13);
	pkt[10] ^= 1;
	CHECK(parse_datagram(pkt, 41, 0, &p, &len) < 0,
	      "rejects a bad IPv4 header checksum");

	build(pkt, 13);
	CHECK(parse_datagram(pkt, 30, 0, &p, &len) < 0,
	      "rejects a datagram shorter than its header says");

	build(pkt, 13);
	pkt[6] = 0x20;
	pkt[10] = pkt[11] = 0;
	uint16_t c = inet_csum(pkt, 20);
	memcpy(pkt + 10, &c, 2);
	CHECK(parse_datagram(pkt, 41, 0, &p, &len) < 0, "rejects fragments");

	return test_summary();
}
