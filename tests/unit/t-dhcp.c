#include "dhcp/dhcp.c"
#include "test.h"

#include <arpa/inet.h>
#include <string.h>

#define XID 0x11223344u

static const unsigned char mac[ETH_ALEN] = {0x52, 0x54, 0x00, 0xba, 0x5b, 0xe3};

static void reply(uint8_t b[DHCP_MSG_LEN], const uint8_t *opts, size_t n) {
	uint32_t xid = htonl(XID);
	memset(b, 0, DHCP_MSG_LEN);
	b[0] = 2;
	memcpy(b + 4, &xid, 4);
	memcpy(b + 16, "\x0a\x00\x00\x05", 4);
	memcpy(b + 236, "\x63\x82\x53\x63", 4);
	memcpy(b + 240, opts, n);
}

static void test_build(void) {
	uint8_t b[DHCP_MSG_LEN];
	uint32_t addr = inet_addr("10.0.0.5"), srv = inet_addr("10.0.0.1");

	size_t n = dhcp_build_discover(b, htonl(XID), 7, mac);
	CHECK(n == DHCP_MSG_LEN, "discover has the full message length");
	CHECK(b[0] == 1 && b[1] == 1 && b[2] == ETH_ALEN, "discover header");
	CHECK(b[8] == 0 && b[9] == 7, "discover carries secs");
	CHECK(memcmp(b + 28, mac, ETH_ALEN) == 0, "discover carries chaddr");
	CHECK(memcmp(b + 236, "\x63\x82\x53\x63", 4) == 0, "magic cookie");
	CHECK(b[240] == 53 && b[242] == DHCPDISCOVER, "message type first");

	dhcp_build_request(b, htonl(XID), 0, mac, addr, srv);
	CHECK(b[242] == DHCPREQUEST && b[243] == 50 && b[249] == 54,
	      "request carries requested IP and server id");

	dhcp_build_request(b, htonl(XID), 0, mac, addr, 0);
	CHECK(b[243] == 50 && b[249] == 55, "init-reboot request omits server id");

	dhcp_build_decline(b, htonl(XID), mac, addr, srv);
	CHECK(b[242] == DHCPDECLINE && b[8] == 0 && b[9] == 0,
	      "decline type with secs 0");

	dhcp_build_renew(b, htonl(XID), 3, mac, addr);
	CHECK(memcmp(b + 12, &addr, 4) == 0 && b[243] == 55,
	      "renew sets ciaddr and no options 50/54");
}

/* The options a server or a listener can tell this host by: hostname (12),
 * vendor class (60), client identifier (61), user class (77), FQDN (81). */
static int anonymous(const uint8_t b[DHCP_MSG_LEN]) {
	static const uint8_t allowed[] = {OPT_REQUESTED_IP, OPT_MSG_TYPE,
	                                  OPT_SERVER_ID, OPT_PARAM_REQ};
	for (size_t i = 44; i < 236; i++)
		if (b[i])
			return 0;
	size_t i = 240;
	while (i < DHCP_MSG_LEN && b[i] != OPT_END) {
		if (!memchr(allowed, b[i], sizeof(allowed)) || i + 1 >= DHCP_MSG_LEN)
			return 0;
		if (b[i] == OPT_PARAM_REQ)
			for (size_t k = 0; k < b[i + 1]; k++)
				if (!memchr(param_req, b[i + 2 + k], sizeof(param_req)))
					return 0;
		i += 2 + (size_t)b[i + 1];
	}
	for (i++; i < DHCP_MSG_LEN; i++)
		if (b[i])
			return 0;
	return 1;
}

static void test_traceability(void) {
	uint8_t b[DHCP_MSG_LEN];
	uint32_t addr = inet_addr("10.0.0.5"), srv = inet_addr("10.0.0.1");

	dhcp_build_discover(b, htonl(XID), 7, mac);
	CHECK(anonymous(b), "discover identifies the host only by chaddr");
	dhcp_build_request(b, htonl(XID), 0, mac, addr, srv);
	CHECK(anonymous(b), "request identifies the host only by chaddr");
	dhcp_build_request(b, htonl(XID), 0, mac, addr, 0);
	CHECK(anonymous(b), "init-reboot request too");
	dhcp_build_decline(b, htonl(XID), mac, addr, srv);
	CHECK(anonymous(b), "decline too");
	dhcp_build_renew(b, htonl(XID), 3, mac, addr);
	CHECK(anonymous(b), "renew too");

	dhcp_build_discover(b, htonl(XID), 7, mac);
	b[243] = 12;
	CHECK(!anonymous(b), "a hostname option is caught");
	dhcp_build_discover(b, htonl(XID), 7, mac);
	b[50] = 't';
	CHECK(!anonymous(b), "a server name is caught");
}

static void test_parse(void) {
	uint8_t b[DHCP_MSG_LEN];
	struct dhcp_info i;
	const uint8_t ack[] = {53, 1,  5,  54, 4, 10,  0,   0,   1, 51, 4, 0,
	                       0,  14, 16, 1,  4, 255, 255, 255, 0, 3,  4, 10,
	                       0,  0,  1,  58, 4, 0,   0,   7,   8, 59, 4, 0,
	                       0,  12, 78, 6,  4, 9,   9,   9,   9, 255};
	reply(b, ack, sizeof(ack));

	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0, "parses a valid ACK");
	CHECK(i.type == DHCPACK, "message type");
	CHECK(i.yiaddr == inet_addr("10.0.0.5"), "yiaddr");
	CHECK(i.server_id == inet_addr("10.0.0.1"), "server id");
	CHECK(i.mask == inet_addr("255.255.255.0"), "mask");
	CHECK(i.router == inet_addr("10.0.0.1"), "router");
	CHECK(i.dns[0] == inet_addr("9.9.9.9") && i.dns[1] == 0, "dns");
	CHECK(ntohl(i.lease) == 3600 && ntohl(i.t1) == 1800 && ntohl(i.t2) == 3150,
	      "lease, T1 and T2");

	CHECK(dhcp_parse_reply(b, 300, htonl(0xdeadbeef), &i) < 0,
	      "rejects a foreign xid");
	CHECK(dhcp_parse_reply(b, 239, htonl(XID), &i) < 0,
	      "rejects a truncated header");
	b[0] = 1;
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) < 0, "rejects BOOTREQUEST");
	b[0] = 2;
	b[236] = 0;
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) < 0,
	      "rejects a bad magic cookie");

	const uint8_t notype[] = {54, 4, 10, 0, 0, 1, 255};
	reply(b, notype, sizeof(notype));
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) < 0,
	      "rejects a reply without message type");

	const uint8_t hostile[] = {53, 1, 5, 6, 200, 1, 2, 3, 4};
	reply(b, hostile, sizeof(hostile));
	CHECK(dhcp_parse_reply(b, 240 + sizeof(hostile), htonl(XID), &i) == 0 &&
	          i.dns[0] == 0,
	      "ignores an option longer than the message");

	const uint8_t cut[] = {6, 4, 1, 2, 3, 4, 53};
	reply(b, cut, sizeof(cut));
	CHECK(dhcp_parse_reply(b, 240 + sizeof(cut), htonl(XID), &i) < 0,
	      "rejects a truncated message type option");
}

static void test_overload(void) {
	uint8_t b[DHCP_MSG_LEN];
	struct dhcp_info i;
	const uint8_t opts[] = {53, 1, 5, 52, 1, 3, 255};
	const uint8_t file[] = {1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 0, 1, 255};
	const uint8_t sname[] = {6, 4, 9, 9, 9, 9, 255};

	reply(b, opts, sizeof(opts));
	memcpy(b + 108, file, sizeof(file));
	memcpy(b + 44, sname, sizeof(sname));
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0 &&
	          i.mask == inet_addr("255.255.255.0") &&
	          i.router == inet_addr("10.0.0.1") &&
	          i.dns[0] == inet_addr("9.9.9.9"),
	      "overload 3 reads file and sname");

	b[245] = 1;
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0 && i.router &&
	          i.dns[0] == 0,
	      "overload 1 reads file only");

	b[245] = 0;
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0 && i.router == 0,
	      "without overload sname and file are ignored");

	b[245] = 3;
	b[109] = 200;
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0 && i.mask == 0,
	      "ignores a hostile length inside file");
}

static void test_dns(void) {
	uint8_t b[DHCP_MSG_LEN];
	struct dhcp_info i;

	const uint8_t four[] = {53, 1, 5, 6, 16, 9, 9, 9, 9, 1, 1,
	                        1,  1, 8, 8, 8,  8, 4, 4, 4, 4, 255};
	reply(b, four, sizeof(four));
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0 &&
	          i.dns[0] == inet_addr("9.9.9.9") &&
	          i.dns[1] == inet_addr("1.1.1.1") &&
	          i.dns[2] == inet_addr("8.8.8.8"),
	      "keeps the first three DNS servers");

	const uint8_t odd[] = {53, 1, 5, 6, 6, 9, 9, 9, 9, 1, 1, 255};
	reply(b, odd, sizeof(odd));
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0 &&
	          i.dns[0] == inet_addr("9.9.9.9") && i.dns[1] == 0,
	      "ignores a trailing partial address");

	const uint8_t shorty[] = {53, 1, 5, 6, 3, 9, 9, 9, 255};
	reply(b, shorty, sizeof(shorty));
	CHECK(dhcp_parse_reply(b, 300, htonl(XID), &i) == 0 && i.dns[0] == 0,
	      "ignores a DNS option shorter than one address");
}

int main(void) {
	test_build();
	test_traceability();
	test_parse();
	test_overload();
	test_dns();
	return test_summary();
}
