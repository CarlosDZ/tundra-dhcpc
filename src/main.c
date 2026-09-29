#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "dhcp.h"
#include "rawsock.h"

#define REPLY_TIMEOUT_MS 10000

static long elapsed_ms(const struct timespec *t0) {
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - t0->tv_sec) * 1000 +
	       (now.tv_nsec - t0->tv_nsec) / 1000000;
}

static int wait_reply(const struct rawsock *rs, uint32_t xid, unsigned int want,
                      uint32_t server, struct dhcp_info *info) {
	uint8_t buf[2048];
	struct timespec t0;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		long left = REPLY_TIMEOUT_MS - elapsed_ms(&t0);
		const uint8_t *msg;
		size_t len;
		int r;

		if (left <= 0)
			return 0;

		r = rawsock_recv(rs, buf, sizeof buf, (int)left, &msg, &len);
		if (r < 0)
			return -1;
		if (r == 0)
			continue;

		if (dhcp_parse_reply(msg, len, xid, info) < 0)
			continue;
		if (info->type > 31 || !(want & (1u << info->type)))
			continue;
		if (server && info->server_id != server)
			continue;
		return 1;
	}
}

static void print_ip(const char *label, uint32_t a) {
	char s[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &a, s, sizeof s);
	printf("  %-8s %s\n", label, s);
}

static void print_info(const char *what, const struct dhcp_info *info) {
	printf("%s received\n", what);
	print_ip("address", info->yiaddr);
	if (info->server_id)
		print_ip("server", info->server_id);
	if (info->mask)
		printf("  %-8s /%d\n", "prefix", __builtin_popcount(ntohl(info->mask)));
	if (info->router)
		print_ip("router", info->router);
	if (info->dns)
		print_ip("dns", info->dns);
	if (info->lease)
		printf("  %-8s %u s\n", "lease", ntohl(info->lease));
}

int main(int argc, char **argv) {
	struct rawsock rs;
	struct dhcp_info offer, ack;
	uint8_t msg[DHCP_MSG_LEN];
	uint32_t xid;
	size_t len;
	int r;

	if (argc != 2) {
		fprintf(stderr, "usage: tundra-dhcpc <interface>\n");
		return 2;
	}
	if (strcmp(argv[1], "--version") == 0) {
		printf("tundra-dhcpc %s\n", TUNDRA_DHCPC_VERSION);
		return 0;
	}

	if (rawsock_open(&rs, argv[1]) < 0)
		return 1;

	if (getrandom(&xid, sizeof xid, 0) != sizeof xid) {
		perror("getrandom error");
		goto fail;
	}

	len = dhcp_build_discover(msg, xid, rs.mac);
	if (rawsock_send(&rs, msg, len) < 0)
		goto fail;
	printf("DHCPDISCOVER sent on %s (xid 0x%08x)\n", argv[1], ntohl(xid));

	r = wait_reply(&rs, xid, 1u << DHCPOFFER, 0, &offer);
	if (r < 0)
		goto fail;
	if (r == 0) {
		fprintf(stderr, "no DHCPOFFER within %d ms\n", REPLY_TIMEOUT_MS);
		goto fail;
	}
	print_info("DHCPOFFER", &offer);
	if (!offer.server_id) {
		fprintf(stderr, "DHCPOFFER without server identifier\n");
		goto fail;
	}

	len = dhcp_build_request(msg, xid, rs.mac, offer.yiaddr, offer.server_id);
	if (rawsock_send(&rs, msg, len) < 0)
		goto fail;
	printf("DHCPREQUEST sent\n");

	r = wait_reply(&rs, xid, 1u << DHCPACK | 1u << DHCPNAK, offer.server_id,
	               &ack);
	if (r < 0)
		goto fail;
	if (r == 0) {
		fprintf(stderr, "no DHCPACK within %d ms\n", REPLY_TIMEOUT_MS);
		goto fail;
	}
	if (ack.type == DHCPNAK) {
		fprintf(stderr, "DHCPNAK from server\n");
		goto fail;
	}
	print_info("DHCPACK", &ack);

	rawsock_close(&rs);
	return 0;

fail:
	rawsock_close(&rs);
	return 1;
}
