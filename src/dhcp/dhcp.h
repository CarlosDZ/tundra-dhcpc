#ifndef TUNDRA_DHCP_H
#define TUNDRA_DHCP_H

#include <linux/if_ether.h>
#include <stddef.h>
#include <stdint.h>

#define DHCP_MSG_LEN 548
#define DHCP_MAX_DNS 3

enum {
	DHCPDISCOVER = 1,
	DHCPOFFER = 2,
	DHCPREQUEST = 3,
	DHCPDECLINE = 4,
	DHCPACK = 5,
	DHCPNAK = 6,
};

struct dhcp_info {
	uint8_t type;
	uint32_t yiaddr;
	uint32_t server_id;
	uint32_t mask;
	uint32_t router;
	uint32_t dns[DHCP_MAX_DNS];
	uint32_t lease;
	uint32_t t1;
	uint32_t t2;
};

size_t dhcp_build_discover(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                           uint16_t secs, const unsigned char mac[ETH_ALEN]);
size_t dhcp_build_request(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                          uint16_t secs, const unsigned char mac[ETH_ALEN],
                          uint32_t addr, uint32_t server);

size_t dhcp_build_decline(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                          const unsigned char mac[ETH_ALEN], uint32_t addr,
                          uint32_t server);

size_t dhcp_build_renew(uint8_t buf[DHCP_MSG_LEN], uint32_t xid, uint16_t secs,
                        const unsigned char mac[ETH_ALEN], uint32_t ciaddr);

int dhcp_parse_reply(const uint8_t *msg, size_t len, uint32_t xid,
                     struct dhcp_info *info);

#endif
