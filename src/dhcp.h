#ifndef TUNDRA_DHCPC_DHCP_H
#define TUNDRA_DHCPC_DHCP_H

#include <linux/if_ether.h>
#include <stddef.h>
#include <stdint.h>

#define DHCP_MSG_LEN 548

enum {
	DHCPDISCOVER = 1,
	DHCPOFFER = 2,
	DHCPREQUEST = 3,
	DHCPACK = 5,
	DHCPNAK = 6,
};

struct dhcp_info {
	uint8_t type;
	uint32_t yiaddr;
	uint32_t server_id;
	uint32_t mask;
	uint32_t router;
	uint32_t dns;
	uint32_t lease;
};

size_t dhcp_build_discover(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                           const uint8_t mac[ETH_ALEN]);
size_t dhcp_build_request(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                          const uint8_t mac[ETH_ALEN], uint32_t addr,
                          uint32_t server);

int dhcp_parse_reply(const uint8_t *msg, size_t len, uint32_t xid,
                     struct dhcp_info *info);

#endif
