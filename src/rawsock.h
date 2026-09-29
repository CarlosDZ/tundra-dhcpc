#ifndef TUNDRA_DHCPC_RAWSOCK_H
#define TUNDRA_DHCPC_RAWSOCK_H

#include <linux/if_ether.h>
#include <stddef.h>
#include <stdint.h>

struct rawsock {
	int fd;
	int ifindex;
	uint8_t mac[ETH_ALEN];
};

int rawsock_open(struct rawsock *rs, const char *ifname);
void rawsock_close(struct rawsock *rs);

int rawsock_send(const struct rawsock *rs, const void *payload, size_t len);

int rawsock_recv(const struct rawsock *rs, uint8_t *buf, size_t cap,
                 int timeout_ms, const uint8_t **payload, size_t *len);

#endif
