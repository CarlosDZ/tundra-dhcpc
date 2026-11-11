#ifndef TUNDRA_LEASE_H
#define TUNDRA_LEASE_H

#include "dhcp.h"

#include <stddef.h>
#include <stdint.h>

struct lease_times {
	uint64_t t1_at;
	uint64_t t2_at;
	uint64_t expiry_at;
};

int lease_path(char *buf, size_t size, const char *ifname, const char *key);
/* mac is the address the lease was given to: a lease is only good for it. */
int lease_save(const char *path, const struct dhcp_info *info,
               const struct lease_times *lt, const unsigned char mac[ETH_ALEN]);
int lease_load(const char *path, struct dhcp_info *info, struct lease_times *lt,
               unsigned char mac[ETH_ALEN]);
void lease_remove(const char *path);

#endif
