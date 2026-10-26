#ifndef TUNDRA_APPLY_H
#define TUNDRA_APPLY_H

#include "dhcp.h"

#include <stdint.h>

#define LIFETIME_FOREVER 0xffffffffu
#define APPLY_FAIL -1
#define APPLY_USAGE -2

struct apply_opts {
	int has_metric;
	unsigned int metric;
	const char *table;
	unsigned int priority;
};

int apply_check_table(const char *table);
int apply_lease(const char *ifname, const struct dhcp_info *info,
                const struct apply_opts *opts, uint32_t lifetime);
int apply_refresh(const char *ifname, const struct dhcp_info *info,
                  const struct apply_opts *opts, uint32_t lifetime);
void apply_remove(const char *ifname, const struct dhcp_info *info,
                  const struct apply_opts *opts);

#endif
