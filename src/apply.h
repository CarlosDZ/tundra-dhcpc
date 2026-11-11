#ifndef TUNDRA_APPLY_H
#define TUNDRA_APPLY_H

#include "dhcp.h"

#include <stdint.h>

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
/* unsure: the address may not be there; a missing one is not an error. */
int apply_remove(const char *ifname, const struct dhcp_info *info,
                 const struct apply_opts *opts, int unsure);
int apply_remove_rule(const struct dhcp_info *info,
                      const struct apply_opts *opts);

#endif
