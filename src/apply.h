#ifndef TUNDRA_APPLY_H
#define TUNDRA_APPLY_H

#include "dhcp.h"

int apply_lease(const char *ifname, const struct dhcp_info *info,
                int has_metric, unsigned int metric);
int apply_remove(const char *ifname, const struct dhcp_info *info);

#endif
