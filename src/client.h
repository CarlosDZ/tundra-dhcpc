#ifndef TUNDRA_CLIENT_H
#define TUNDRA_CLIENT_H

#include "apply.h"

int client_run(const char *ifname, const struct apply_opts *ap,
               unsigned int grace_ms, const char *lease_key, int probe,
               int secs_override);

#endif
