#ifndef TUNDRA_CLIENT_H
#define TUNDRA_CLIENT_H

int client_run(const char *ifname, int has_metric, unsigned int metric,
               unsigned int grace_ms, const char *lease_key, int probe);

#endif
