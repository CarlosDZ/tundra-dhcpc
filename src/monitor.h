#ifndef TUNDRA_MONITOR_H
#define TUNDRA_MONITOR_H

#include "apply.h"
#include "monmsg.h"

#include <sys/types.h>

int monitor_run(const char *ifname, const struct apply_opts *ap,
                const char *lease_path, const struct mon_held *held, int fd,
                int sfd, pid_t worker);

#endif
