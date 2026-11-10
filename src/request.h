#ifndef TUNDRA_REQUEST_H
#define TUNDRA_REQUEST_H

#include "dhcp.h"
#include "lease.h"
#include "monmsg.h"

#include <stdint.h>

struct req_chan {
	int fd;
	int done;
	int done_status;
	char done_out[MON_OUT_MAX];
};

int req_apply(struct req_chan *ch, const struct dhcp_info *info,
              uint32_t lifetime);
int req_refresh(struct req_chan *ch, const struct dhcp_info *info,
                uint32_t lifetime);
int req_remove(struct req_chan *ch, const struct dhcp_info *info);
int req_remove_rule(struct req_chan *ch, const struct dhcp_info *info);
int req_probe_start(struct req_chan *ch, uint32_t addr);
void req_probe_stop(struct req_chan *ch);
void req_lease_save(struct req_chan *ch, const struct dhcp_info *info,
                    const struct lease_times *lt);
void req_lease_remove(struct req_chan *ch);

/* 1 with a finished probe, 0 with nothing, -1 when the monitor is gone. */
int req_probe_done(struct req_chan *ch, int *status, char out[MON_OUT_MAX]);

#endif
