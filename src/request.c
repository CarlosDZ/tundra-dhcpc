#include "request.h"
#include "apply.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int read_rep(struct req_chan *ch, struct mon_rep *rep) {
	ssize_t n;
	do
		n = read(ch->fd, rep, sizeof(*rep));
	while (n < 0 && errno == EINTR);
	if (n != (ssize_t)sizeof(*rep))
		return -1;
	rep->out[sizeof(rep->out) - 1] = '\0';
	return 0;
}

static void keep_done(struct req_chan *ch, const struct mon_rep *rep) {
	ch->done = 1;
	ch->done_status = rep->status;
	memcpy(ch->done_out, rep->out, sizeof(ch->done_out));
}

static int call(struct req_chan *ch, const struct mon_req *req) {
	struct mon_rep rep;
	ssize_t n;

	fflush(stdout);
	do
		n = write(ch->fd, req, sizeof(*req));
	while (n < 0 && errno == EINTR);
	if (n != (ssize_t)sizeof(*req))
		return APPLY_FAIL;

	for (;;) {
		if (read_rep(ch, &rep) < 0)
			return APPLY_FAIL;
		if (rep.type == MON_REPLY)
			return rep.result;
		if (rep.type == MON_PROBE_DONE)
			keep_done(ch, &rep);
	}
}

static int config_req(struct mon_req *req, uint32_t type,
                      const struct dhcp_info *info) {
	if (!mon_mask_ok(info->mask)) {
		fprintf(stderr, "invalid or missing subnet mask in lease\n");
		return -1;
	}
	memset(req, 0, sizeof(*req));
	req->type = type;
	req->yiaddr = info->yiaddr;
	req->mask = info->mask;
	req->router = info->router;
	return 0;
}

int req_apply(struct req_chan *ch, const struct dhcp_info *info,
              uint32_t lifetime) {
	struct mon_req req;
	if (config_req(&req, MON_APPLY, info) < 0)
		return APPLY_FAIL;
	req.lifetime = lifetime;
	return call(ch, &req);
}

int req_refresh(struct req_chan *ch, const struct dhcp_info *info,
                uint32_t lifetime) {
	struct mon_req req;
	if (config_req(&req, MON_REFRESH, info) < 0)
		return APPLY_FAIL;
	req.lifetime = lifetime;
	return call(ch, &req);
}

int req_remove(struct req_chan *ch, const struct dhcp_info *info) {
	struct mon_req req;
	if (config_req(&req, MON_REMOVE, info) < 0)
		return APPLY_FAIL;
	return call(ch, &req);
}

int req_remove_rule(struct req_chan *ch, const struct dhcp_info *info) {
	struct mon_req req;
	if (config_req(&req, MON_REMOVE_RULE, info) < 0)
		return APPLY_FAIL;
	return call(ch, &req);
}

int req_probe_start(struct req_chan *ch, uint32_t addr) {
	struct mon_req req;
	memset(&req, 0, sizeof(req));
	req.type = MON_PROBE_START;
	req.yiaddr = addr;
	ch->done = 0;
	return call(ch, &req);
}

void req_probe_stop(struct req_chan *ch) {
	struct mon_req req;
	memset(&req, 0, sizeof(req));
	req.type = MON_PROBE_STOP;
	call(ch, &req);
	ch->done = 0;
}

void req_lease_save(struct req_chan *ch, const struct dhcp_info *info,
                    const struct lease_times *lt) {
	struct mon_req req;
	memset(&req, 0, sizeof(req));
	req.type = MON_LEASE_SAVE;
	req.yiaddr = info->yiaddr;
	req.mask = info->mask;
	req.router = info->router;
	req.server_id = info->server_id;
	memcpy(req.dns, info->dns, sizeof(req.dns));
	req.lease = info->lease;
	req.t1_at = lt->t1_at;
	req.t2_at = lt->t2_at;
	req.expiry_at = lt->expiry_at;
	call(ch, &req);
}

void req_lease_remove(struct req_chan *ch) {
	struct mon_req req;
	memset(&req, 0, sizeof(req));
	req.type = MON_LEASE_REMOVE;
	call(ch, &req);
}

int req_probe_done(struct req_chan *ch, int *status, char out[MON_OUT_MAX]) {
	if (!ch->done) {
		struct mon_rep rep;
		if (read_rep(ch, &rep) < 0)
			return -1;
		if (rep.type != MON_PROBE_DONE)
			return 0;
		keep_done(ch, &rep);
	}
	ch->done = 0;
	*status = ch->done_status;
	memcpy(out, ch->done_out, MON_OUT_MAX);
	return 1;
}
