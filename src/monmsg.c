#include "monmsg.h"

#include <arpa/inet.h>
#include <string.h>

int mon_mask_ok(uint32_t mask) {
	uint32_t inv = ~ntohl(mask);
	return mask && !(inv & (inv + 1));
}

static int addr_ok(uint32_t addr) {
	uint32_t top = ntohl(addr) >> 24;
	return top >= 1 && top <= 223 && top != 127;
}

static int config_ok(const struct mon_req *r) {
	return addr_ok(r->yiaddr) && mon_mask_ok(r->mask) &&
	       (!r->router || addr_ok(r->router));
}

static int is_held(const struct mon_req *r, const struct mon_held *held) {
	return held->set && r->yiaddr == held->yiaddr && r->mask == held->mask &&
	       r->router == held->router;
}

static void copy_config(struct mon_req *to, const struct mon_req *from) {
	to->yiaddr = from->yiaddr;
	to->mask = from->mask;
	to->router = from->router;
}

enum mon_verdict mon_check(const void *buf, size_t len,
                           const struct mon_held *held, int probing,
                           struct mon_req *req) {
	if (len != sizeof(*req))
		return MON_FATAL;
	memcpy(req, buf, sizeof(*req));

	struct mon_req used;
	int ok = 0;
	memset(&used, 0, sizeof(used));
	used.type = req->type;
	switch (req->type) {
	case MON_APPLY:
		copy_config(&used, req);
		used.lifetime = req->lifetime;
		ok = config_ok(req) && req->lifetime;
		break;
	case MON_REFRESH:
		copy_config(&used, req);
		used.lifetime = req->lifetime;
		ok = config_ok(req) && is_held(req, held) && req->lifetime;
		break;
	case MON_REMOVE:
	case MON_REMOVE_RULE:
		copy_config(&used, req);
		ok = config_ok(req) && is_held(req, held);
		break;
	case MON_PROBE_START:
		used.yiaddr = req->yiaddr;
		ok = addr_ok(req->yiaddr) && !probing;
		break;
	case MON_PROBE_STOP:
	case MON_LEASE_REMOVE:
		ok = 1;
		break;
	case MON_LEASE_SAVE:
		used = *req;
		used.lifetime = 0;
		ok = config_ok(req) && is_held(req, held) && req->lease;
		break;
	default:
		return MON_FATAL;
	}

	/* a field the request type does not use must be zero */
	if (memcmp(&used, req, sizeof(used)) != 0)
		return MON_FATAL;
	return ok ? MON_OK : MON_REFUSE;
}
