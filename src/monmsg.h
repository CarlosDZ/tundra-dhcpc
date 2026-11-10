#ifndef TUNDRA_MONMSG_H
#define TUNDRA_MONMSG_H

#include <stddef.h>
#include <stdint.h>

#define MON_OUT_MAX 256

enum mon_type {
	MON_APPLY = 1,
	MON_REFRESH,
	MON_REMOVE,
	MON_REMOVE_RULE,
	MON_PROBE_START,
	MON_PROBE_STOP,
	MON_LEASE_SAVE,
	MON_LEASE_REMOVE,
};

/* Addresses and lease in network byte order, as in struct dhcp_info. */
struct mon_req {
	uint32_t type;
	uint32_t lifetime;
	uint32_t yiaddr;
	uint32_t mask;
	uint32_t router;
	uint32_t server_id;
	uint32_t dns[3];
	uint32_t lease;
	uint64_t t1_at;
	uint64_t t2_at;
	uint64_t expiry_at;
};

enum mon_rep_type { MON_REPLY = 1, MON_PROBE_DONE };

struct mon_rep {
	uint32_t type;
	int32_t result;
	int32_t status;
	char out[MON_OUT_MAX];
};

_Static_assert(sizeof(struct mon_req) == 64, "mon_req must be 64 bytes");
_Static_assert(sizeof(struct mon_rep) == 12 + MON_OUT_MAX,
               "mon_rep must have no padding");

struct mon_held {
	int set;
	uint32_t yiaddr;
	uint32_t mask;
	uint32_t router;
};

enum mon_verdict { MON_OK, MON_REFUSE, MON_FATAL };

int mon_mask_ok(uint32_t mask);
enum mon_verdict mon_check(const void *buf, size_t len,
                           const struct mon_held *held, int probing,
                           struct mon_req *req);

#endif
