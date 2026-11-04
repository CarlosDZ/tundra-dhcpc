#include "dhcp.h"

#include <arpa/inet.h>
#include <string.h>

#define DHCP_MAGIC 0x63825363u
#define DHCP_OPTIONS_LEN 308

enum { BOOTREQUEST = 1, BOOTREPLY = 2 };
enum { OVERLOAD_FILE = 1, OVERLOAD_SNAME = 2 };

enum {
	OPT_PAD = 0,
	OPT_SUBNET_MASK = 1,
	OPT_ROUTER = 3,
	OPT_DNS = 6,
	OPT_REQUESTED_IP = 50,
	OPT_LEASE_TIME = 51,
	OPT_OVERLOAD = 52,
	OPT_MSG_TYPE = 53,
	OPT_SERVER_ID = 54,
	OPT_PARAM_REQ = 55,
	OPT_RENEWAL_TIME = 58,
	OPT_REBINDING_TIME = 59,
	OPT_END = 255,
};

struct dhcp_msg {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic;
	uint8_t options[DHCP_OPTIONS_LEN];
} __attribute__((packed));

#define DHCP_FIXED_LEN offsetof(struct dhcp_msg, options)

_Static_assert(DHCP_FIXED_LEN == 240, "BOOTP header + magic must be 240 bytes");
_Static_assert(sizeof(struct dhcp_msg) == DHCP_MSG_LEN, "DHCP message size");

static const uint8_t param_req[] = {OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS};

static uint8_t *opt_put(uint8_t *o, uint8_t code, uint8_t len,
                        const void *val) {
	*o++ = code;
	*o++ = len;
	memcpy(o, val, len);
	return o + len;
}

static const uint8_t *opt_find(const uint8_t *opts, size_t len, uint8_t code,
                               uint8_t *olen) {
	size_t i = 0;
	while (i < len) {
		uint8_t c = opts[i];
		if (c == OPT_END)
			break;
		if (c == OPT_PAD) {
			i++;
			continue;
		}
		if (i + 1 >= len)
			break;
		uint8_t l = opts[i + 1];
		if (i + 2 + l > len)
			break;
		if (c == code) {
			*olen = l;
			return opts + i + 2;
		}
		i += 2 + l;
	}
	return NULL;
}

struct opt_zones {
	const uint8_t *ptr[3];
	size_t len[3];
	int n;
};

static const uint8_t *zones_find(const struct opt_zones *z, uint8_t code,
                                 uint8_t *olen) {
	for (int i = 0; i < z->n; i++) {
		const uint8_t *v = opt_find(z->ptr[i], z->len[i], code, olen);
		if (v)
			return v;
	}
	return NULL;
}

static void opt_get_addr(const struct opt_zones *z, uint8_t code,
                         uint32_t *out) {
	uint8_t l;
	const uint8_t *v = zones_find(z, code, &l);
	if (v && l >= 4)
		memcpy(out, v, 4);
}

static void opt_get_addrs(const struct opt_zones *z, uint8_t code,
                          uint32_t *out, int max) {
	uint8_t l;
	const uint8_t *v = zones_find(z, code, &l);
	for (int i = 0; v && i < max && (i + 1) * 4 <= l; i++)
		memcpy(&out[i], v + i * 4, 4);
}

static uint8_t *msg_init(struct dhcp_msg *m, uint32_t xid, uint16_t secs,
                         const unsigned char mac[ETH_ALEN], uint8_t type) {
	memset(m, 0, sizeof(*m));
	m->op = BOOTREQUEST;
	m->secs = htons(secs);
	m->htype = 1;
	m->hlen = ETH_ALEN;
	m->xid = xid;
	memcpy(m->chaddr, mac, ETH_ALEN);
	m->magic = htonl(DHCP_MAGIC);
	return opt_put(m->options, OPT_MSG_TYPE, 1, &type);
}

size_t dhcp_build_discover(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                           uint16_t secs, const unsigned char mac[ETH_ALEN]) {
	struct dhcp_msg m;
	uint8_t *o = msg_init(&m, xid, secs, mac, DHCPDISCOVER);
	o = opt_put(o, OPT_PARAM_REQ, sizeof(param_req), param_req);
	*o = OPT_END;

	memcpy(buf, &m, sizeof(m));
	return sizeof(m);
}

size_t dhcp_build_request(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                          uint16_t secs, const unsigned char mac[ETH_ALEN],
                          uint32_t addr, uint32_t server) {
	struct dhcp_msg m;
	uint8_t *o = msg_init(&m, xid, secs, mac, DHCPREQUEST);
	o = opt_put(o, OPT_REQUESTED_IP, 4, &addr);
	if (server)
		o = opt_put(o, OPT_SERVER_ID, 4, &server);
	o = opt_put(o, OPT_PARAM_REQ, sizeof(param_req), param_req);
	*o = OPT_END;

	memcpy(buf, &m, sizeof(m));
	return sizeof(m);
}

size_t dhcp_build_decline(uint8_t buf[DHCP_MSG_LEN], uint32_t xid,
                          const unsigned char mac[ETH_ALEN], uint32_t addr,
                          uint32_t server) {
	struct dhcp_msg m;
	uint8_t *o = msg_init(&m, xid, 0, mac, DHCPDECLINE);
	o = opt_put(o, OPT_REQUESTED_IP, 4, &addr);
	o = opt_put(o, OPT_SERVER_ID, 4, &server);
	*o = OPT_END;

	memcpy(buf, &m, sizeof(m));
	return sizeof(m);
}

size_t dhcp_build_renew(uint8_t buf[DHCP_MSG_LEN], uint32_t xid, uint16_t secs,
                        const unsigned char mac[ETH_ALEN], uint32_t ciaddr) {
	struct dhcp_msg m;
	uint8_t *o = msg_init(&m, xid, secs, mac, DHCPREQUEST);
	m.ciaddr = ciaddr;
	o = opt_put(o, OPT_PARAM_REQ, sizeof(param_req), param_req);
	*o = OPT_END;

	memcpy(buf, &m, sizeof(m));
	return sizeof(m);
}

int dhcp_parse_reply(const uint8_t *msg, size_t len, uint32_t xid,
                     struct dhcp_info *info) {
	if (len < DHCP_FIXED_LEN)
		return -1;

	struct dhcp_msg m;
	memcpy(&m, msg, DHCP_FIXED_LEN);
	if (m.op != BOOTREPLY || m.xid != xid || m.magic != htonl(DHCP_MAGIC))
		return -1;

	struct opt_zones z = {{msg + DHCP_FIXED_LEN}, {len - DHCP_FIXED_LEN}, 1};
	uint8_t l;
	const uint8_t *ov = opt_find(z.ptr[0], z.len[0], OPT_OVERLOAD, &l);
	if (ov && l == 1) {
		if (ov[0] & OVERLOAD_FILE) {
			z.ptr[z.n] = msg + offsetof(struct dhcp_msg, file);
			z.len[z.n++] = sizeof(m.file);
		}
		if (ov[0] & OVERLOAD_SNAME) {
			z.ptr[z.n] = msg + offsetof(struct dhcp_msg, sname);
			z.len[z.n++] = sizeof(m.sname);
		}
	}

	const uint8_t *t = zones_find(&z, OPT_MSG_TYPE, &l);
	if (!t || l != 1)
		return -1;

	memset(info, 0, sizeof(*info));
	info->type = t[0];
	info->yiaddr = m.yiaddr;
	opt_get_addr(&z, OPT_SERVER_ID, &info->server_id);
	opt_get_addr(&z, OPT_SUBNET_MASK, &info->mask);
	opt_get_addr(&z, OPT_ROUTER, &info->router);
	opt_get_addrs(&z, OPT_DNS, info->dns, DHCP_MAX_DNS);
	opt_get_addr(&z, OPT_LEASE_TIME, &info->lease);
	opt_get_addr(&z, OPT_RENEWAL_TIME, &info->t1);
	opt_get_addr(&z, OPT_REBINDING_TIME, &info->t2);
	return 0;
}
