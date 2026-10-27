#include "client.h"
#include "apply.h"
#include "arp.h"
#include "conflict.h"
#include "dhcp.h"
#include "gateway.h"
#include "lease.h"
#include "link.h"
#include "rawsock.h"
#include "timing.h"
#include "udpsock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/signalfd.h>
#include <unistd.h>

#define REQUEST_TRIES 4
#define MAX_WAIT_MS 60000
#define PROBE_WAIT_MS 1000
#define PROBE_NUM 3
#define PROBE_MIN_MS 1000
#define PROBE_MAX_MS 2000
#define ANNOUNCE_WAIT_MS 2000
#define ANNOUNCE_NUM 2
#define ANNOUNCE_INTERVAL_MS 2000
#define DECLINE_WAIT_S 10
#define EXIT_USAGE 2
#define EXIT_ALERT 111
#define DEFEND_INTERVAL_S 10

enum state {
	WAITING,
	GRACE,
	SELECTING,
	REQUESTING,
	REBOOTING,
	PROBING,
	ANNOUNCING,
	BOUND,
	RENEWING,
	REBINDING
};

struct client {
	const char *ifname;
	char lease_path[256];
	struct apply_opts ap;
	unsigned int grace_ms;
	int probe;
	int secs_override;
	int exit_code;
	struct rawsock rs;
	struct udpsock us;
	int linkfd;
	int arpfd;
	int probes;
	int announces;
	struct conflicts cs;
	struct gateway gw;
	int carrier;
	int applied;
	enum state state;
	uint32_t xid;
	int tries;
	uint64_t backoff;
	uint64_t retry_ms;
	uint64_t xact_at;
	uint16_t discover_secs;
	struct dhcp_info offer;
	struct dhcp_info lease;
	struct dhcp_info pending;
	uint64_t ack_at;
	struct lease_times lt;
	uint64_t deadline;
};

static const char *ip_str(uint32_t a, char buf[INET_ADDRSTRLEN]) {
	return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

static int new_xid(struct client *c) {
	if (getrandom(&c->xid, sizeof(c->xid), 0) != sizeof(c->xid)) {
		perror("getrandom error");
		return -1;
	}
	return 0;
}

static uint16_t msg_secs(const struct client *c) {
	if (c->secs_override >= 0)
		return (uint16_t)c->secs_override;
	return elapsed_secs(c->xact_at, now_ms());
}

static int send_raw(struct client *c, const uint8_t *msg, size_t len,
                    const char *what) {
	if (rawsock_send(&c->rs, msg, len) == 0)
		printf("%s sent on %s (xid 0x%08x)\n", what, c->ifname, ntohl(c->xid));
	return 0;
}

static int send_discover(struct client *c) {
	uint8_t msg[DHCP_MSG_LEN];
	c->discover_secs = msg_secs(c);
	size_t len = dhcp_build_discover(msg, c->xid, c->discover_secs, c->rs.mac);
	return send_raw(c, msg, len, "DHCPDISCOVER");
}

static int send_request(struct client *c, uint16_t secs, uint32_t addr,
                        uint32_t server) {
	uint8_t msg[DHCP_MSG_LEN];
	size_t len = dhcp_build_request(msg, c->xid, secs, c->rs.mac, addr, server);
	return send_raw(c, msg, len, "DHCPREQUEST");
}

static int send_renew(struct client *c, uint32_t dst) {
	uint8_t msg[DHCP_MSG_LEN];
	size_t len =
	    dhcp_build_renew(msg, c->xid, msg_secs(c), c->rs.mac, c->lease.yiaddr);
	udpsock_send(&c->us, dst, msg, len);
	return 0;
}

static int send_decline(struct client *c, uint32_t addr, uint32_t server) {
	uint8_t msg[DHCP_MSG_LEN];
	size_t len = dhcp_build_decline(msg, c->xid, c->rs.mac, addr, server);
	return send_raw(c, msg, len, "DHCPDECLINE");
}

static void arp_close(struct client *c) {
	if (c->arpfd >= 0) {
		close(c->arpfd);
		c->arpfd = -1;
	}
}

static void drop_address(struct client *c) {
	if (c->applied)
		apply_remove(c->ifname, &c->lease, &c->ap);
	c->applied = 0;
	gateway_stop(&c->gw);
	udpsock_close(&c->us);
	arp_close(c);
}

static int ensure_arp(struct client *c) {
	if (c->arpfd < 0)
		c->arpfd = arp_open(c->rs.ifindex);
	return c->arpfd < 0 ? -1 : 0;
}

static void start_gw_check(struct client *c) {
	if (!c->lease.router || ensure_arp(c) < 0)
		return;
	gateway_start(&c->gw, now_ms());
	arp_request(c->arpfd, c->rs.ifindex, c->rs.mac, c->lease.yiaddr,
	            c->lease.router);
}

static void forget_lease(struct client *c) {
	memset(&c->lease, 0, sizeof(c->lease));
	lease_remove(c->lease_path);
}

static void save_lease(struct client *c) {
	lease_save(c->lease_path, &c->lease, &c->lt);
}

static void wait_carrier(struct client *c) {
	rawsock_close(&c->rs);
	arp_close(c);
	c->state = WAITING;
	c->deadline = UINT64_MAX;
}

static int begin(struct client *c) {
	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	return new_xid(c);
}

static int discover_in(struct client *c, uint64_t delay) {
	forget_lease(c);
	if (begin(c) < 0)
		return -1;
	c->state = SELECTING;
	c->backoff = BACKOFF_START_MS;
	c->deadline = now_ms() + delay;
	c->xact_at = c->deadline;
	if (delay)
		printf("retrying in %llu ms\n", (unsigned long long)delay);
	return 0;
}

static int start_discovery(struct client *c) { return discover_in(c, 0); }

static int retry_later(struct client *c) {
	drop_address(c);
	int r = discover_in(c, c->retry_ms);
	if (c->retry_ms < BACKOFF_MAX_MS)
		c->retry_ms *= 2;
	return r;
}

static int start_reboot(struct client *c) {
	char a[INET_ADDRSTRLEN];

	if (begin(c) < 0)
		return -1;
	c->state = REBOOTING;
	c->tries = 0;
	c->backoff = BACKOFF_START_MS;
	c->xact_at = now_ms();
	c->deadline = backoff_next(&c->backoff, c->xact_at);
	printf("requesting previous address %s\n", ip_str(c->lease.yiaddr, a));
	return send_request(c, msg_secs(c), c->lease.yiaddr, 0);
}

static int lose_lease(struct client *c) {
	drop_address(c);
	return start_discovery(c);
}

static int same_config(const struct dhcp_info *a, const struct dhcp_info *b) {
	return a->yiaddr == b->yiaddr && a->mask == b->mask &&
	       a->router == b->router;
}

static int quit(struct client *c, int code) {
	drop_address(c);
	forget_lease(c);
	c->exit_code = code;
	return -1;
}

static int open_udp(struct client *c) {
	if (c->us.fd < 0 && udpsock_open(&c->us, c->ifname) < 0)
		return -1;
	rawsock_close(&c->rs);
	return 0;
}

static int config_error(struct client *c) {
	fprintf(stderr, "invalid configuration for tundra-ip on %s, giving up\n",
	        c->ifname);
	return quit(c, EXIT_USAGE);
}

static int complete_bind(struct client *c, const struct dhcp_info *ack,
                         uint64_t ack_at) {
	char a[INET_ADDRSTRLEN], s[INET_ADDRSTRLEN];

	int r = apply_lease(c->ifname, ack, &c->ap,
	                    lease_lifetime(ack, ack_at, now_ms()));
	if (r == APPLY_USAGE)
		return config_error(c);
	if (r < 0) {
		fprintf(stderr, "could not apply lease on %s\n", c->ifname);
		return retry_later(c);
	}
	c->applied = 1;
	if (open_udp(c) < 0)
		return retry_later(c);
	c->retry_ms = BACKOFF_START_MS;
	conflicts_new_address(&c->cs);

	c->lease = *ack;
	lease_timers(&c->lt, &c->lease, ack_at);
	save_lease(c);
	printf("bound to %s from %s, lease %u s\n", ip_str(ack->yiaddr, a),
	       ip_str(ack->server_id, s), ntohl(ack->lease));

	if (ensure_arp(c) == 0) {
		arp_request(c->arpfd, c->rs.ifindex, c->rs.mac, c->lease.yiaddr,
		            c->lease.yiaddr);
		c->announces = 1;
		c->state = ANNOUNCING;
		c->deadline = now_ms() + ANNOUNCE_INTERVAL_MS;
		start_gw_check(c);
		return 0;
	}
	c->state = BOUND;
	c->deadline = c->lt.t1_at;
	return 0;
}

static int start_probe(struct client *c, const struct dhcp_info *ack,
                       uint64_t now) {
	char a[INET_ADDRSTRLEN];

	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	if (c->arpfd < 0) {
		c->arpfd = arp_open(c->rs.ifindex);
		if (c->arpfd < 0)
			return -1;
	}
	c->pending = *ack;
	c->ack_at = now;
	c->probes = 0;
	c->state = PROBING;
	c->deadline = now + random_ms(0, PROBE_WAIT_MS);
	printf("probing address %s\n", ip_str(ack->yiaddr, a));
	return 0;
}

static int bind_lease(struct client *c, const struct dhcp_info *ack) {
	char a[INET_ADDRSTRLEN], s[INET_ADDRSTRLEN];
	uint64_t now = now_ms();

	if (!ack->lease) {
		fprintf(stderr, "DHCPACK without lease time\n");
		return lose_lease(c);
	}

	int same = c->applied && same_config(&c->lease, ack);
	if (c->applied == 1 && same) {
		if (open_udp(c) < 0)
			return retry_later(c);
		int r = apply_refresh(c->ifname, ack, &c->ap,
		                      lease_lifetime(ack, now, now_ms()));
		if (r == APPLY_USAGE)
			return config_error(c);
		if (r < 0)
			fprintf(stderr, "could not refresh address lifetime on %s\n",
			        c->ifname);
		c->lease = *ack;
		c->state = BOUND;
		lease_timers(&c->lt, &c->lease, now);
		c->deadline = c->lt.t1_at;
		save_lease(c);
		printf("renewed %s from %s, lease %u s\n", ip_str(ack->yiaddr, a),
		       ip_str(ack->server_id, s), ntohl(ack->lease));
		start_gw_check(c);
		return 0;
	}

	if (c->applied && !same) {
		printf("lease changed, reapplying\n");
		drop_address(c);
	}
	if (!c->probe)
		return complete_bind(c, ack, now);
	return start_probe(c, ack, now);
}

static const char *mac_str(const unsigned char m[ETH_ALEN], char buf[18]) {
	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3],
	         m[4], m[5]);
	return buf;
}

#define FORGED_HINT                                                            \
	"; ARP sender differs from frame source (crafted packet or proxying "      \
	"device)"

static int raise_alert(struct client *c, const char *kind) {
	char a[INET_ADDRSTRLEN], m[18];
	const struct conflicts *cs = &c->cs;

	fprintf(stderr, "alert: %s on %s:", kind, c->ifname);
	for (int i = 0; i < cs->n; i++)
		fprintf(stderr, " %s (%s)", ip_str(cs->recs[i].addr, a),
		        mac_str(cs->recs[i].mac, m));
	if (c->gw.known && conflicts_has_mac(cs, c->gw.mac))
		fprintf(stderr, "; responder uses the gateway MAC (proxy ARP or "
		                "gateway impersonation)");
	if (conflicts_forged(cs))
		fprintf(stderr, FORGED_HINT);
	fprintf(stderr, "\n");
	return quit(c, EXIT_ALERT);
}

static int raise_gw_alert(struct client *c) {
	char a[INET_ADDRSTRLEN], m[18];

	fprintf(stderr, "alert: gateway impersonation (D) on %s: %s claimed by",
	        c->ifname, ip_str(c->lease.router, a));
	for (int i = 0; i < c->gw.nseen; i++)
		fprintf(stderr, " %s", mac_str(c->gw.seen[i], m));
	if (c->gw.forged)
		fprintf(stderr, FORGED_HINT);
	fprintf(stderr, "\n");
	return quit(c, EXIT_ALERT);
}

static int act(struct client *c, enum verdict v, enum alert_kind kind,
               uint32_t addr, uint32_t server,
               const unsigned char mac[ETH_ALEN]) {
	char a[INET_ADDRSTRLEN], m[18];

	switch (v) {
	case V_DEFEND:
		arp_request(c->arpfd, c->rs.ifindex, c->rs.mac, addr, addr);
		printf("defending address %s against %s\n", ip_str(addr, a),
		       mac_str(mac, m));
		return 0;
	case V_HOLD:
		printf("address %s claimed by %s, holding it\n", ip_str(addr, a),
		       mac_str(mac, m));
		return 0;
	case V_GIVE_UP:
	case V_ALERT:
		break;
	}

	printf("address %s in use by %s\n", ip_str(addr, a), mac_str(mac, m));
	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	send_decline(c, addr, server);
	drop_address(c);
	forget_lease(c);
	if (v == V_ALERT)
		return raise_alert(c, alert_name(kind));
	return discover_in(c, scaled_ms(DECLINE_WAIT_S));
}

static int on_gateway(struct client *c) {
	char m[18];

	switch (gateway_settle(&c->gw)) {
	case GW_IMPERSONATED:
		return raise_gw_alert(c);
	case GW_LEARNED:
		printf("gateway is at %s\n", mac_str(c->gw.mac, m));
		return 0;
	case GW_NONE:
		break;
	}
	return 0;
}

static int on_arp(struct client *c) {
	struct arp_msg msg;
	int r = arp_read(c->arpfd, &msg);
	if (r <= 0)
		return r;
	if (memcmp(msg.sha, c->rs.mac, ETH_ALEN) == 0)
		return 0;
	int forged = memcmp(msg.sha, msg.src, ETH_ALEN) != 0;
	enum alert_kind kind;
	enum verdict v;

	switch (c->state) {
	case PROBING:
		if (msg.spa != c->pending.yiaddr &&
		    (msg.spa != 0 || msg.tpa != c->pending.yiaddr))
			return 0;
		v = conflict_probe(&c->cs, c->pending.yiaddr, msg.sha, forged, now_ms(),
		                   &kind);
		return act(c, v, kind, c->pending.yiaddr, c->pending.server_id,
		           msg.sha);
	case ANNOUNCING:
	case BOUND:
	case RENEWING:
	case REBINDING:
		if (msg.spa == c->lease.yiaddr) {
			v = conflict_claim(&c->cs, c->lease.yiaddr, msg.sha, forged,
			                   now_ms(), &kind);
			return act(c, v, kind, c->lease.yiaddr, c->lease.server_id,
			           msg.sha);
		}
		if (c->lease.router && msg.spa == c->lease.router &&
		    gateway_reply(&c->gw, msg.sha, forged) == GW_IMPERSONATED)
			return raise_gw_alert(c);
		return 0;
	case WAITING:
	case GRACE:
	case SELECTING:
	case REQUESTING:
	case REBOOTING:
		break;
	}
	return 0;
}

static int on_carrier_up(struct client *c) {
	printf("carrier acquired on %s\n", c->ifname);
	if (c->lease.yiaddr && now_ms() < c->lt.expiry_at)
		return start_reboot(c);
	drop_address(c);
	return start_discovery(c);
}

static int on_carrier_down(struct client *c) {
	uint64_t now = now_ms();

	printf("carrier lost on %s\n", c->ifname);
	if (!c->applied) {
		wait_carrier(c);
		return 0;
	}
	if (c->grace_ms == 0) {
		printf("removing address\n");
		drop_address(c);
		wait_carrier(c);
		return 0;
	}

	rawsock_close(&c->rs);
	arp_close(c);
	c->state = GRACE;
	c->deadline = now + c->grace_ms;
	if (c->deadline > c->lt.expiry_at)
		c->deadline = c->lt.expiry_at;
	printf("keeping address for %u ms\n", c->grace_ms);
	return 0;
}

static int keep_previous(struct client *c, uint64_t now) {
	printf("no answer, keeping previous lease\n");
	if (c->applied < 0) {
		int r = apply_lease(c->ifname, &c->lease, &c->ap,
		                    lifetime_until(c->lt.expiry_at, now));
		if (r == APPLY_USAGE)
			return config_error(c);
		if (r < 0)
			return retry_later(c);
	}
	c->applied = 1;
	if (open_udp(c) < 0)
		return retry_later(c);
	ensure_arp(c);
	c->state = BOUND;
	c->deadline = c->lt.t1_at;
	return 0;
}

static int on_timeout(struct client *c) {
	char s[INET_ADDRSTRLEN];
	uint64_t now = now_ms();

	switch (c->state) {
	case WAITING:
		c->deadline = UINT64_MAX;
		return 0;
	case GRACE:
		if (now >= c->lt.expiry_at)
			printf("lease expired, removing address\n");
		else
			printf("carrier still down, removing address\n");
		drop_address(c);
		if (now >= c->lt.expiry_at)
			forget_lease(c);
		wait_carrier(c);
		return 0;
	case SELECTING:
		c->deadline = backoff_next(&c->backoff, now);
		return send_discover(c);
	case REQUESTING:
		if (++c->tries >= REQUEST_TRIES) {
			printf("no DHCPACK, restarting discovery\n");
			return start_discovery(c);
		}
		c->deadline = backoff_next(&c->backoff, now);
		return send_request(c, c->discover_secs, c->offer.yiaddr,
		                    c->offer.server_id);
	case REBOOTING:
		if (++c->tries < REQUEST_TRIES) {
			c->deadline = backoff_next(&c->backoff, now);
			return send_request(c, msg_secs(c), c->lease.yiaddr, 0);
		}
		if (c->applied)
			return keep_previous(c, now);
		printf("no answer, restarting discovery\n");
		return start_discovery(c);
	case PROBING:
		if (c->probes < PROBE_NUM) {
			arp_request(c->arpfd, c->rs.ifindex, c->rs.mac, 0,
			            c->pending.yiaddr);
			c->probes++;
			if (c->probes < PROBE_NUM)
				c->deadline = now + random_ms(PROBE_MIN_MS, PROBE_MAX_MS);
			else
				c->deadline = now + ANNOUNCE_WAIT_MS;
			return 0;
		}
		return complete_bind(c, &c->pending, c->ack_at);
	case ANNOUNCING:
		arp_request(c->arpfd, c->rs.ifindex, c->rs.mac, c->lease.yiaddr,
		            c->lease.yiaddr);
		if (++c->announces < ANNOUNCE_NUM) {
			c->deadline = now + ANNOUNCE_INTERVAL_MS;
			return 0;
		}
		c->state = BOUND;
		c->deadline = c->lt.t1_at;
		return 0;
	case BOUND:
		if (new_xid(c) < 0)
			return -1;
		c->state = RENEWING;
		c->xact_at = now;
		printf("renewing lease with %s\n", ip_str(c->lease.server_id, s));
		/* fall through */
	case RENEWING:
		if (now >= c->lt.t2_at) {
			if (new_xid(c) < 0)
				return -1;
			c->state = REBINDING;
			printf("no answer from server, rebinding\n");
			c->deadline = retry_before(now, c->lt.expiry_at);
			return send_renew(c, htonl(INADDR_BROADCAST));
		}
		c->deadline = retry_before(now, c->lt.t2_at);
		return send_renew(c, c->lease.server_id);
	case REBINDING:
		if (now >= c->lt.expiry_at) {
			printf("lease expired, removing address\n");
			return lose_lease(c);
		}
		c->deadline = retry_before(now, c->lt.expiry_at);
		return send_renew(c, htonl(INADDR_BROADCAST));
	}
	return -1;
}

static int on_reply(struct client *c, const struct dhcp_info *r) {
	char a[INET_ADDRSTRLEN], s[INET_ADDRSTRLEN];

	switch (c->state) {
	case WAITING:
	case GRACE:
	case PROBING:
	case ANNOUNCING:
	case BOUND:
		return 0;
	case SELECTING:
		if (r->type != DHCPOFFER || !r->server_id)
			return 0;
		printf("DHCPOFFER %s from %s\n", ip_str(r->yiaddr, a),
		       ip_str(r->server_id, s));
		c->offer = *r;
		c->state = REQUESTING;
		c->tries = 0;
		c->backoff = BACKOFF_START_MS;
		c->deadline = backoff_next(&c->backoff, now_ms());
		return send_request(c, c->discover_secs, c->offer.yiaddr,
		                    c->offer.server_id);
	case REQUESTING:
		if (r->server_id != c->offer.server_id)
			return 0;
		if (r->type == DHCPNAK) {
			printf("DHCPNAK from %s, restarting discovery\n",
			       ip_str(r->server_id, s));
			return start_discovery(c);
		}
		if (r->type != DHCPACK)
			return 0;
		return bind_lease(c, r);
	case RENEWING:
		if (r->server_id != c->lease.server_id)
			return 0;
		/* fall through */
	case REBOOTING:
	case REBINDING:
		if (r->type == DHCPNAK) {
			printf("DHCPNAK from %s, removing address\n",
			       ip_str(r->server_id, s));
			return lose_lease(c);
		}
		if (r->type != DHCPACK)
			return 0;
		return bind_lease(c, r);
	}
	return -1;
}

static int dhcp_fd(const struct client *c) {
	switch (c->state) {
	case SELECTING:
	case REQUESTING:
	case REBOOTING:
		return c->rs.fd;
	case RENEWING:
	case REBINDING:
		return c->us.fd;
	case WAITING:
	case GRACE:
	case PROBING:
	case ANNOUNCING:
	case BOUND:
		break;
	}
	return -1;
}

static int on_packet(struct client *c) {
	uint8_t buf[2048];
	const uint8_t *msg = buf;
	size_t len;
	int r;

	if (dhcp_fd(c) == c->rs.fd)
		r = rawsock_recv(&c->rs, buf, sizeof(buf), 0, &msg, &len);
	else
		r = udpsock_recv(&c->us, buf, sizeof(buf), &len);
	if (r <= 0)
		return r;

	struct dhcp_info info;
	if (dhcp_parse_reply(msg, len, c->xid, &info) < 0)
		return 0;
	return on_reply(c, &info);
}

static int on_link(struct client *c) {
	enum link_event ev;
	if (link_read(c->linkfd, c->rs.ifindex, &ev) < 0)
		return -1;

	switch (ev) {
	case LINK_NONE:
		return 0;
	case LINK_GONE:
		fprintf(stderr, "interface %s removed\n", c->ifname);
		return -1;
	case LINK_UP:
		if (c->carrier == 1)
			return 0;
		c->carrier = 1;
		return on_carrier_up(c);
	case LINK_DOWN:
		if (c->carrier == 0)
			return 0;
		if (c->carrier < 0 && !c->applied) {
			c->carrier = 0;
			printf("waiting for carrier on %s\n", c->ifname);
			return 0;
		}
		c->carrier = 0;
		return on_carrier_down(c);
	}
	return -1;
}

static int open_signals(void) {
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("sigprocmask error");
		return -1;
	}

	int fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (fd < 0)
		perror("signalfd error");
	return fd;
}

static int loop(struct client *c, int sfd) {
	for (;;) {
		uint64_t now = now_ms();
		if (gateway_due(&c->gw, now)) {
			if (on_gateway(c) < 0)
				return c->exit_code;
			continue;
		}
		if (now >= c->deadline) {
			if (on_timeout(c) < 0)
				return c->exit_code;
			continue;
		}

		uint64_t next = c->deadline;
		if (c->gw.until && c->gw.until < next)
			next = c->gw.until;
		uint64_t wait = next - now;
		if (wait > MAX_WAIT_MS)
			wait = MAX_WAIT_MS;

		struct pollfd pfd[4] = {{.fd = dhcp_fd(c), .events = POLLIN},
		                        {.fd = sfd, .events = POLLIN},
		                        {.fd = c->linkfd, .events = POLLIN},
		                        {.fd = c->arpfd, .events = POLLIN}};
		if (poll(pfd, 4, (int)wait) < 0) {
			if (errno == EINTR)
				continue;
			perror("poll error");
			return c->exit_code;
		}

		if (pfd[1].revents & POLLIN) {
			struct signalfd_siginfo si;
			if (read(sfd, &si, sizeof(si)) == sizeof(si))
				printf("received %s, exiting\n", strsignal((int)si.ssi_signo));
			return 0;
		}
		if (pfd[2].revents & POLLIN) {
			if (on_link(c) < 0)
				return c->exit_code;
			continue;
		}
		if (pfd[3].revents & POLLIN) {
			if (on_arp(c) < 0)
				return c->exit_code;
			continue;
		}
		if (pfd[0].revents & POLLIN) {
			if (on_packet(c) < 0)
				return c->exit_code;
		}
	}
}

static void load_lease(struct client *c) {
	char a[INET_ADDRSTRLEN];
	struct lease_times lt;

	if (lease_load(c->lease_path, &c->lease, &lt) < 0)
		return;
	if (now_ms() >= lt.expiry_at) {
		forget_lease(c);
		return;
	}
	c->lt = lt;
	c->applied = -1;
	printf("previous lease %s found\n", ip_str(c->lease.yiaddr, a));
}

int client_run(const char *ifname, const struct apply_opts *ap,
               unsigned int grace_ms, const char *lease_key, int probe,
               int secs_override) {
	struct client c;
	memset(&c, 0, sizeof(c));
	c.ifname = ifname;
	c.ap = *ap;
	c.grace_ms = grace_ms;
	c.probe = probe;
	c.secs_override = secs_override;
	c.exit_code = 1;
	c.us.fd = -1;
	c.arpfd = -1;
	c.carrier = -1;
	c.retry_ms = BACKOFF_START_MS;
	conflicts_init(&c.cs, scaled_ms(DEFEND_INTERVAL_S), !probe);
	gateway_init(&c.gw);
	if (lease_path(c.lease_path, sizeof(c.lease_path), ifname, lease_key) < 0)
		return 1;

	int sfd = open_signals();
	if (sfd < 0)
		return 1;

	int ret = 1;
	if (rawsock_open(&c.rs, ifname) == 0) {
		c.linkfd = link_open();
		if (c.linkfd >= 0) {
			wait_carrier(&c);
			load_lease(&c);
			if (link_request(c.linkfd, c.rs.ifindex) == 0)
				ret = loop(&c, sfd);
			close(c.linkfd);
		}
	}

	rawsock_close(&c.rs);
	udpsock_close(&c.us);
	arp_close(&c);
	close(sfd);
	return ret;
}
