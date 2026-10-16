#include "client.h"
#include "apply.h"
#include "arp.h"
#include "dhcp.h"
#include "lease.h"
#include "link.h"
#include "rawsock.h"
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
#include <time.h>
#include <unistd.h>

#define BACKOFF_START_MS 4000
#define BACKOFF_MAX_MS 64000
#define JITTER_MS 1000
#define REQUEST_TRIES 4
#define RENEW_MIN_MS 60000
#define MAX_WAIT_MS 60000
#define LEASE_INFINITE 0xffffffffu
#define PROBE_WAIT_MS 1000
#define PROBE_NUM 3
#define PROBE_MIN_MS 1000
#define PROBE_MAX_MS 2000
#define ANNOUNCE_WAIT_MS 2000
#define ANNOUNCE_NUM 2
#define ANNOUNCE_INTERVAL_MS 2000
#define DECLINE_WAIT_MS 10000
#define MAX_CONFLICTS 3
#define EXIT_ALERT 111

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
	int has_metric;
	unsigned int metric;
	unsigned int grace_ms;
	int probe;
	int exit_code;
	struct rawsock rs;
	struct udpsock us;
	int linkfd;
	int arpfd;
	int probes;
	int announces;
	int conflicts;
	uint32_t conflict_addr[MAX_CONFLICTS];
	unsigned char conflict_mac[MAX_CONFLICTS][ETH_ALEN];
	int carrier;
	int applied;
	enum state state;
	uint32_t xid;
	int tries;
	uint64_t backoff;
	uint64_t retry_ms;
	struct dhcp_info offer;
	struct dhcp_info lease;
	struct dhcp_info pending;
	uint64_t ack_at;
	uint64_t t1_at;
	uint64_t t2_at;
	uint64_t expiry_at;
	uint64_t deadline;
};

static uint64_t now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint64_t scaled_ms(uint64_t secs) {
	return secs * 1000 / TUNDRA_DHCPC_TIME_SCALE;
}

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

static uint64_t random_ms(uint64_t min, uint64_t max) {
	uint32_t r = 0;
	if (getrandom(&r, sizeof(r), 0) != sizeof(r))
		return min;
	return min + r % (max - min + 1);
}

static void arm_retry(struct client *c, uint64_t now) {
	uint32_t r = 0;
	if (getrandom(&r, sizeof(r), 0) != sizeof(r))
		r = JITTER_MS;
	c->deadline = now + c->backoff - JITTER_MS + r % (2 * JITTER_MS + 1);
	if (c->backoff < BACKOFF_MAX_MS)
		c->backoff *= 2;
}

static uint64_t next_retry(uint64_t now, uint64_t limit) {
	uint64_t wait = (limit - now) / 2;
	uint64_t min = scaled_ms(RENEW_MIN_MS / 1000);
	if (wait < min)
		wait = min;
	return now + wait < limit ? now + wait : limit;
}

static int send_discover(struct client *c) {
	uint8_t msg[DHCP_MSG_LEN];
	size_t len = dhcp_build_discover(msg, c->xid, c->rs.mac);
	if (rawsock_send(&c->rs, msg, len) < 0)
		return 0;
	printf("DHCPDISCOVER sent on %s (xid 0x%08x)\n", c->ifname, ntohl(c->xid));
	return 0;
}

static int send_request(struct client *c, uint32_t addr, uint32_t server) {
	uint8_t msg[DHCP_MSG_LEN];
	size_t len = dhcp_build_request(msg, c->xid, c->rs.mac, addr, server);
	if (rawsock_send(&c->rs, msg, len) < 0)
		return 0;
	printf("DHCPREQUEST sent\n");
	return 0;
}

static int send_renew(struct client *c, uint32_t dst) {
	uint8_t msg[DHCP_MSG_LEN];
	size_t len = dhcp_build_renew(msg, c->xid, c->rs.mac, c->lease.yiaddr);
	udpsock_send(&c->us, dst, msg, len);
	return 0;
}

static int send_decline(struct client *c) {
	uint8_t msg[DHCP_MSG_LEN];
	size_t len = dhcp_build_decline(msg, c->xid, c->rs.mac, c->pending.yiaddr,
	                                c->pending.server_id);
	if (rawsock_send(&c->rs, msg, len) < 0)
		return 0;
	printf("DHCPDECLINE sent\n");
	return 0;
}

static void arp_close(struct client *c) {
	if (c->arpfd >= 0) {
		close(c->arpfd);
		c->arpfd = -1;
	}
}

static void drop_address(struct client *c) {
	if (c->applied)
		apply_remove(c->ifname, &c->lease);
	c->applied = 0;
	udpsock_close(&c->us);
}

static void forget_lease(struct client *c) {
	memset(&c->lease, 0, sizeof(c->lease));
	lease_remove(c->lease_path);
}

static void save_lease(struct client *c) {
	struct lease_times lt = {c->t1_at, c->t2_at, c->expiry_at};
	lease_save(c->lease_path, &c->lease, &lt);
}

static void wait_carrier(struct client *c) {
	rawsock_close(&c->rs);
	arp_close(c);
	c->state = WAITING;
	c->deadline = UINT64_MAX;
}

static int start_discovery(struct client *c) {
	forget_lease(c);
	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	if (new_xid(c) < 0)
		return -1;
	c->state = SELECTING;
	c->backoff = BACKOFF_START_MS;
	arm_retry(c, now_ms());
	return send_discover(c);
}

static int start_reboot(struct client *c) {
	char a[INET_ADDRSTRLEN];

	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	if (new_xid(c) < 0)
		return -1;
	c->state = REBOOTING;
	c->tries = 0;
	c->backoff = BACKOFF_START_MS;
	arm_retry(c, now_ms());
	printf("requesting previous address %s\n", ip_str(c->lease.yiaddr, a));
	return send_request(c, c->lease.yiaddr, 0);
}

static int defer_discovery(struct client *c) {
	forget_lease(c);
	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	if (new_xid(c) < 0)
		return -1;
	c->state = SELECTING;
	c->backoff = BACKOFF_START_MS;
	c->deadline = now_ms() + c->retry_ms;
	printf("retrying in %llu ms\n", (unsigned long long)c->retry_ms);
	if (c->retry_ms < BACKOFF_MAX_MS)
		c->retry_ms *= 2;
	return 0;
}

static int lose_lease(struct client *c) {
	drop_address(c);
	return start_discovery(c);
}

static int same_config(const struct dhcp_info *a, const struct dhcp_info *b) {
	return a->yiaddr == b->yiaddr && a->mask == b->mask &&
	       a->router == b->router;
}

static void set_timers(struct client *c, uint64_t now) {
	uint32_t lease = ntohl(c->lease.lease);
	if (lease == LEASE_INFINITE) {
		c->t1_at = c->t2_at = c->expiry_at = UINT64_MAX;
		return;
	}

	uint32_t t1 = ntohl(c->lease.t1);
	uint32_t t2 = ntohl(c->lease.t2);
	if (!t2 || t2 >= lease)
		t2 = (uint32_t)((uint64_t)lease * 7 / 8);
	if (!t1 || t1 >= t2)
		t1 = lease / 2;

	c->t1_at = now + scaled_ms(t1);
	c->t2_at = now + scaled_ms(t2);
	c->expiry_at = now + scaled_ms(lease);
}

static int complete_bind(struct client *c, const struct dhcp_info *ack,
                         uint64_t ack_at) {
	char a[INET_ADDRSTRLEN], s[INET_ADDRSTRLEN];

	if (apply_lease(c->ifname, ack, c->has_metric, c->metric) < 0) {
		fprintf(stderr, "could not apply lease on %s\n", c->ifname);
		drop_address(c);
		arp_close(c);
		return defer_discovery(c);
	}
	c->applied = 1;
	if (c->us.fd < 0 && udpsock_open(&c->us, c->ifname) < 0) {
		drop_address(c);
		arp_close(c);
		return defer_discovery(c);
	}
	rawsock_close(&c->rs);
	c->retry_ms = BACKOFF_START_MS;
	c->conflicts = 0;

	c->lease = *ack;
	set_timers(c, ack_at);
	save_lease(c);
	printf("bound to %s from %s, lease %u s\n", ip_str(ack->yiaddr, a),
	       ip_str(ack->server_id, s), ntohl(ack->lease));

	if (c->arpfd < 0)
		c->arpfd = arp_open(c->rs.ifindex);
	if (c->arpfd >= 0) {
		arp_announce(c->arpfd, c->rs.ifindex, c->rs.mac, c->lease.yiaddr);
		c->announces = 1;
		c->state = ANNOUNCING;
		c->deadline = now_ms() + ANNOUNCE_INTERVAL_MS;
		return 0;
	}
	c->state = BOUND;
	c->deadline = c->t1_at;
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
		if (c->us.fd < 0 && udpsock_open(&c->us, c->ifname) < 0) {
			drop_address(c);
			return defer_discovery(c);
		}
		rawsock_close(&c->rs);
		c->lease = *ack;
		c->state = BOUND;
		set_timers(c, now);
		c->deadline = c->t1_at;
		save_lease(c);
		printf("renewed %s from %s, lease %u s\n", ip_str(ack->yiaddr, a),
		       ip_str(ack->server_id, s), ntohl(ack->lease));
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

static int restart_after(struct client *c, uint64_t ms) {
	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	if (new_xid(c) < 0)
		return -1;
	c->state = SELECTING;
	c->backoff = BACKOFF_START_MS;
	c->deadline = now_ms() + ms;
	printf("restarting discovery in %llu ms\n", (unsigned long long)ms);
	return 0;
}

static void alert(struct client *c) {
	char a[INET_ADDRSTRLEN];

	fprintf(stderr,
	        "alert: %d consecutive address conflicts on %s:", c->conflicts,
	        c->ifname);
	for (int i = 0; i < c->conflicts; i++) {
		const unsigned char *m = c->conflict_mac[i];
		fprintf(stderr, " %s (%02x:%02x:%02x:%02x:%02x:%02x)",
		        ip_str(c->conflict_addr[i], a), m[0], m[1], m[2], m[3], m[4],
		        m[5]);
	}
	fprintf(stderr, "\n");
}

static int on_conflict(struct client *c, const unsigned char mac[ETH_ALEN]) {
	char a[INET_ADDRSTRLEN];

	printf("address %s in use by %02x:%02x:%02x:%02x:%02x:%02x\n",
	       ip_str(c->pending.yiaddr, a), mac[0], mac[1], mac[2], mac[3], mac[4],
	       mac[5]);
	c->conflict_addr[c->conflicts] = c->pending.yiaddr;
	memcpy(c->conflict_mac[c->conflicts], mac, ETH_ALEN);
	c->conflicts++;

	send_decline(c);
	arp_close(c);
	drop_address(c);
	forget_lease(c);

	if (c->conflicts >= MAX_CONFLICTS) {
		alert(c);
		c->exit_code = EXIT_ALERT;
		return -1;
	}
	return restart_after(c, DECLINE_WAIT_MS);
}

static int on_carrier_up(struct client *c) {
	printf("carrier acquired on %s\n", c->ifname);
	if (c->lease.yiaddr && now_ms() < c->expiry_at)
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
	if (c->deadline > c->expiry_at)
		c->deadline = c->expiry_at;
	printf("keeping address for %u ms\n", c->grace_ms);
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
		if (now >= c->expiry_at)
			printf("lease expired, removing address\n");
		else
			printf("carrier still down, removing address\n");
		drop_address(c);
		if (now >= c->expiry_at)
			forget_lease(c);
		wait_carrier(c);
		return 0;
	case SELECTING:
		arm_retry(c, now);
		return send_discover(c);
	case REQUESTING:
		if (++c->tries >= REQUEST_TRIES) {
			printf("no DHCPACK, restarting discovery\n");
			return start_discovery(c);
		}
		arm_retry(c, now);
		return send_request(c, c->offer.yiaddr, c->offer.server_id);
	case REBOOTING:
		if (++c->tries >= REQUEST_TRIES) {
			if (c->applied) {
				printf("no answer, keeping previous lease\n");
				if (c->applied < 0 &&
				    apply_lease(c->ifname, &c->lease, c->has_metric,
				                c->metric) < 0) {
					drop_address(c);
					return defer_discovery(c);
				}
				c->applied = 1;
				if (c->us.fd < 0 && udpsock_open(&c->us, c->ifname) < 0) {
					drop_address(c);
					return defer_discovery(c);
				}
				rawsock_close(&c->rs);
				c->state = BOUND;
				c->deadline = c->t1_at;
				return 0;
			}
			printf("no answer, restarting discovery\n");
			return start_discovery(c);
		}
		arm_retry(c, now);
		return send_request(c, c->lease.yiaddr, 0);
	case PROBING:
		if (c->probes < PROBE_NUM) {
			arp_probe(c->arpfd, c->rs.ifindex, c->rs.mac, c->pending.yiaddr);
			c->probes++;
			if (c->probes < PROBE_NUM)
				c->deadline = now + random_ms(PROBE_MIN_MS, PROBE_MAX_MS);
			else
				c->deadline = now + ANNOUNCE_WAIT_MS;
			return 0;
		}
		return complete_bind(c, &c->pending, c->ack_at);
	case ANNOUNCING:
		arp_announce(c->arpfd, c->rs.ifindex, c->rs.mac, c->lease.yiaddr);
		if (++c->announces < ANNOUNCE_NUM) {
			c->deadline = now + ANNOUNCE_INTERVAL_MS;
			return 0;
		}
		arp_close(c);
		c->state = BOUND;
		c->deadline = c->t1_at;
		return 0;
	case BOUND:
		if (new_xid(c) < 0)
			return -1;
		c->state = RENEWING;
		printf("renewing lease with %s\n", ip_str(c->lease.server_id, s));
		/* fall through */
	case RENEWING:
		if (now >= c->t2_at) {
			if (new_xid(c) < 0)
				return -1;
			c->state = REBINDING;
			printf("no answer from server, rebinding\n");
			c->deadline = next_retry(now, c->expiry_at);
			return send_renew(c, htonl(INADDR_BROADCAST));
		}
		c->deadline = next_retry(now, c->t2_at);
		return send_renew(c, c->lease.server_id);
	case REBINDING:
		if (now >= c->expiry_at) {
			printf("lease expired, removing address\n");
			return lose_lease(c);
		}
		c->deadline = next_retry(now, c->expiry_at);
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
		arm_retry(c, now_ms());
		return send_request(c, c->offer.yiaddr, c->offer.server_id);
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

static int on_packet(struct client *c) {
	uint8_t buf[2048];
	const uint8_t *msg = buf;
	size_t len;
	int r;

	if (c->state == PROBING) {
		unsigned char sender[ETH_ALEN];
		r = arp_conflict(c->arpfd, c->rs.mac, c->pending.yiaddr, sender);
		if (r <= 0)
			return r;
		return on_conflict(c, sender);
	}
	if (c->state == SELECTING || c->state == REQUESTING ||
	    c->state == REBOOTING)
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

static int active_fd(const struct client *c) {
	switch (c->state) {
	case SELECTING:
	case REQUESTING:
	case REBOOTING:
		return c->rs.fd;
	case RENEWING:
	case REBINDING:
		return c->us.fd;
	case PROBING:
		return c->arpfd;
	case WAITING:
	case GRACE:
	case ANNOUNCING:
	case BOUND:
		break;
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
		if (now >= c->deadline) {
			if (on_timeout(c) < 0)
				return c->exit_code;
			continue;
		}

		uint64_t wait = c->deadline - now;
		if (wait > MAX_WAIT_MS)
			wait = MAX_WAIT_MS;

		struct pollfd pfd[3] = {{.fd = active_fd(c), .events = POLLIN},
		                        {.fd = sfd, .events = POLLIN},
		                        {.fd = c->linkfd, .events = POLLIN}};
		if (poll(pfd, 3, (int)wait) < 0) {
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
	c->t1_at = lt.t1_at;
	c->t2_at = lt.t2_at;
	c->expiry_at = lt.expiry_at;
	c->applied = -1;
	printf("previous lease %s found\n", ip_str(c->lease.yiaddr, a));
}

int client_run(const char *ifname, int has_metric, unsigned int metric,
               unsigned int grace_ms, const char *lease_key, int probe) {
	struct client c;
	memset(&c, 0, sizeof(c));
	c.ifname = ifname;
	c.has_metric = has_metric;
	c.metric = metric;
	c.grace_ms = grace_ms;
	c.probe = probe;
	c.exit_code = 1;
	c.us.fd = -1;
	c.arpfd = -1;
	c.carrier = -1;
	c.retry_ms = BACKOFF_START_MS;
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
