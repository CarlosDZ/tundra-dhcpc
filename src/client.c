#include "client.h"
#include "apply.h"
#include "dhcp.h"
#include "lease.h"
#include "link.h"
#include "probe.h"
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
#include <sys/wait.h>
#include <unistd.h>

#define REQUEST_TRIES 4
#define MAX_WAIT_MS 60000
#define PROBE_TIMEOUT_S 30
#define DECLINE_WAIT_S 10
#define EXIT_USAGE 2
#define EXIT_ALERT 111

enum state {
	WAITING,
	GRACE,
	SELECTING,
	REQUESTING,
	REBOOTING,
	PROBING,
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
	pid_t probe_pid;
	int probe_out;
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

static void stop_probe(struct client *c) {
	if (c->probe_pid > 0)
		probe_stop(c->probe_pid, c->probe_out);
	c->probe_pid = 0;
	c->probe_out = -1;
}

static int drop_address(struct client *c) {
	int r = 0;
	if (c->applied)
		r = apply_remove(c->ifname, &c->lease, &c->ap);
	c->applied = 0;
	udpsock_close(&c->us);
	return r;
}

static void forget_lease(struct client *c) {
	memset(&c->lease, 0, sizeof(c->lease));
	lease_remove(c->lease_path);
}

static void save_lease(struct client *c) {
	lease_save(c->lease_path, &c->lease, &c->lt);
}

static void wait_carrier(struct client *c) {
	stop_probe(c);
	rawsock_close(&c->rs);
	c->state = WAITING;
	c->deadline = UINT64_MAX;
}

static int begin(struct client *c) {
	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	return new_xid(c);
}

static int discover_in(struct client *c, uint64_t delay) {
	stop_probe(c);
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

	stop_probe(c);
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
	stop_probe(c);
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

	c->lease = *ack;
	lease_timers(&c->lt, &c->lease, ack_at);
	save_lease(c);
	printf("bound to %s from %s, lease %u s\n", ip_str(ack->yiaddr, a),
	       ip_str(ack->server_id, s), ntohl(ack->lease));
	c->state = BOUND;
	c->deadline = c->lt.t1_at;
	return 0;
}

static int start_probe(struct client *c, const struct dhcp_info *ack,
                       uint64_t now) {
	char a[INET_ADDRSTRLEN];

	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	c->pending = *ack;
	c->ack_at = now;
	printf("probing address %s\n", ip_str(ack->yiaddr, a));
	if (probe_spawn(c->ifname, ack->yiaddr, &c->probe_pid, &c->probe_out) < 0)
		return retry_later(c);
	c->state = PROBING;
	c->deadline = now + scaled_ms(PROBE_TIMEOUT_S);
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

static int decline(struct client *c, uint32_t addr, uint32_t server) {
	if (c->rs.fd < 0 && rawsock_open(&c->rs, c->ifname) < 0)
		return -1;
	return send_decline(c, addr, server);
}

static int on_probe(struct client *c, int status) {
	char out[PROBE_OUT_MAX], mac[18] = "", a[INET_ADDRSTRLEN];

	probe_drain(c->probe_out, out, sizeof(out));
	close(c->probe_out);
	c->probe_pid = 0;
	c->probe_out = -1;

	switch (probe_judge(status, out, mac)) {
	case PR_FREE:
		return complete_bind(c, &c->pending, c->ack_at);
	case PR_TAKEN:
		printf("address %s in use by %s\n", ip_str(c->pending.yiaddr, a), mac);
		decline(c, c->pending.yiaddr, c->pending.server_id);
		return discover_in(c, scaled_ms(DECLINE_WAIT_S));
	case PR_ALERT:
		decline(c, c->pending.yiaddr, c->pending.server_id);
		return quit(c, EXIT_ALERT);
	case PR_CONFIG:
		fprintf(stderr,
		        "tundra-blueice-arp rejected its arguments, giving up\n");
		return quit(c, EXIT_USAGE);
	case PR_RETRY:
		break;
	}
	fprintf(stderr, "could not probe address %s on %s\n",
	        ip_str(c->pending.yiaddr, a), c->ifname);
	return retry_later(c);
}

static int on_child(struct client *c) {
	int status;
	if (c->probe_pid <= 0)
		return 0;
	pid_t r = waitpid(c->probe_pid, &status, WNOHANG);
	if (r == 0 || (r < 0 && errno == EINTR))
		return 0;
	if (r < 0) {
		perror("waitpid error");
		status = 0x7f00;
	}
	return on_probe(c, status);
}

static int on_conflict(struct client *c) {
	char a[INET_ADDRSTRLEN];

	if (!c->applied) {
		printf("no address in use on %s, ignoring SIGUSR2\n", c->ifname);
		return 0;
	}
	printf("address %s in conflict, declining it\n",
	       ip_str(c->lease.yiaddr, a));
	decline(c, c->lease.yiaddr, c->lease.server_id);
	drop_address(c);
	return discover_in(c, scaled_ms(DECLINE_WAIT_S));
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
		fprintf(stderr, "probe of %s timed out\n",
		        ip_str(c->pending.yiaddr, s));
		return retry_later(c);
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
		if (c->applied)
			apply_remove_rule(&c->lease, &c->ap);
		c->applied = 0;
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
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigaddset(&mask, SIGCHLD);
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

		struct pollfd pfd[3] = {{.fd = dhcp_fd(c), .events = POLLIN},
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
			if (read(sfd, &si, sizeof(si)) != sizeof(si))
				return 0;
			int r;
			switch (si.ssi_signo) {
			case SIGCHLD:
				r = on_child(c);
				break;
			case SIGUSR2:
				r = on_conflict(c);
				break;
			case SIGUSR1:
				stop_probe(c);
				printf("releasing address on %s\n", c->ifname);
				return drop_address(c) < 0 ? 1 : 0;
			default:
				printf("received %s, exiting\n", strsignal((int)si.ssi_signo));
				return 0;
			}
			if (r < 0)
				return c->exit_code;
			continue;
		}
		if (pfd[2].revents & POLLIN) {
			if (on_link(c) < 0)
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
	c.probe_out = -1;
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

	stop_probe(&c);
	rawsock_close(&c.rs);
	udpsock_close(&c.us);
	close(sfd);
	return ret;
}
