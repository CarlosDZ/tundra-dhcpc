#include "monitor.h"
#include "lease.h"
#include "probe.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(MON_OUT_MAX == PROBE_OUT_MAX, "probe output must fit a reply");

struct monitor {
	const char *ifname;
	const struct apply_opts *ap;
	const char *lease_path;
	int fd;
	pid_t worker;
	struct mon_held held;
	pid_t probe_pid;
	int probe_out;
	const unsigned char *mac;
	/* What is held comes from a stored lease: it may not be on the
	 * interface any more. */
	int unsure;
};

static void stop_probe(struct monitor *m) {
	if (m->probe_pid > 0)
		probe_stop(m->probe_pid, m->probe_out);
	m->probe_pid = 0;
	m->probe_out = -1;
}

static int send_rep(struct monitor *m, const struct mon_rep *rep) {
	ssize_t n;
	do
		n = write(m->fd, rep, sizeof(*rep));
	while (n < 0 && errno == EINTR);
	return n == (ssize_t)sizeof(*rep) ? 0 : -1;
}

static int reply(struct monitor *m, int result) {
	struct mon_rep rep;
	memset(&rep, 0, sizeof(rep));
	rep.type = MON_REPLY;
	rep.result = result;
	return send_rep(m, &rep);
}

static int worker_exit(struct monitor *m, int status) {
	stop_probe(m);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	fprintf(stderr, "worker killed by signal %d\n", WTERMSIG(status));
	return 1;
}

static int worker_wait(struct monitor *m) {
	int status;
	while (waitpid(m->worker, &status, 0) < 0) {
		if (errno != EINTR) {
			perror("waitpid error");
			stop_probe(m);
			return 1;
		}
	}
	return worker_exit(m, status);
}

static int worker_kill(struct monitor *m) {
	kill(m->worker, SIGKILL);
	worker_wait(m);
	return 1;
}

static int execute(struct monitor *m, const struct mon_req *r) {
	struct dhcp_info info;
	struct lease_times lt;

	memset(&info, 0, sizeof(info));
	info.yiaddr = r->yiaddr;
	info.mask = r->mask;
	info.router = r->router;

	switch (r->type) {
	case MON_APPLY:
		m->held.set = 1;
		m->unsure = 0;
		m->held.yiaddr = r->yiaddr;
		m->held.mask = r->mask;
		m->held.router = r->router;
		return apply_lease(m->ifname, &info, m->ap, r->lifetime);
	case MON_REFRESH:
		return apply_refresh(m->ifname, &info, m->ap, r->lifetime);
	case MON_REMOVE:
		m->held.set = 0;
		return apply_remove(m->ifname, &info, m->ap, m->unsure);
	case MON_REMOVE_RULE:
		return apply_remove_rule(&info, m->ap);
	case MON_PROBE_START:
		return probe_spawn(m->ifname, r->yiaddr, &m->probe_pid, &m->probe_out);
	case MON_PROBE_STOP:
		stop_probe(m);
		return 0;
	case MON_LEASE_SAVE:
		info.server_id = r->server_id;
		memcpy(info.dns, r->dns, sizeof(info.dns));
		info.lease = r->lease;
		lt.t1_at = r->t1_at;
		lt.t2_at = r->t2_at;
		lt.expiry_at = r->expiry_at;
		return lease_save(m->lease_path, &info, &lt, m->mac);
	case MON_LEASE_REMOVE:
		lease_remove(m->lease_path);
		return 0;
	}
	return -1;
}

/* Returns 0 to go on, 1 when the worker closed its end, -1 to give up. */
static int on_request(struct monitor *m) {
	/* one byte more than a request, so an oversized message is seen */
	char buf[sizeof(struct mon_req) + 1];
	struct mon_req req;

	ssize_t n = read(m->fd, buf, sizeof(buf));
	if (n < 0 && errno == EINTR)
		return 0;
	if (n <= 0)
		return 1;

	switch (mon_check(buf, (size_t)n, &m->held, m->probe_pid > 0, &req)) {
	case MON_OK:
		return reply(m, execute(m, &req));
	case MON_REFUSE:
		fprintf(stderr, "refused request %u from the worker\n", req.type);
		return reply(m, APPLY_FAIL);
	case MON_FATAL:
		break;
	}
	fprintf(stderr, "malformed request from the worker\n");
	return -1;
}

static int probe_done(struct monitor *m) {
	int status;
	if (m->probe_pid <= 0)
		return 0;
	pid_t r = waitpid(m->probe_pid, &status, WNOHANG);
	if (r == 0 || (r < 0 && errno == EINTR))
		return 0;
	if (r < 0) {
		perror("waitpid error");
		status = 0x7f00;
	}

	struct mon_rep rep;
	memset(&rep, 0, sizeof(rep));
	rep.type = MON_PROBE_DONE;
	rep.status = status;
	probe_drain(m->probe_out, rep.out, sizeof(rep.out));
	close(m->probe_out);
	m->probe_pid = 0;
	m->probe_out = -1;
	return send_rep(m, &rep);
}

int monitor_run(const char *ifname, const struct apply_opts *ap,
                const char *lease_path, const struct mon_held *held,
                const unsigned char mac[ETH_ALEN], int fd, int sfd,
                pid_t worker) {
	struct monitor m = {ifname, ap, lease_path, fd,  worker,
	                    *held,  0,  -1,         mac, held->set};

	for (;;) {
		struct pollfd pfd[2] = {{.fd = sfd, .events = POLLIN},
		                        {.fd = fd, .events = POLLIN}};
		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			perror("poll error");
			return worker_kill(&m);
		}

		if (pfd[0].revents & POLLIN) {
			struct signalfd_siginfo si;
			if (read(sfd, &si, sizeof(si)) != sizeof(si))
				return worker_kill(&m);
			if (si.ssi_signo != SIGCHLD) {
				kill(worker, (int)si.ssi_signo);
				continue;
			}
			int status;
			if (waitpid(worker, &status, WNOHANG) == worker)
				return worker_exit(&m, status);
			if (probe_done(&m) < 0)
				return worker_wait(&m);
			continue;
		}
		if (pfd[1].revents) {
			int r = on_request(&m);
			if (r < 0)
				return worker_kill(&m);
			if (r > 0)
				return worker_wait(&m);
		}
	}
}
