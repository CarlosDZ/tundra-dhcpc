#include "apply.h"
#include "timing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 16

struct cmd {
	char *argv[MAX_ARGS];
	int argc;
};

static void cmd_init(struct cmd *c, const char *obj, const char *verb) {
	c->argc = 0;
	c->argv[c->argc++] = "tundra-ip";
	c->argv[c->argc++] = (char *)obj;
	c->argv[c->argc++] = (char *)verb;
	c->argv[c->argc] = NULL;
}

static void cmd_add(struct cmd *c, const char *arg) {
	if (c->argc < MAX_ARGS - 1) {
		c->argv[c->argc++] = (char *)arg;
		c->argv[c->argc] = NULL;
	}
}

static void cmd_pair(struct cmd *c, const char *key, const char *value) {
	cmd_add(c, key);
	cmd_add(c, value);
}

static int run(const struct cmd *c, int quiet) {
	fflush(stdout);

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork error");
		return APPLY_FAIL;
	}
	if (pid == 0) {
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		if (quiet) {
			int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
			if (fd >= 0) {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
			}
		}
		execv(TUNDRA_IP_PATH, c->argv);
		perror("execv error");
		_exit(127);
	}

	int status;
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			perror("waitpid error");
			return APPLY_FAIL;
		}
	}

	if (WIFSIGNALED(status)) {
		if (!quiet)
			fprintf(stderr, "tundra-ip killed by signal %d\n",
			        WTERMSIG(status));
		return APPLY_FAIL;
	}
	if (WEXITSTATUS(status) != 0) {
		if (!quiet)
			fprintf(stderr, "tundra-ip exited with status %d\n",
			        WEXITSTATUS(status));
		return WEXITSTATUS(status) == 2 ? APPLY_USAGE : APPLY_FAIL;
	}
	return 0;
}

static int mask_to_prefix(uint32_t mask) {
	uint32_t inv = ~ntohl(mask);
	if (inv & (inv + 1))
		return -1;
	return __builtin_popcount(ntohl(mask));
}

struct addrs {
	char ip[INET_ADDRSTRLEN];
	char host[INET_ADDRSTRLEN + 3];
	char cidr[INET_ADDRSTRLEN + 3];
	char net[INET_ADDRSTRLEN + 3];
	char gw[INET_ADDRSTRLEN];
	char metric[16];
	char priority[16];
};

static int format_addrs(const struct dhcp_info *info,
                        const struct apply_opts *opts, struct addrs *a) {
	int prefix = mask_to_prefix(info->mask);
	if (!info->mask || prefix < 0) {
		fprintf(stderr, "invalid or missing subnet mask in lease\n");
		return -1;
	}

	char net[INET_ADDRSTRLEN];
	uint32_t netaddr = info->yiaddr & info->mask;
	inet_ntop(AF_INET, &info->yiaddr, a->ip, sizeof(a->ip));
	inet_ntop(AF_INET, &netaddr, net, sizeof(net));
	inet_ntop(AF_INET, &info->router, a->gw, sizeof(a->gw));
	snprintf(a->host, sizeof(a->host), "%s/32", a->ip);
	snprintf(a->cidr, sizeof(a->cidr), "%s/%d", a->ip, prefix);
	snprintf(a->net, sizeof(a->net), "%s/%d", net, prefix);
	snprintf(a->metric, sizeof(a->metric), "%u", opts->metric);
	snprintf(a->priority, sizeof(a->priority), "%u", opts->priority);
	return 0;
}

static int addr_replace(const char *ifname, const struct apply_opts *opts,
                        const struct addrs *a, uint32_t lifetime) {
	char life[16];
	struct cmd c;
	cmd_init(&c, "addr", "replace");
	cmd_add(&c, a->cidr);
	cmd_pair(&c, "on", ifname);
	if (opts->has_metric)
		cmd_pair(&c, "metric", a->metric);
	if (lifetime != LIFETIME_FOREVER) {
		snprintf(life, sizeof(life), "%u", lifetime);
		cmd_pair(&c, "valid", life);
		cmd_pair(&c, "preferred", life);
	}
	return run(&c, 0);
}

static void rule_del(const struct apply_opts *opts, const struct addrs *a) {
	struct cmd c;
	cmd_init(&c, "rule", "del");
	cmd_pair(&c, "from", a->host);
	cmd_pair(&c, "table", opts->table);
	cmd_pair(&c, "priority", a->priority);
	run(&c, 1);
}

int apply_check_table(const char *table) {
	struct cmd c;
	cmd_init(&c, "route", "show");
	cmd_pair(&c, "table", table);
	return run(&c, 1);
}

static int default_replace(const char *ifname, const struct apply_opts *opts,
                           const struct addrs *a, const char *table) {
	struct cmd c;
	cmd_init(&c, "route", "replace");
	cmd_add(&c, "default");
	cmd_pair(&c, "via", a->gw);
	cmd_pair(&c, "on", ifname);
	if (table)
		cmd_pair(&c, "table", table);
	if (opts->has_metric)
		cmd_pair(&c, "metric", a->metric);
	return run(&c, 0);
}

static void default_del(const char *ifname, const char *table) {
	struct cmd c;
	cmd_init(&c, "route", "del");
	cmd_add(&c, "default");
	cmd_pair(&c, "on", ifname);
	if (table)
		cmd_pair(&c, "table", table);
	run(&c, 1);
}

static int apply_routes(const char *ifname, const struct dhcp_info *info,
                        const struct apply_opts *opts, const struct addrs *a) {
	struct cmd c;
	int r;
	if (opts->table) {
		cmd_init(&c, "route", "replace");
		cmd_add(&c, a->net);
		cmd_pair(&c, "on", ifname);
		cmd_pair(&c, "table", opts->table);
		cmd_pair(&c, "src", a->ip);
		if (opts->has_metric)
			cmd_pair(&c, "metric", a->metric);
		if ((r = run(&c, 0)) < 0)
			return r;
	}

	if (info->router) {
		if ((r = default_replace(ifname, opts, a, NULL)) < 0)
			return r;
		if (opts->table &&
		    (r = default_replace(ifname, opts, a, opts->table)) < 0)
			return r;
	}

	if (opts->table) {
		rule_del(opts, a);
		cmd_init(&c, "rule", "add");
		cmd_pair(&c, "from", a->host);
		cmd_pair(&c, "table", opts->table);
		cmd_pair(&c, "priority", a->priority);
		if ((r = run(&c, 0)) < 0)
			return r;
	}
	return 0;
}

int apply_lease(const char *ifname, const struct dhcp_info *info,
                const struct apply_opts *opts, uint32_t lifetime) {
	struct addrs a;
	if (format_addrs(info, opts, &a) < 0)
		return APPLY_FAIL;

	int r = addr_replace(ifname, opts, &a, lifetime);
	if (r < 0)
		return r;
	r = apply_routes(ifname, info, opts, &a);
	if (r < 0) {
		apply_remove(ifname, info, opts);
		return r;
	}
	return 0;
}

int apply_refresh(const char *ifname, const struct dhcp_info *info,
                  const struct apply_opts *opts, uint32_t lifetime) {
	struct addrs a;
	if (format_addrs(info, opts, &a) < 0)
		return APPLY_FAIL;
	return addr_replace(ifname, opts, &a, lifetime);
}

void apply_remove(const char *ifname, const struct dhcp_info *info,
                  const struct apply_opts *opts) {
	struct addrs a;
	if (format_addrs(info, opts, &a) < 0)
		return;

	struct cmd c;
	if (opts->table) {
		rule_del(opts, &a);
		default_del(ifname, opts->table);

		cmd_init(&c, "route", "del");
		cmd_add(&c, a.net);
		cmd_pair(&c, "on", ifname);
		cmd_pair(&c, "table", opts->table);
		run(&c, 1);
	}
	if (info->router)
		default_del(ifname, NULL);

	cmd_init(&c, "addr", "del");
	cmd_add(&c, a.cidr);
	cmd_pair(&c, "on", ifname);
	run(&c, 0);
}
