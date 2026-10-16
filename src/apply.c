#include "apply.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int run(char *const argv[]) {
	fflush(stdout);

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork error");
		return -1;
	}
	if (pid == 0) {
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		execv(TUNDRA_IP_PATH, argv);
		perror("execv error");
		_exit(127);
	}

	int status;
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			perror("waitpid error");
			return -1;
		}
	}

	if (WIFSIGNALED(status)) {
		fprintf(stderr, "tundra-ip killed by signal %d\n", WTERMSIG(status));
		return -1;
	}
	if (WEXITSTATUS(status) != 0) {
		fprintf(stderr, "tundra-ip exited with status %d\n",
		        WEXITSTATUS(status));
		return -1;
	}
	return 0;
}

static int mask_to_prefix(uint32_t mask) {
	uint32_t inv = ~ntohl(mask);
	if (inv & (inv + 1))
		return -1;
	return __builtin_popcount(ntohl(mask));
}

static int format_cidr(const struct dhcp_info *info, char *cidr, size_t size) {
	int prefix = mask_to_prefix(info->mask);
	if (!info->mask || prefix < 0) {
		fprintf(stderr, "invalid or missing subnet mask in lease\n");
		return -1;
	}

	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &info->yiaddr, ip, sizeof(ip));
	snprintf(cidr, size, "%s/%d", ip, prefix);
	return 0;
}

int apply_lease(const char *ifname, const struct dhcp_info *info,
                int has_metric, unsigned int metric) {
	char cidr[32];
	if (format_cidr(info, cidr, sizeof(cidr)) < 0)
		return -1;

	char metric_str[16];
	snprintf(metric_str, sizeof(metric_str), "%u", metric);

	char *addr_argv[] = {"tundra-ip",    "addr", "replace", cidr, "on",
	                     (char *)ifname, NULL,   NULL,      NULL};
	if (has_metric) {
		addr_argv[6] = "metric";
		addr_argv[7] = metric_str;
	}
	if (run(addr_argv) < 0)
		return -1;

	if (!info->router)
		return 0;

	char gw[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &info->router, gw, sizeof(gw));
	char *route_argv[] = {"tundra-ip", "route", "replace", "default",
	                      "via",       gw,      "on",      (char *)ifname,
	                      NULL,        NULL,    NULL};
	if (has_metric) {
		route_argv[8] = "metric";
		route_argv[9] = metric_str;
	}
	if (run(route_argv) < 0) {
		apply_remove(ifname, info);
		return -1;
	}
	return 0;
}

int apply_remove(const char *ifname, const struct dhcp_info *info) {
	char cidr[32];
	if (format_cidr(info, cidr, sizeof(cidr)) < 0)
		return -1;

	char *argv[] = {"tundra-ip", "addr",         "del", cidr,
	                "on",        (char *)ifname, NULL};
	return run(argv);
}
