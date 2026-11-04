#include "probe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXIT_ALERT 111
#define EXIT_USAGE 2

int probe_spawn(const char *ifname, uint32_t addr, pid_t *pid, int *out) {
	char ip[INET_ADDRSTRLEN];
	int p[2];

	inet_ntop(AF_INET, &addr, ip, sizeof(ip));
	if (pipe2(p, O_CLOEXEC) < 0) {
		perror("pipe error");
		return -1;
	}
	fflush(stdout);

	pid_t child = fork();
	if (child < 0) {
		perror("fork error");
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (child == 0) {
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		signal(SIGHUP, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		dup2(p[1], STDOUT_FILENO);
		char *argv[] = {"tundra-blueice-arp", "probe", (char *)ifname, ip,
		                NULL};
		execv(TUNDRA_BLUEICE_ARP_PATH, argv);
		perror("execv error");
		_exit(127);
	}

	close(p[1]);
	*pid = child;
	*out = p[0];
	return 0;
}

void probe_stop(pid_t pid, int out) {
	kill(pid, SIGTERM);
	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;
	close(out);
}

size_t probe_drain(int fd, char *buf, size_t size) {
	size_t len = 0;
	while (len + 1 < size) {
		ssize_t n = read(fd, buf + len, size - 1 - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	buf[len] = '\0';
	return len;
}

static int parse_taken(const char *out, char mac[18]) {
	char sha[18], src[18], end;
	if (sscanf(out, "taken mac %17s src %17s%c", sha, src, &end) != 3 ||
	    end != '\n' || strlen(sha) != 17)
		return -1;
	memcpy(mac, sha, 18);
	return 0;
}

enum probe_result probe_judge(int status, const char *out, char mac[18]) {
	if (!WIFEXITED(status))
		return PR_RETRY;
	switch (WEXITSTATUS(status)) {
	case 0:
		if (strcmp(out, "free\n") == 0)
			return PR_FREE;
		if (parse_taken(out, mac) == 0)
			return PR_TAKEN;
		return PR_RETRY;
	case EXIT_ALERT:
		return PR_ALERT;
	case EXIT_USAGE:
		return PR_CONFIG;
	default:
		return PR_RETRY;
	}
}
