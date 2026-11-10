#include "parent.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

int parent_parse(const char *s, pid_t *pid) {
	if (!s || s[0] < '1' || s[0] > '9')
		return -1;
	char *end;
	errno = 0;
	unsigned long long v = strtoull(s, &end, 10);
	if (errno || *end != '\0' || v < 2 || v > INT32_MAX)
		return -1;
	*pid = (pid_t)v;
	return 0;
}

void parent_bind(void) {
	pid_t pid;
	if (parent_parse(getenv(PARENT_ENV), &pid) < 0)
		return;
	prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0);
	if (getppid() != pid)
		raise(SIGTERM);
}

void parent_announce(void) {
	char pid[16];
	snprintf(pid, sizeof(pid), "%d", (int)getpid());
	setenv(PARENT_ENV, pid, 1);
}
