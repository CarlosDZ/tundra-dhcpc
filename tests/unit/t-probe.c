#include "probe.c"
#include "test.h"

#define EXITED(c) ((c) << 8)

static const char *taken =
    "taken mac 02:aa:aa:aa:aa:01 src 02:dd:dd:dd:dd:dd\n";

static void test_judge(void) {
	char mac[18] = "";
	CHECK(probe_judge(EXITED(0), "free\n", mac) == PR_FREE, "free");
	CHECK(probe_judge(EXITED(0), taken, mac) == PR_TAKEN &&
	          strcmp(mac, "02:aa:aa:aa:aa:01") == 0,
	      "taken, with the sender MAC");
	CHECK(probe_judge(EXITED(0), "", mac) == PR_RETRY, "no result is retried");
	CHECK(probe_judge(EXITED(0), "free", mac) == PR_RETRY,
	      "a truncated result is retried");
	CHECK(probe_judge(EXITED(0), "taken mac 02:aa src x\n", mac) == PR_RETRY,
	      "a malformed taken line is retried");
	CHECK(probe_judge(EXITED(111), "", mac) == PR_ALERT, "111 is an alert");
	CHECK(probe_judge(EXITED(2), "", mac) == PR_CONFIG,
	      "2 is a configuration error");
	CHECK(probe_judge(EXITED(1), "", mac) == PR_RETRY, "1 is retried");
	CHECK(probe_judge(EXITED(127), "", mac) == PR_RETRY,
	      "a sensor that could not be run is retried");
	CHECK(probe_judge(SIGKILL, "free\n", mac) == PR_RETRY,
	      "a killed probe is retried");
}

static void test_drain(void) {
	int p[2];
	char buf[8];
	if (pipe(p) < 0)
		return;
	if (write(p[1], "free\n", 5) != 5)
		return;
	close(p[1]);
	CHECK(probe_drain(p[0], buf, sizeof(buf)) == 5 &&
	          strcmp(buf, "free\n") == 0,
	      "reads the whole output");
	close(p[0]);

	if (pipe(p) < 0)
		return;
	if (write(p[1], "0123456789abcdef", 16) != 16)
		return;
	close(p[1]);
	CHECK(probe_drain(p[0], buf, sizeof(buf)) == 7 && buf[7] == '\0',
	      "a long output is cut and terminated");
	close(p[0]);
}

int main(void) {
	test_judge();
	test_drain();
	return test_summary();
}
