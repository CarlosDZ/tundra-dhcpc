#include "apply.h"
#include "client.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_uint(const char *s, unsigned int *out) {
	if (s[0] < '0' || s[0] > '9')
		return -1;

	char *end;
	errno = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno || *end != '\0' || v > UINT_MAX)
		return -1;

	*out = (unsigned int)v;
	return 0;
}

static int valid_name(const char *s) {
	size_t len = strlen(s);
	if (len == 0 || len > 64 || s[0] == '.')
		return 0;
	for (size_t i = 0; i < len; i++) {
		char ch = s[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
		      (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'))
			return 0;
	}
	return 1;
}

static int parse_table(const char *s, const char **out) {
	if (!valid_name(s) || strcmp(s, "local") == 0 ||
	    strcmp(s, "default") == 0 || strcmp(s, "0") == 0 ||
	    strcmp(s, "253") == 0 || strcmp(s, "255") == 0)
		return -1;
	if (strcmp(s, "main") == 0 || strcmp(s, "254") == 0)
		*out = NULL;
	else
		*out = s;
	return 0;
}

static void usage(void) {
	fprintf(stderr, "usage: tundra-dhcpc <interface> [metric <n>] "
	                "[carrier-grace <ms>] [lease-key <name>] [probe on|off] "
	                "[secs <n>] [table <table>] [rule-priority <n>]\n");
}

int main(int argc, char *argv[]) {
	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		printf("tundra-dhcpc %s\n", TUNDRA_DHCPC_VERSION);
		return 0;
	}
	if (argc < 2 || argc % 2 != 0) {
		usage();
		return 2;
	}

	struct apply_opts ap = {0, 0, NULL, 1000};
	int has_priority = 0;
	unsigned int grace_ms = 0;
	const char *lease_key = NULL;
	int probe = 1;
	int secs_override = -1;
	for (int i = 2; i < argc; i += 2) {
		if (strcmp(argv[i], "metric") == 0 && !ap.has_metric) {
			if (parse_uint(argv[i + 1], &ap.metric) < 0) {
				fprintf(stderr, "invalid metric: %s\n", argv[i + 1]);
				return 2;
			}
			ap.has_metric = 1;
		} else if (strcmp(argv[i], "carrier-grace") == 0) {
			if (parse_uint(argv[i + 1], &grace_ms) < 0) {
				fprintf(stderr, "invalid carrier-grace: %s\n", argv[i + 1]);
				return 2;
			}
		} else if (strcmp(argv[i], "lease-key") == 0) {
			if (!valid_name(argv[i + 1])) {
				fprintf(stderr, "invalid lease-key: %s\n", argv[i + 1]);
				return 2;
			}
			lease_key = argv[i + 1];
		} else if (strcmp(argv[i], "probe") == 0) {
			if (strcmp(argv[i + 1], "on") == 0) {
				probe = 1;
			} else if (strcmp(argv[i + 1], "off") == 0) {
				probe = 0;
			} else {
				fprintf(stderr, "invalid probe: %s\n", argv[i + 1]);
				return 2;
			}
		} else if (strcmp(argv[i], "secs") == 0) {
			unsigned int v;
			if (parse_uint(argv[i + 1], &v) < 0 || v > 0xffff) {
				fprintf(stderr, "invalid secs: %s\n", argv[i + 1]);
				return 2;
			}
			secs_override = (int)v;
		} else if (strcmp(argv[i], "table") == 0) {
			if (parse_table(argv[i + 1], &ap.table) < 0) {
				fprintf(stderr, "invalid table: %s\n", argv[i + 1]);
				return 2;
			}
		} else if (strcmp(argv[i], "rule-priority") == 0) {
			if (parse_uint(argv[i + 1], &ap.priority) < 0 || ap.priority == 0 ||
			    ap.priority > 32765) {
				fprintf(stderr, "invalid rule-priority: %s\n", argv[i + 1]);
				return 2;
			}
			has_priority = 1;
		} else {
			usage();
			return 2;
		}
	}

	if (has_priority && !ap.table) {
		fprintf(stderr, "rule-priority requires table\n");
		return 2;
	}
	if (ap.table) {
		int r = apply_check_table(ap.table);
		if (r == APPLY_USAGE) {
			fprintf(stderr, "invalid table: %s\n", ap.table);
			return 2;
		}
		if (r < 0) {
			fprintf(stderr, "could not check table %s\n", ap.table);
			return 1;
		}
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	return client_run(argv[1], &ap, grace_ms, lease_key, probe, secs_override);
}
