#include "lease.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RUN_DIR "/run/tundra"
#define LEASE_DIR RUN_DIR "/dhcpc"

int lease_path(char *buf, size_t size, const char *ifname, const char *key) {
	int n;
	if (key)
		n = snprintf(buf, size, "%s/%s-%s.lease", LEASE_DIR, ifname, key);
	else
		n = snprintf(buf, size, "%s/%s.lease", LEASE_DIR, ifname);
	if (n < 0 || (size_t)n >= size) {
		fprintf(stderr, "lease path too long\n");
		return -1;
	}
	return 0;
}

static int make_dir(const char *path, mode_t mode) {
	if (mkdir(path, mode) < 0 && errno != EEXIST) {
		perror("mkdir error");
		return -1;
	}
	return 0;
}

static void put_addr(FILE *f, const char *key, uint32_t a) {
	char s[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &a, s, sizeof(s));
	fprintf(f, "%s=%s\n", key, s);
}

static void put_dns(FILE *f, const uint32_t dns[DHCP_MAX_DNS]) {
	char s[INET_ADDRSTRLEN];
	if (!dns[0])
		return;
	fputs("dns=", f);
	for (int i = 0; i < DHCP_MAX_DNS && dns[i]; i++) {
		inet_ntop(AF_INET, &dns[i], s, sizeof(s));
		fprintf(f, "%s%s", i ? "," : "", s);
	}
	fputc('\n', f);
}

int lease_save(const char *path, const struct dhcp_info *info,
               const struct lease_times *lt,
               const unsigned char mac[ETH_ALEN]) {
	if (make_dir(RUN_DIR, 0755) < 0 || make_dir(LEASE_DIR, 0700) < 0)
		return -1;

	char tmp[256];
	int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return -1;

	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		perror("open error");
		return -1;
	}
	FILE *f = fdopen(fd, "w");
	if (!f) {
		perror("fdopen error");
		close(fd);
		unlink(tmp);
		return -1;
	}

	put_addr(f, "address", info->yiaddr);
	put_addr(f, "mask", info->mask);
	put_addr(f, "server", info->server_id);
	if (info->router)
		put_addr(f, "router", info->router);
	put_dns(f, info->dns);
	fprintf(f, "lease=%u\n", ntohl(info->lease));
	fprintf(f, "t1_at=%llu\n", (unsigned long long)lt->t1_at);
	fprintf(f, "t2_at=%llu\n", (unsigned long long)lt->t2_at);
	fprintf(f, "expiry_at=%llu\n", (unsigned long long)lt->expiry_at);
	fprintf(f, "mac=%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2],
	        mac[3], mac[4], mac[5]);

	if (fflush(f) != 0 || fsync(fd) < 0) {
		perror("write error");
		fclose(f);
		unlink(tmp);
		return -1;
	}
	if (fclose(f) != 0) {
		perror("fclose error");
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path) < 0) {
		perror("rename error");
		unlink(tmp);
		return -1;
	}
	return 0;
}

static int parse_addr(const char *s, uint32_t *out) {
	struct in_addr a;
	if (inet_pton(AF_INET, s, &a) != 1)
		return -1;
	*out = a.s_addr;
	return 0;
}

static int parse_dns(char *s, uint32_t dns[DHCP_MAX_DNS]) {
	int n = 0;
	for (char *tok = strtok(s, ","); tok; tok = strtok(NULL, ",")) {
		if (n == DHCP_MAX_DNS || parse_addr(tok, &dns[n]) < 0)
			return -1;
		n++;
	}
	return n ? 0 : -1;
}

static int parse_mac(const char *s, unsigned char mac[ETH_ALEN]) {
	unsigned int b[ETH_ALEN];
	char end;
	if (strlen(s) != 3 * ETH_ALEN - 1 ||
	    sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &b[0], &b[1], &b[2], &b[3],
	           &b[4], &b[5], &end) != ETH_ALEN)
		return -1;
	for (int i = 0; i < ETH_ALEN; i++)
		mac[i] = (unsigned char)b[i];
	return 0;
}

static int parse_u64(const char *s, uint64_t *out) {
	if (s[0] < '0' || s[0] > '9')
		return -1;

	char *end;
	errno = 0;
	unsigned long long v = strtoull(s, &end, 10);
	if (errno || *end != '\0')
		return -1;

	*out = v;
	return 0;
}

int lease_load(const char *path, struct dhcp_info *info, struct lease_times *lt,
               unsigned char mac[ETH_ALEN]) {
	FILE *f = fopen(path, "re");
	if (!f)
		return -1;

	memset(info, 0, sizeof(*info));
	memset(lt, 0, sizeof(*lt));

	char line[128];
	int seen = 0;
	int bad = 0;
	while (fgets(line, sizeof(line), f)) {
		size_t len = strlen(line);
		if (len == 0 || line[len - 1] != '\n') {
			bad = 1;
			break;
		}
		line[len - 1] = '\0';

		char *val = strchr(line, '=');
		if (!val) {
			bad = 1;
			break;
		}
		*val++ = '\0';

		uint64_t n;
		int r = 0;
		if (strcmp(line, "address") == 0) {
			r = parse_addr(val, &info->yiaddr);
			seen |= 1;
		} else if (strcmp(line, "mask") == 0) {
			r = parse_addr(val, &info->mask);
			seen |= 2;
		} else if (strcmp(line, "server") == 0) {
			r = parse_addr(val, &info->server_id);
			seen |= 4;
		} else if (strcmp(line, "router") == 0) {
			r = parse_addr(val, &info->router);
		} else if (strcmp(line, "dns") == 0) {
			r = parse_dns(val, info->dns);
		} else if (strcmp(line, "lease") == 0) {
			r = parse_u64(val, &n);
			if (r == 0 && (n == 0 || n > UINT32_MAX))
				r = -1;
			info->lease = htonl((uint32_t)n);
			seen |= 8;
		} else if (strcmp(line, "t1_at") == 0) {
			r = parse_u64(val, &lt->t1_at);
			seen |= 16;
		} else if (strcmp(line, "t2_at") == 0) {
			r = parse_u64(val, &lt->t2_at);
			seen |= 32;
		} else if (strcmp(line, "expiry_at") == 0) {
			r = parse_u64(val, &lt->expiry_at);
			seen |= 64;
		} else if (strcmp(line, "mac") == 0) {
			r = parse_mac(val, mac);
			seen |= 128;
		}
		if (r < 0) {
			bad = 1;
			break;
		}
	}
	fclose(f);

	if (bad || seen != 255 || !info->yiaddr || !info->mask) {
		fprintf(stderr, "ignoring invalid lease file %s\n", path);
		memset(info, 0, sizeof(*info));
		return -1;
	}
	info->type = DHCPACK;
	return 0;
}

void lease_remove(const char *path) {
	if (unlink(path) < 0 && errno != ENOENT)
		perror("unlink error");
}
