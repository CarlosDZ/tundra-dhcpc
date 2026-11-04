#include "dhcp/lease.c"
#include "test.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char path[] = "/tmp/tdc-lease.XXXXXX";

static int load(const char *content, struct dhcp_info *i,
                struct lease_times *lt) {
	FILE *f = fopen(path, "w");
	if (!f)
		return -2;
	fputs(content, f);
	fclose(f);
	return lease_load(path, i, lt);
}

int main(void) {
	if (!freopen("/dev/null", "w", stderr))
		return 1;

	int fd = mkstemp(path);
	if (fd < 0)
		return 1;
	close(fd);

	struct dhcp_info i;
	struct lease_times lt;
	const char *valid =
	    "address=10.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	    "router=10.0.0.1\nlease=3600\nt1_at=100\nt2_at=200\n"
	    "expiry_at=300\n";

	CHECK(load(valid, &i, &lt) == 0, "loads a valid lease");
	CHECK(i.yiaddr == inet_addr("10.0.0.5") && ntohl(i.lease) == 3600 &&
	          lt.t1_at == 100 && lt.t2_at == 200 && lt.expiry_at == 300,
	      "fields and times");

	CHECK(load("future=1\naddress=10.0.0.5\nmask=255.255.255.0\n"
	           "server=10.0.0.1\nlease=60\nt1_at=1\nt2_at=2\nexpiry_at=3\n",
	           &i, &lt) == 0,
	      "ignores unknown keys");
	CHECK(load("address=10.0.0.5\nmask=255.255.255.0\n", &i, &lt) < 0 &&
	          i.yiaddr == 0,
	      "rejects an incomplete file and leaves no partial lease");
	CHECK(load("address=999.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	           "lease=60\nt1_at=1\nt2_at=2\nexpiry_at=3\n",
	           &i, &lt) < 0,
	      "rejects a malformed address");
	CHECK(load("address=10.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	           "lease=0\nt1_at=1\nt2_at=2\nexpiry_at=3\n",
	           &i, &lt) < 0,
	      "rejects a zero lease");
	CHECK(load("address=10.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	           "lease=60\nt1_at=-1\nt2_at=2\nexpiry_at=3\n",
	           &i, &lt) < 0,
	      "rejects a negative time");
	CHECK(load("address=10.0.0.5\nmask", &i, &lt) < 0,
	      "rejects a truncated line");
	CHECK(load("garbage\n", &i, &lt) < 0, "rejects a line without '='");
	CHECK(load("address=10.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	           "dns=9.9.9.9,1.1.1.1,8.8.8.8\nlease=60\nt1_at=1\nt2_at=2\n"
	           "expiry_at=3\n",
	           &i, &lt) == 0 &&
	          i.dns[0] == inet_addr("9.9.9.9") &&
	          i.dns[1] == inet_addr("1.1.1.1") &&
	          i.dns[2] == inet_addr("8.8.8.8"),
	      "loads a list of DNS servers");
	CHECK(load("address=10.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	           "dns=9.9.9.9\nlease=60\nt1_at=1\nt2_at=2\nexpiry_at=3\n",
	           &i, &lt) == 0 &&
	          i.dns[0] == inet_addr("9.9.9.9") && i.dns[1] == 0,
	      "loads a single DNS server");
	CHECK(load("address=10.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	           "dns=1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4\nlease=60\nt1_at=1\n"
	           "t2_at=2\nexpiry_at=3\n",
	           &i, &lt) < 0,
	      "rejects more than three DNS servers");
	CHECK(load("address=10.0.0.5\nmask=255.255.255.0\nserver=10.0.0.1\n"
	           "dns=1.1.1.1,bad\nlease=60\nt1_at=1\nt2_at=2\nexpiry_at=3\n",
	           &i, &lt) < 0,
	      "rejects a malformed DNS server");

	char *out = NULL;
	size_t outlen = 0;
	FILE *m = open_memstream(&out, &outlen);
	uint32_t dns[DHCP_MAX_DNS] = {inet_addr("9.9.9.9"), inet_addr("1.1.1.1")};
	put_dns(m, dns);
	fclose(m);
	CHECK(out && strcmp(out, "dns=9.9.9.9,1.1.1.1\n") == 0,
	      "writes the DNS servers as a comma list");
	free(out);

	out = NULL;
	m = open_memstream(&out, &outlen);
	uint32_t none[DHCP_MAX_DNS] = {0};
	put_dns(m, none);
	fclose(m);
	CHECK(out && out[0] == '\0', "writes nothing without DNS servers");
	free(out);

	unlink(path);
	CHECK(lease_load(path, &i, &lt) < 0, "a missing file is not a lease");

	return test_summary();
}
