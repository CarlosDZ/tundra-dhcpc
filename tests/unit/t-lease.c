#include "dhcp/lease.c"
#include "test.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
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
	unlink(path);
	CHECK(lease_load(path, &i, &lt) < 0, "a missing file is not a lease");

	return test_summary();
}
