#include "test.h"
#include "timing.c"

static struct dhcp_info lease_of(uint32_t secs, uint32_t t1, uint32_t t2) {
	struct dhcp_info i = {0};
	i.lease = htonl(secs);
	i.t1 = htonl(t1);
	i.t2 = htonl(t2);
	return i;
}

static void test_backoff(void) {
	uint64_t b = BACKOFF_START_MS;
	int in_range = 1;
	for (int i = 0; i < 200; i++) {
		uint64_t probe = BACKOFF_START_MS;
		uint64_t d = backoff_next(&probe, 1000000);
		if (d < 1000000 + BACKOFF_START_MS - JITTER_MS ||
		    d > 1000000 + BACKOFF_START_MS + JITTER_MS)
			in_range = 0;
	}
	CHECK(in_range, "jitter stays within one second of the backoff");

	uint64_t seq[] = {8000, 16000, 32000, 64000, 64000};
	int doubles = 1;
	for (int i = 0; i < 5; i++) {
		backoff_next(&b, 0);
		if (b != seq[i])
			doubles = 0;
	}
	CHECK(doubles, "backoff doubles up to 64 s and stays there");
}

static void test_retry(void) {
	CHECK(retry_before(0, 1000000) == 500000,
	      "retry at half of the remaining time");
	CHECK(retry_before(0, 100000) == 60000, "retry no sooner than one minute");
	CHECK(retry_before(0, 30000) == 30000, "retry never after the limit");
}

static void test_lease_timers(void) {
	struct lease_times lt;
	struct dhcp_info l = lease_of(3600, 0, 0);
	lease_timers(&lt, &l, 1000);
	CHECK(lt.t1_at == 1000 + 1800000 && lt.t2_at == 1000 + 3150000 &&
	          lt.expiry_at == 1000 + 3600000,
	      "default T1 and T2 at 1/2 and 7/8 of the lease");

	l = lease_of(3600, 600, 900);
	lease_timers(&lt, &l, 0);
	CHECK(lt.t1_at == 600000 && lt.t2_at == 900000,
	      "server T1 and T2 are honoured");

	l = lease_of(3600, 600, 4000);
	lease_timers(&lt, &l, 0);
	CHECK(lt.t1_at == 600000 && lt.t2_at == 3150000,
	      "T2 beyond the lease falls back to 7/8");

	l = lease_of(3600, 3500, 3000);
	lease_timers(&lt, &l, 0);
	CHECK(lt.t1_at == 1800000 && lt.t2_at == 3000000,
	      "T1 beyond T2 falls back to 1/2");

	l = lease_of(LEASE_INFINITE, 0, 0);
	lease_timers(&lt, &l, 0);
	CHECK(lt.t1_at == UINT64_MAX && lt.expiry_at == UINT64_MAX,
	      "an infinite lease never expires");
}

static void test_lifetimes(void) {
	CHECK(lifetime_until(UINT64_MAX, 0) == LIFETIME_FOREVER,
	      "no expiry gives a permanent address");
	CHECK(lifetime_until(5000, 0) == 5 + LIFETIME_MARGIN_S,
	      "lifetime is the remaining lease plus the margin");
	CHECK(lifetime_until(1000, 9000) == LIFETIME_MARGIN_S,
	      "an expired lease keeps only the margin");

	struct dhcp_info l = lease_of(60, 0, 0);
	CHECK(lease_lifetime(&l, 0, 20000) == 40 + LIFETIME_MARGIN_S,
	      "lifetime counts from the ACK");
	l = lease_of(LEASE_INFINITE, 0, 0);
	CHECK(lease_lifetime(&l, 0, 20000) == LIFETIME_FOREVER,
	      "an infinite lease gives a permanent address");
}

static void test_elapsed(void) {
	CHECK(elapsed_secs(0, 3999) == 3, "elapsed seconds are truncated");
	CHECK(elapsed_secs(5000, 1000) == 0, "a future start counts as zero");
	CHECK(elapsed_secs(0, 100000000) == 0xffff, "elapsed seconds saturate");
}

int main(void) {
	test_backoff();
	test_retry();
	test_lease_timers();
	test_lifetimes();
	test_elapsed();
	return test_summary();
}
