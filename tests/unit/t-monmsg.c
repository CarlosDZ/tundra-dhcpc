#include "monmsg.c"
#include "test.h"

#define IP(a, b, c, d) htonl((uint32_t)(a) << 24 | (b) << 16 | (c) << 8 | (d))

static const struct mon_held none = {0, 0, 0, 0};

static struct mon_held held(void) {
	struct mon_held h = {1, IP(10, 0, 0, 5), IP(255, 255, 255, 0),
	                     IP(10, 0, 0, 1)};
	return h;
}

static struct mon_req config(uint32_t type) {
	struct mon_req r;
	memset(&r, 0, sizeof(r));
	r.type = type;
	r.yiaddr = IP(10, 0, 0, 5);
	r.mask = IP(255, 255, 255, 0);
	r.router = IP(10, 0, 0, 1);
	return r;
}

static struct mon_req apply(void) {
	struct mon_req r = config(MON_APPLY);
	r.lifetime = 130;
	return r;
}

static enum mon_verdict check(const struct mon_req *r,
                              const struct mon_held *h) {
	struct mon_req out;
	return mon_check(r, sizeof(*r), h, 0, &out);
}

static void test_frame(void) {
	struct mon_req r = apply(), out;
	char big[sizeof(r) + 1] = {0};
	memcpy(big, &r, sizeof(r));

	CHECK(mon_check(&r, sizeof(r), &none, 0, &out) == MON_OK &&
	          memcmp(&r, &out, sizeof(r)) == 0,
	      "a well formed request is accepted and copied");
	CHECK(mon_check(&r, sizeof(r) - 1, &none, 0, &out) == MON_FATAL,
	      "a short message is fatal");
	CHECK(mon_check(big, sizeof(big), &none, 0, &out) == MON_FATAL,
	      "a long message is fatal");
	CHECK(mon_check(&r, 0, &none, 0, &out) == MON_FATAL,
	      "an empty message is fatal");

	r.type = 0;
	CHECK(check(&r, &none) == MON_FATAL, "type 0 is fatal");
	r.type = MON_LEASE_REMOVE + 1;
	CHECK(check(&r, &none) == MON_FATAL, "an unknown type is fatal");
	r.type = 0xffffffff;
	CHECK(check(&r, &none) == MON_FATAL, "a huge type is fatal");
}

static void test_unused_fields(void) {
	struct mon_req r = apply();
	r.server_id = IP(10, 0, 0, 1);
	CHECK(check(&r, &none) == MON_FATAL, "apply with a server is fatal");
	r = apply();
	r.expiry_at = 1;
	CHECK(check(&r, &none) == MON_FATAL, "apply with lease times is fatal");

	struct mon_held h = held();
	r = config(MON_REMOVE);
	r.lifetime = 1;
	CHECK(check(&r, &h) == MON_FATAL, "remove with a lifetime is fatal");

	memset(&r, 0, sizeof(r));
	r.type = MON_PROBE_START;
	r.yiaddr = IP(10, 0, 0, 5);
	r.mask = IP(255, 255, 255, 0);
	CHECK(check(&r, &none) == MON_FATAL, "probe with a mask is fatal");

	memset(&r, 0, sizeof(r));
	r.type = MON_PROBE_STOP;
	r.yiaddr = IP(10, 0, 0, 5);
	CHECK(check(&r, &none) == MON_FATAL, "probe stop with an address is fatal");

	memset(&r, 0, sizeof(r));
	r.type = MON_LEASE_REMOVE;
	r.dns[2] = 1;
	CHECK(check(&r, &none) == MON_FATAL, "lease removal with data is fatal");

	r = config(MON_LEASE_SAVE);
	r.lease = htonl(120);
	r.lifetime = 5;
	CHECK(check(&r, &h) == MON_FATAL, "lease save with a lifetime is fatal");
}

static void test_addresses(void) {
	struct mon_req r = apply();
	r.yiaddr = 0;
	CHECK(check(&r, &none) == MON_REFUSE, "address 0.0.0.0 is refused");
	r.yiaddr = IP(0, 1, 2, 3);
	CHECK(check(&r, &none) == MON_REFUSE, "address in 0/8 is refused");
	r.yiaddr = IP(127, 0, 0, 1);
	CHECK(check(&r, &none) == MON_REFUSE, "loopback address is refused");
	r.yiaddr = IP(224, 0, 0, 1);
	CHECK(check(&r, &none) == MON_REFUSE, "multicast address is refused");
	r.yiaddr = IP(255, 255, 255, 255);
	CHECK(check(&r, &none) == MON_REFUSE, "broadcast address is refused");
	r.yiaddr = IP(223, 255, 255, 1);
	CHECK(check(&r, &none) == MON_OK, "last unicast block is accepted");
	r.yiaddr = IP(1, 0, 0, 1);
	CHECK(check(&r, &none) == MON_OK, "first unicast block is accepted");

	r = apply();
	r.mask = 0;
	CHECK(check(&r, &none) == MON_REFUSE, "missing mask is refused");
	r.mask = IP(255, 0, 255, 0);
	CHECK(check(&r, &none) == MON_REFUSE, "non contiguous mask is refused");
	r.mask = IP(255, 255, 255, 255);
	CHECK(check(&r, &none) == MON_OK, "/32 mask is accepted");

	r = apply();
	r.router = 0;
	CHECK(check(&r, &none) == MON_OK, "no router is accepted");
	r.router = IP(127, 0, 0, 1);
	CHECK(check(&r, &none) == MON_REFUSE, "loopback router is refused");
	r.router = IP(240, 0, 0, 1);
	CHECK(check(&r, &none) == MON_REFUSE, "reserved router is refused");

	r = apply();
	r.lifetime = 0;
	CHECK(check(&r, &none) == MON_REFUSE, "lifetime 0 is refused");
	r.lifetime = 0xffffffff;
	CHECK(check(&r, &none) == MON_OK, "infinite lifetime is accepted");
}

static void test_held(void) {
	struct mon_held h = held();
	uint32_t types[] = {MON_REFRESH, MON_REMOVE, MON_REMOVE_RULE,
	                    MON_LEASE_SAVE};
	const char *names[] = {"refresh", "remove", "rule removal", "lease save"};
	char desc[80];

	for (int i = 0; i < 4; i++) {
		struct mon_req r = config(types[i]);
		if (types[i] == MON_REFRESH)
			r.lifetime = 60;
		if (types[i] == MON_LEASE_SAVE)
			r.lease = htonl(120);

		snprintf(desc, sizeof(desc), "%s of the held address is accepted",
		         names[i]);
		CHECK(check(&r, &h) == MON_OK, desc);
		snprintf(desc, sizeof(desc), "%s with nothing held is refused",
		         names[i]);
		CHECK(check(&r, &none) == MON_REFUSE, desc);

		struct mon_req other = r;
		other.yiaddr = IP(10, 0, 0, 6);
		snprintf(desc, sizeof(desc), "%s of another address is refused",
		         names[i]);
		CHECK(check(&other, &h) == MON_REFUSE, desc);
		other = r;
		other.mask = IP(255, 255, 0, 0);
		snprintf(desc, sizeof(desc), "%s with another mask is refused",
		         names[i]);
		CHECK(check(&other, &h) == MON_REFUSE, desc);
		other = r;
		other.router = IP(10, 0, 0, 2);
		snprintf(desc, sizeof(desc), "%s with another router is refused",
		         names[i]);
		CHECK(check(&other, &h) == MON_REFUSE, desc);
	}

	struct mon_req r = config(MON_REFRESH);
	CHECK(check(&r, &h) == MON_REFUSE, "refresh with lifetime 0 is refused");
	r = config(MON_LEASE_SAVE);
	CHECK(check(&r, &h) == MON_REFUSE, "lease save without lease is refused");

	r = apply();
	r.yiaddr = IP(10, 0, 0, 9);
	CHECK(check(&r, &h) == MON_OK, "apply does not need the held address");
}

static void test_probe(void) {
	struct mon_req r, out;
	memset(&r, 0, sizeof(r));
	r.type = MON_PROBE_START;
	r.yiaddr = IP(10, 0, 0, 5);
	CHECK(mon_check(&r, sizeof(r), &none, 0, &out) == MON_OK,
	      "a probe is accepted");
	CHECK(mon_check(&r, sizeof(r), &none, 1, &out) == MON_REFUSE,
	      "a second probe is refused");
	r.yiaddr = IP(224, 0, 0, 1);
	CHECK(mon_check(&r, sizeof(r), &none, 0, &out) == MON_REFUSE,
	      "a probe of a multicast address is refused");

	memset(&r, 0, sizeof(r));
	r.type = MON_PROBE_STOP;
	CHECK(mon_check(&r, sizeof(r), &none, 0, &out) == MON_OK,
	      "stopping without a probe is accepted");
	r.type = MON_LEASE_REMOVE;
	CHECK(mon_check(&r, sizeof(r), &none, 0, &out) == MON_OK,
	      "lease removal is accepted");
}

static void test_mask(void) {
	CHECK(mon_mask_ok(IP(255, 255, 255, 0)), "/24 is a mask");
	CHECK(mon_mask_ok(IP(128, 0, 0, 0)), "/1 is a mask");
	CHECK(!mon_mask_ok(0), "0 is not a mask");
	CHECK(!mon_mask_ok(IP(0, 255, 255, 255)), "an inverted mask is not a mask");
}

int main(void) {
	test_frame();
	test_unused_fields();
	test_addresses();
	test_held();
	test_probe();
	test_mask();
	return test_summary();
}
