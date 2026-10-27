#include "guard/conflict.c"
#include "test.h"

#define DEFEND_MS 10000
#define S 1000

static const unsigned char evil[ETH_ALEN] = {2, 0xaa, 0xaa, 0xaa, 0xaa, 1};
static const unsigned char other[ETH_ALEN] = {2, 0xbb, 0xbb, 0xbb, 0xbb, 1};
static const unsigned char multicast[ETH_ALEN] = {1, 0, 0x5e, 0, 0, 1};
static const unsigned char zero[ETH_ALEN] = {0};

static uint32_t ip(int n) { return (uint32_t)(0x0a000000 | n); }

static void test_probe(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	CHECK(conflict_probe(&cs, ip(1), evil, 0, 1 * S, &k) == V_GIVE_UP &&
	          k == ALERT_NONE,
	      "a probe conflict gives the address up");
	CHECK(conflict_probe(&cs, ip(2), evil, 0, 2 * S, &k) == V_GIVE_UP,
	      "a second address taken by the same host still gives up");
	CHECK(conflict_probe(&cs, ip(3), evil, 0, 3 * S, &k) == V_ALERT &&
	          k == ALERT_SAME_HOST,
	      "A: a third address taken by the same host raises the alert");

	conflicts_init(&cs, DEFEND_MS, 0);
	CHECK(conflict_probe(&cs, ip(1), evil, 0, 0, &k) == V_GIVE_UP &&
	          conflict_probe(&cs, ip(1), evil, 0, S, &k) == V_GIVE_UP &&
	          conflict_probe(&cs, ip(1), evil, 0, 2 * S, &k) == V_GIVE_UP,
	      "the same address repeated by one host is not case A");

	conflicts_init(&cs, DEFEND_MS, 0);
	CHECK(conflict_probe(&cs, ip(1), multicast, 0, 0, &k) == V_ALERT &&
	          k == ALERT_INVALID_MAC,
	      "a multicast responder raises the alert at once");
	conflicts_init(&cs, DEFEND_MS, 0);
	CHECK(conflict_probe(&cs, ip(1), zero, 0, 0, &k) == V_ALERT &&
	          k == ALERT_INVALID_MAC,
	      "an all-zero responder raises the alert at once");
}

static void test_many_hosts(void) {
	struct conflicts cs;
	enum alert_kind k = ALERT_NONE;
	enum verdict v = V_GIVE_UP;
	int before = 1;
	conflicts_init(&cs, DEFEND_MS, 0);

	for (int i = 0; i < 10; i++) {
		unsigned char mac[ETH_ALEN] = {2, 0, 0, 0, 0, (unsigned char)i};
		v = conflict_probe(&cs, ip(i), mac, 0, (uint64_t)i * S, &k);
		if (i < 9 && v != V_GIVE_UP)
			before = 0;
	}
	CHECK(before, "B: fewer than ten hosts only give up");
	CHECK(v == V_ALERT && k == ALERT_MANY_HOSTS,
	      "B: the tenth distinct host raises the alert");
}

static void test_window(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	conflict_probe(&cs, ip(1), evil, 0, 0, &k);
	conflict_probe(&cs, ip(2), evil, 0, S, &k);
	CHECK(conflict_probe(&cs, ip(3), evil, 0, CONFLICT_WINDOW_MS + 2 * S, &k) ==
	          V_GIVE_UP,
	      "conflicts older than the window are forgotten");

	conflicts_init(&cs, DEFEND_MS, 0);
	for (int i = 0; i < 20; i++) {
		unsigned char mac[ETH_ALEN] = {2, 1, 0, 0, 0, (unsigned char)i};
		conflict_probe(&cs, ip(100 + i), mac, 0, (uint64_t)i, &k);
	}
	CHECK(cs.n == CONFLICT_MAX, "the record keeps a bounded history");
}

static void test_claims(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	CHECK(conflict_claim(&cs, ip(1), evil, 0, 100 * S, &k) == V_DEFEND,
	      "the first claim is defended");
	CHECK(conflict_claim(&cs, ip(1), evil, 0, 105 * S, &k) == V_GIVE_UP,
	      "a claim within the defense interval gives up");

	conflicts_init(&cs, DEFEND_MS, 0);
	CHECK(conflict_claim(&cs, ip(1), evil, 0, 100 * S, &k) == V_DEFEND &&
	          conflict_claim(&cs, ip(1), other, 0, 111 * S, &k) == V_DEFEND,
	      "spaced claims are defended");
	CHECK(conflict_claim(&cs, ip(1), evil, 0, 122 * S, &k) == V_ALERT &&
	          k == ALERT_CLAIMED,
	      "C: the third claim on the address in use raises the alert");

	conflicts_init(&cs, DEFEND_MS, 0);
	CHECK(conflict_claim(&cs, ip(1), multicast, 0, 0, &k) == V_ALERT &&
	          k == ALERT_INVALID_MAC,
	      "an invalid MAC claiming the address raises the alert");

	conflicts_init(&cs, DEFEND_MS, 0);
	conflict_claim(&cs, ip(1), evil, 0, 100 * S, &k);
	conflicts_new_address(&cs);
	CHECK(conflict_claim(&cs, ip(2), other, 0, 101 * S, &k) == V_DEFEND,
	      "a new address starts a fresh defense interval");
}

static void test_forced(void) {
	struct conflicts cs;
	enum alert_kind k;
	int never = 1;
	conflicts_init(&cs, DEFEND_MS, 1);

	CHECK(conflict_claim(&cs, ip(1), evil, 0, 100 * S, &k) == V_DEFEND,
	      "forced: the first claim is defended");
	CHECK(conflict_claim(&cs, ip(1), evil, 0, 101 * S, &k) == V_HOLD,
	      "forced: a claim within the interval is held");
	for (int i = 0; i < 10; i++) {
		enum verdict v = conflict_claim(&cs, ip(1), i % 2 ? multicast : other,
		                                0, (uint64_t)(102 + i * 11) * S, &k);
		if (v == V_GIVE_UP || v == V_ALERT)
			never = 0;
	}
	CHECK(never, "forced: never gives up nor alerts");
}

static void test_hints(void) {
	struct conflicts cs;
	enum alert_kind k;
	conflicts_init(&cs, DEFEND_MS, 0);

	conflict_probe(&cs, ip(1), evil, 0, 0, &k);
	CHECK(!conflicts_forged(&cs), "genuine replies are not forged");
	conflict_probe(&cs, ip(2), other, 1, S, &k);
	CHECK(conflicts_forged(&cs), "a forged reply is remembered");
	CHECK(conflicts_has_mac(&cs, other) && !conflicts_has_mac(&cs, zero),
	      "responder MACs can be looked up");
}

int main(void) {
	test_probe();
	test_many_hosts();
	test_window();
	test_claims();
	test_forced();
	test_hints();
	return test_summary();
}
