#include "guard/gateway.c"
#include "test.h"

static const unsigned char router[ETH_ALEN] = {0x52, 0x54, 0, 0xac, 0xc9, 0xff};
static const unsigned char evil[ETH_ALEN] = {2, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb};
static const unsigned char third[ETH_ALEN] = {2, 0xcc, 0xcc, 0xcc, 0xcc, 1};

static void test_learning(void) {
	struct gateway g;
	gateway_init(&g);

	gateway_start(&g, 1000);
	CHECK(!gateway_due(&g, 1999) && gateway_due(&g, 2000),
	      "collection lasts one second");
	gateway_reply(&g, router, 0);
	gateway_reply(&g, router, 0);
	CHECK(gateway_settle(&g) == GW_LEARNED && g.known &&
	          memcmp(g.mac, router, ETH_ALEN) == 0,
	      "a single gateway MAC is learned");
	CHECK(!gateway_due(&g, 5000), "settling ends the collection");

	gateway_start(&g, 5000);
	gateway_reply(&g, router, 0);
	CHECK(gateway_settle(&g) == GW_NONE, "the same MAC again is not news");

	gateway_start(&g, 6000);
	CHECK(gateway_settle(&g) == GW_NONE && g.known,
	      "no reply keeps what was known");

	struct gateway fresh;
	gateway_init(&fresh);
	gateway_start(&fresh, 0);
	CHECK(gateway_settle(&fresh) == GW_NONE && !fresh.known,
	      "no reply on a new network learns nothing");
}

static void test_impersonation(void) {
	struct gateway g;
	gateway_init(&g);

	gateway_start(&g, 0);
	gateway_reply(&g, router, 0);
	gateway_reply(&g, evil, 1);
	CHECK(gateway_settle(&g) == GW_IMPERSONATED && g.nseen == 2 && g.forged,
	      "D: two MACs during the collection");

	gateway_init(&g);
	gateway_start(&g, 0);
	gateway_reply(&g, router, 0);
	gateway_settle(&g);
	CHECK(gateway_reply(&g, router, 0) == GW_NONE,
	      "the known gateway answering later is fine");
	CHECK(gateway_reply(&g, evil, 0) == GW_IMPERSONATED && g.nseen == 2 &&
	          memcmp(g.seen[0], router, ETH_ALEN) == 0 &&
	          memcmp(g.seen[1], evil, ETH_ALEN) == 0 && !g.forged,
	      "D: another MAC after learning, both reported");

	gateway_init(&g);
	CHECK(gateway_reply(&g, evil, 0) == GW_NONE,
	      "an unknown gateway outside the collection is not judged");
}

static void test_limits(void) {
	struct gateway g;
	gateway_init(&g);
	gateway_start(&g, 0);
	for (int i = 0; i < 10; i++) {
		unsigned char mac[ETH_ALEN] = {2, 0, 0, 0, 0, (unsigned char)i};
		gateway_reply(&g, mac, 0);
	}
	gateway_reply(&g, third, 0);
	CHECK(g.nseen == GW_MAX_MACS, "the list of seen MACs is bounded");

	gateway_init(&g);
	gateway_start(&g, 0);
	gateway_stop(&g);
	CHECK(!gateway_due(&g, 10000), "a stopped collection never settles");
}

int main(void) {
	test_learning();
	test_impersonation();
	test_limits();
	return test_summary();
}
