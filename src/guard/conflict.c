#include "conflict.h"

#include <string.h>

static int mac_invalid(const unsigned char m[ETH_ALEN]) {
	static const unsigned char zero[ETH_ALEN];
	return (m[0] & 1) || memcmp(m, zero, ETH_ALEN) == 0;
}

void conflicts_init(struct conflicts *cs, uint64_t defend_ms, int forced) {
	memset(cs, 0, sizeof(*cs));
	cs->defend_ms = defend_ms;
	cs->forced = forced;
}

void conflicts_new_address(struct conflicts *cs) { cs->last_defense = 0; }

static void record(struct conflicts *cs, uint32_t addr,
                   const unsigned char mac[ETH_ALEN], int bound, int forged,
                   uint64_t now) {
	int n = 0;
	for (int i = 0; i < cs->n; i++)
		if (now - cs->recs[i].at < CONFLICT_WINDOW_MS)
			cs->recs[n++] = cs->recs[i];
	if (n == CONFLICT_MAX) {
		memmove(&cs->recs[0], &cs->recs[1],
		        (CONFLICT_MAX - 1) * sizeof(cs->recs[0]));
		n--;
	}
	cs->recs[n].at = now;
	cs->recs[n].addr = addr;
	memcpy(cs->recs[n].mac, mac, ETH_ALEN);
	cs->recs[n].bound = bound;
	cs->recs[n].forged = forged;
	cs->n = n + 1;
}

static int pair_seen(const struct conflicts *cs, int i) {
	for (int j = 0; j < i; j++)
		if (cs->recs[j].addr == cs->recs[i].addr &&
		    memcmp(cs->recs[j].mac, cs->recs[i].mac, ETH_ALEN) == 0)
			return 1;
	return 0;
}

static enum alert_kind evaluate(const struct conflicts *cs,
                                const unsigned char mac[ETH_ALEN]) {
	if (mac_invalid(mac))
		return ALERT_INVALID_MAC;

	int addrs = 0, pairs = 0, claims = 0;
	for (int i = 0; i < cs->n; i++) {
		if (cs->recs[i].bound)
			claims++;
		if (pair_seen(cs, i))
			continue;
		pairs++;
		if (memcmp(cs->recs[i].mac, mac, ETH_ALEN) == 0)
			addrs++;
	}
	if (addrs >= LIMIT_SAME_MAC)
		return ALERT_SAME_HOST;
	if (claims >= LIMIT_CLAIMS)
		return ALERT_CLAIMED;
	if (pairs >= LIMIT_PAIRS)
		return ALERT_MANY_HOSTS;
	return ALERT_NONE;
}

static enum verdict escalate(const struct conflicts *cs,
                             const unsigned char mac[ETH_ALEN],
                             enum verdict otherwise, enum alert_kind *kind) {
	*kind = evaluate(cs, mac);
	return *kind == ALERT_NONE ? otherwise : V_ALERT;
}

enum verdict conflict_probe(struct conflicts *cs, uint32_t addr,
                            const unsigned char mac[ETH_ALEN], int forged,
                            uint64_t now, enum alert_kind *kind) {
	record(cs, addr, mac, 0, forged, now);
	return escalate(cs, mac, V_GIVE_UP, kind);
}

enum verdict conflict_claim(struct conflicts *cs, uint32_t addr,
                            const unsigned char mac[ETH_ALEN], int forged,
                            uint64_t now, enum alert_kind *kind) {
	int recent = cs->last_defense && now - cs->last_defense < cs->defend_ms;

	*kind = ALERT_NONE;
	record(cs, addr, mac, 1, forged, now);
	if (cs->forced) {
		if (recent)
			return V_HOLD;
		cs->last_defense = now;
		return V_DEFEND;
	}

	if (mac_invalid(mac) || recent)
		return escalate(cs, mac, V_GIVE_UP, kind);

	enum verdict v = escalate(cs, mac, V_DEFEND, kind);
	if (v == V_DEFEND)
		cs->last_defense = now;
	return v;
}

int conflicts_forged(const struct conflicts *cs) {
	for (int i = 0; i < cs->n; i++)
		if (cs->recs[i].forged)
			return 1;
	return 0;
}

int conflicts_has_mac(const struct conflicts *cs,
                      const unsigned char mac[ETH_ALEN]) {
	for (int i = 0; i < cs->n; i++)
		if (memcmp(cs->recs[i].mac, mac, ETH_ALEN) == 0)
			return 1;
	return 0;
}

const char *alert_name(enum alert_kind kind) {
	switch (kind) {
	case ALERT_INVALID_MAC:
		return "invalid responder MAC";
	case ALERT_SAME_HOST:
		return "single host claiming addresses (A)";
	case ALERT_MANY_HOSTS:
		return "many hosts claiming addresses (B)";
	case ALERT_CLAIMED:
		return "address in use repeatedly claimed (C)";
	case ALERT_NONE:
		break;
	}
	return "conflict";
}
