#include "gateway.h"

#include <string.h>

void gateway_init(struct gateway *g) { memset(g, 0, sizeof(*g)); }

void gateway_start(struct gateway *g, uint64_t now) {
	g->nseen = 0;
	g->forged = 0;
	g->until = now + GW_WAIT_MS;
}

void gateway_stop(struct gateway *g) { g->until = 0; }

int gateway_due(const struct gateway *g, uint64_t now) {
	return g->until && now >= g->until;
}

static void seen_add(struct gateway *g, const unsigned char mac[ETH_ALEN]) {
	for (int i = 0; i < g->nseen; i++)
		if (memcmp(g->seen[i], mac, ETH_ALEN) == 0)
			return;
	if (g->nseen < GW_MAX_MACS)
		memcpy(g->seen[g->nseen++], mac, ETH_ALEN);
}

enum gw_event gateway_reply(struct gateway *g,
                            const unsigned char mac[ETH_ALEN], int forged) {
	if (g->until) {
		g->forged |= forged;
		seen_add(g, mac);
		return GW_NONE;
	}
	if (!g->known || memcmp(mac, g->mac, ETH_ALEN) == 0)
		return GW_NONE;

	g->nseen = 0;
	g->forged = forged;
	seen_add(g, g->mac);
	seen_add(g, mac);
	return GW_IMPERSONATED;
}

enum gw_event gateway_settle(struct gateway *g) {
	g->until = 0;
	if (g->nseen >= 2)
		return GW_IMPERSONATED;
	if (g->nseen == 0)
		return GW_NONE;

	int changed = !g->known || memcmp(g->mac, g->seen[0], ETH_ALEN) != 0;
	memcpy(g->mac, g->seen[0], ETH_ALEN);
	g->known = 1;
	return changed ? GW_LEARNED : GW_NONE;
}
