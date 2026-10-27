#ifndef TUNDRA_CONFLICT_H
#define TUNDRA_CONFLICT_H

#include <linux/if_ether.h>
#include <stdint.h>

#define CONFLICT_WINDOW_MS 300000
#define CONFLICT_MAX 16
#define LIMIT_SAME_MAC 3
#define LIMIT_PAIRS 10
#define LIMIT_CLAIMS 3

enum verdict { V_DEFEND, V_HOLD, V_GIVE_UP, V_ALERT };

enum alert_kind {
	ALERT_NONE,
	ALERT_INVALID_MAC,
	ALERT_SAME_HOST,
	ALERT_MANY_HOSTS,
	ALERT_CLAIMED
};

struct conflict {
	uint64_t at;
	uint32_t addr;
	unsigned char mac[ETH_ALEN];
	int bound;
	int forged;
};

struct conflicts {
	struct conflict recs[CONFLICT_MAX];
	int n;
	uint64_t last_defense;
	uint64_t defend_ms;
	int forced;
};

void conflicts_init(struct conflicts *cs, uint64_t defend_ms, int forced);
void conflicts_new_address(struct conflicts *cs);
enum verdict conflict_probe(struct conflicts *cs, uint32_t addr,
                            const unsigned char mac[ETH_ALEN], int forged,
                            uint64_t now, enum alert_kind *kind);
enum verdict conflict_claim(struct conflicts *cs, uint32_t addr,
                            const unsigned char mac[ETH_ALEN], int forged,
                            uint64_t now, enum alert_kind *kind);
int conflicts_forged(const struct conflicts *cs);
int conflicts_has_mac(const struct conflicts *cs,
                      const unsigned char mac[ETH_ALEN]);
const char *alert_name(enum alert_kind kind);

#endif
