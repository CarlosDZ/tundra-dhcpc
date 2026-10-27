#ifndef TUNDRA_GATEWAY_H
#define TUNDRA_GATEWAY_H

#include <linux/if_ether.h>
#include <stdint.h>

#define GW_WAIT_MS 1000
#define GW_MAX_MACS 4

enum gw_event { GW_NONE, GW_LEARNED, GW_IMPERSONATED };

struct gateway {
	unsigned char mac[ETH_ALEN];
	int known;
	unsigned char seen[GW_MAX_MACS][ETH_ALEN];
	int nseen;
	int forged;
	uint64_t until;
};

void gateway_init(struct gateway *g);
void gateway_start(struct gateway *g, uint64_t now);
void gateway_stop(struct gateway *g);
int gateway_due(const struct gateway *g, uint64_t now);
enum gw_event gateway_reply(struct gateway *g,
                            const unsigned char mac[ETH_ALEN], int forged);
enum gw_event gateway_settle(struct gateway *g);

#endif
