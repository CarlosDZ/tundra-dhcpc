#ifndef TUNDRA_ARP_H
#define TUNDRA_ARP_H

#include <linux/if_ether.h>
#include <stdint.h>

struct arp_msg {
	uint16_t oper;
	unsigned char sha[ETH_ALEN];
	uint32_t spa;
	uint32_t tpa;
};

int arp_open(int ifindex);
int arp_request(int fd, int ifindex, const unsigned char mac[ETH_ALEN],
                uint32_t spa, uint32_t tpa);
int arp_read(int fd, struct arp_msg *m);

#endif
