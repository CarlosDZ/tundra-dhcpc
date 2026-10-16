#ifndef TUNDRA_ARP_H
#define TUNDRA_ARP_H

#include <linux/if_ether.h>
#include <stdint.h>

int arp_open(int ifindex);
int arp_probe(int fd, int ifindex, const unsigned char mac[ETH_ALEN],
              uint32_t addr);
int arp_announce(int fd, int ifindex, const unsigned char mac[ETH_ALEN],
                 uint32_t addr);
int arp_conflict(int fd, const unsigned char mac[ETH_ALEN], uint32_t addr,
                 unsigned char sender[ETH_ALEN]);

#endif
