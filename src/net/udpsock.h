#ifndef TUNDRA_UDPSOCK_H
#define TUNDRA_UDPSOCK_H

#include <stddef.h>
#include <stdint.h>

struct udpsock {
	int fd;
};

int udpsock_open(struct udpsock *us, const char *ifname);
void udpsock_close(struct udpsock *us);

int udpsock_send(const struct udpsock *us, uint32_t dst, const void *payload,
                 size_t len);

int udpsock_recv(const struct udpsock *us, uint8_t *buf, size_t cap,
                 size_t *len);

#endif
