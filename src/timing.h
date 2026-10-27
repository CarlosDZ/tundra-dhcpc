#ifndef TUNDRA_TIMING_H
#define TUNDRA_TIMING_H

#include "dhcp.h"
#include "lease.h"

#include <stdint.h>

#define BACKOFF_START_MS 4000
#define BACKOFF_MAX_MS 64000
#define JITTER_MS 1000
#define RENEW_MIN_S 60
#define LEASE_INFINITE 0xffffffffu
#define LIFETIME_FOREVER 0xffffffffu
#define LIFETIME_MARGIN_S 10

uint64_t now_ms(void);
uint64_t scaled_ms(uint64_t secs);
uint64_t random_ms(uint64_t min, uint64_t max);
uint64_t backoff_next(uint64_t *backoff, uint64_t now);
uint64_t retry_before(uint64_t now, uint64_t limit);
void lease_timers(struct lease_times *lt, const struct dhcp_info *lease,
                  uint64_t now);
uint32_t lifetime_until(uint64_t expiry_at, uint64_t now);
uint32_t lease_lifetime(const struct dhcp_info *lease, uint64_t ack_at,
                        uint64_t now);
uint16_t elapsed_secs(uint64_t since, uint64_t now);

#endif
