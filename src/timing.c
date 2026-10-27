#include "timing.h"

#include <arpa/inet.h>
#include <sys/random.h>
#include <time.h>

uint64_t now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint64_t scaled_ms(uint64_t secs) {
	return secs * 1000 / TUNDRA_DHCPC_TIME_SCALE;
}

uint64_t random_ms(uint64_t min, uint64_t max) {
	uint32_t r = 0;
	if (getrandom(&r, sizeof(r), 0) != sizeof(r))
		return min;
	return min + r % (max - min + 1);
}

uint64_t backoff_next(uint64_t *backoff, uint64_t now) {
	uint64_t deadline =
	    now + random_ms(*backoff - JITTER_MS, *backoff + JITTER_MS);
	if (*backoff < BACKOFF_MAX_MS)
		*backoff *= 2;
	return deadline;
}

uint64_t retry_before(uint64_t now, uint64_t limit) {
	uint64_t wait = (limit - now) / 2;
	uint64_t min = scaled_ms(RENEW_MIN_S);
	if (wait < min)
		wait = min;
	return now + wait < limit ? now + wait : limit;
}

void lease_timers(struct lease_times *lt, const struct dhcp_info *lease,
                  uint64_t now) {
	uint32_t secs = ntohl(lease->lease);
	if (secs == LEASE_INFINITE) {
		lt->t1_at = lt->t2_at = lt->expiry_at = UINT64_MAX;
		return;
	}

	uint32_t t1 = ntohl(lease->t1);
	uint32_t t2 = ntohl(lease->t2);
	if (!t2 || t2 >= secs)
		t2 = (uint32_t)((uint64_t)secs * 7 / 8);
	if (!t1 || t1 >= t2)
		t1 = secs / 2;

	lt->t1_at = now + scaled_ms(t1);
	lt->t2_at = now + scaled_ms(t2);
	lt->expiry_at = now + scaled_ms(secs);
}

uint32_t lifetime_until(uint64_t expiry_at, uint64_t now) {
	if (expiry_at == UINT64_MAX)
		return LIFETIME_FOREVER;
	uint64_t secs = (expiry_at > now ? expiry_at - now : 0) / 1000;
	secs += LIFETIME_MARGIN_S;
	return secs >= LIFETIME_FOREVER ? LIFETIME_FOREVER - 1 : (uint32_t)secs;
}

uint32_t lease_lifetime(const struct dhcp_info *lease, uint64_t ack_at,
                        uint64_t now) {
	uint32_t secs = ntohl(lease->lease);
	if (secs == LEASE_INFINITE)
		return LIFETIME_FOREVER;
	return lifetime_until(ack_at + scaled_ms(secs), now);
}

uint16_t elapsed_secs(uint64_t since, uint64_t now) {
	if (now < since)
		return 0;
	uint64_t secs = (now - since) / 1000;
	return secs > 0xffff ? 0xffff : (uint16_t)secs;
}
