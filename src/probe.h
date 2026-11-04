#ifndef TUNDRA_PROBE_H
#define TUNDRA_PROBE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PROBE_OUT_MAX 256

enum probe_result { PR_FREE, PR_TAKEN, PR_ALERT, PR_RETRY, PR_CONFIG };

int probe_spawn(const char *ifname, uint32_t addr, pid_t *pid, int *out);
void probe_stop(pid_t pid, int out);
size_t probe_drain(int fd, char *buf, size_t size);
enum probe_result probe_judge(int status, const char *out, char mac[18]);

#endif
