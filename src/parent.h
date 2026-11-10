#ifndef TUNDRA_PARENT_H
#define TUNDRA_PARENT_H

#include <sys/types.h>

#define PARENT_ENV "TUNDRA_PARENT_PID"

int parent_parse(const char *s, pid_t *pid);
void parent_bind(void);
void parent_announce(void);

#endif
