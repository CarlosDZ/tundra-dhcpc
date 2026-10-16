#ifndef TUNDRA_LINK_H
#define TUNDRA_LINK_H

enum link_event { LINK_NONE, LINK_UP, LINK_DOWN, LINK_GONE };

int link_open(void);
int link_request(int fd, int ifindex);
int link_read(int fd, int ifindex, enum link_event *ev);

#endif
