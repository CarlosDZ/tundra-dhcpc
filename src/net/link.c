#include "link.h"

#include <errno.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int link_open(void) {
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		perror("socket(AF_NETLINK) error");
		return -1;
	}

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind error");
		close(fd);
		return -1;
	}
	return fd;
}

int link_request(int fd, int ifindex) {
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
	} req;
	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifi));
	req.nh.nlmsg_type = RTM_GETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&sa,
	           sizeof(sa)) < 0) {
		perror("sendto error");
		return -1;
	}
	return 0;
}

int link_read(int fd, int ifindex, enum link_event *ev) {
	char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));

	*ev = LINK_NONE;
	ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return 0;
		if (errno == ENOBUFS)
			return link_request(fd, ifindex);
		perror("recv error");
		return -1;
	}

	for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, n);
	     nh = NLMSG_NEXT(nh, n)) {
		if (nh->nlmsg_type != RTM_NEWLINK && nh->nlmsg_type != RTM_DELLINK)
			continue;
		if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
			continue;

		struct ifinfomsg *ifi = NLMSG_DATA(nh);
		if (ifi->ifi_index != ifindex)
			continue;

		if (nh->nlmsg_type == RTM_DELLINK)
			*ev = LINK_GONE;
		else
			*ev = (ifi->ifi_flags & IFF_LOWER_UP) ? LINK_UP : LINK_DOWN;
	}
	return 0;
}
