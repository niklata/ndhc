// Copyright 2011-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NK_NL_H_
#define NK_NL_H_

// Limited netlink code.  The horrors...

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static inline int nlmsg_get_error(const struct nlmsghdr *nlh)
{
    const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nlh);
    if (nlh->nlmsg_len < sizeof(struct nlmsgerr) + NLMSG_HDRLEN)
        return EBADMSG;
    return -err->error;
}

int rtattr_assign(struct rtattr *attr, int type, void *data);
int nl_add_rtattr(struct nlmsghdr *n, size_t max_length, int type,
                  const void *data, size_t data_length);
typedef int (*nl_rtattr_parse_fn)(struct rtattr *attr, int type, void *data);
void nl_rtattr_parse(const struct nlmsghdr *nlh, size_t offset,
                     nl_rtattr_parse_fn workfn, void *data);

ssize_t nl_recv_buf(int fd, char *buf, size_t blen);

typedef void (*nlmsg_foreach_fn)(const struct nlmsghdr *, void *);
int nl_foreach_nlmsg(char *buf, size_t blen, uint32_t seq,
                     uint32_t portid,
                     nlmsg_foreach_fn pfn, void *fnarg);
int nl_sendgetlinks(int fd, uint32_t seq);
int nl_sendgetlink(int fd, uint32_t seq, int ifindex);
int nl_sendgetaddr(int fd, uint32_t seq, uint32_t ifindex);
int nl_sendgetaddr4(int fd, uint32_t seq, uint32_t ifindex);
int nl_sendgetaddr6(int fd, uint32_t seq, uint32_t ifindex);
int nl_sendgetaddrs(int fd, uint32_t seq);
int nl_sendgetaddrs4(int fd, uint32_t seq);
int nl_sendgetaddrs6(int fd, uint32_t seq);

int nl_open(int nltype, unsigned nlgroup, uint32_t *nlportid);

#endif

