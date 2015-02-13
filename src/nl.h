/* nl.h - low level netlink protocol functions
 *
 * Copyright (c) 2011-2015 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
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
int nl_sendgetlinks(int fd, int seq);
int nl_sendgetlink(int fd, int seq, int ifindex);
int nl_sendgetaddr4(int fd, int seq, int ifindex);
int nl_sendgetaddr6(int fd, int seq, int ifindex);
int nl_sendgetaddrs(int fd, int seq);
int nl_sendgetaddrs4(int fd, int seq);
int nl_sendgetaddrs6(int fd, int seq);

int nl_open(int nltype, int nlgroup, int *nlportid);

#endif /* NK_NL_H_ */
