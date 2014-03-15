/* nl.h - low level netlink protocol functions
 *
 * Copyright (c) 2011-2014 Nicholas J. Kain <njkain at gmail dot com>
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

static inline int nl_attr_ok(const struct nlattr *attr, size_t len)
{
    if (len < sizeof *attr)
        return 0;
    if (attr->nla_len < sizeof *attr)
        return 0;
    if (attr->nla_len > len)
        return 0;
    return 1;
}

static inline int rtattr_ok(const struct rtattr *attr, size_t len)
{
    return RTA_OK(attr, len);
}

static inline size_t nlattr_get_len(const struct nlattr *attr)
{
    return attr->nla_len;
}

static inline void *nlattr_get_data(const struct nlattr *attr)
{
    return (char *)attr + NLA_HDRLEN;
}

static inline void *rtattr_get_data(const struct rtattr *attr)
{
    return (char *)RTA_DATA(attr);
}

static inline void *nlmsg_get_data(const struct nlmsghdr *nlh)
{
    return (char *)nlh + NLMSG_HDRLEN;
}

static inline int nlmsg_get_error(const struct nlmsghdr *nlh)
{
    const struct nlmsgerr *err = nlmsg_get_data(nlh);
    if (nlh->nlmsg_len < sizeof(struct nlmsgerr) + NLMSG_HDRLEN)
        return EBADMSG;
    return err->error & 0x7fffffff;
}

extern int nl_add_rtattr(struct nlmsghdr *n, size_t max_length, int type,
                         const void *data, size_t data_length);
typedef int (*nl_attr_parse_fn)(struct nlattr *attr, int type, void *data);
extern void nl_attr_parse(const struct nlmsghdr *nlh, size_t offset,
                          nl_attr_parse_fn workfn, void *data);
typedef int (*nl_rtattr_parse_fn)(struct rtattr *attr, int type, void *data);
extern void nl_rtattr_parse(const struct nlmsghdr *nlh, size_t offset,
                            nl_rtattr_parse_fn workfn, void *data);

extern ssize_t nl_recv_buf(int fd, char *buf, size_t blen);

typedef void (*nlmsg_foreach_fn)(const struct nlmsghdr *, void *);
extern int nl_foreach_nlmsg(char *buf, size_t blen, uint32_t portid,
                            nlmsg_foreach_fn pfn, void *fnarg);
extern int nl_sendgetlink(int fd, int seq);
extern int nl_sendgetaddr(int fd, int seq, int ifindex);

extern int nl_open(int nltype, int nlgroup, int *nlportid);

#endif /* NK_NL_H_ */
