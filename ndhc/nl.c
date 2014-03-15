/* nl.c - low level netlink protocol functions
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

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "log.h"
#include "nl.h"

#define NLMSG_TAIL(nmsg)                               \
    ((struct rtattr *) (((uint8_t*) (nmsg)) +          \
                        NLMSG_ALIGN((nmsg)->nlmsg_len)))

int nl_add_rtattr(struct nlmsghdr *n, size_t max_length, int type,
                  const void *data, size_t data_length)
{
    size_t length;
    struct rtattr *rta;

    length = RTA_LENGTH(data_length);

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length) > max_length)
        return -E2BIG;

    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = length;
    memcpy(RTA_DATA(rta), data, data_length);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length);

    return 0;
}

void nl_attr_parse(const struct nlmsghdr *nlh, size_t offset,
                   nl_attr_parse_fn workfn, void *data)
{
    struct nlattr *attr;
    for (attr = (struct nlattr *)
             ((char *)nlh + NLMSG_HDRLEN + NLMSG_ALIGN(offset));
         nl_attr_ok(attr, (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) -
                    (char *)attr);
         attr = (struct nlattr *)((char *)attr + NLMSG_ALIGN(attr->nla_len)))
    {
        int type = attr->nla_type & NLA_TYPE_MASK;
        if (workfn(attr, type, data) < 0)
            break;
    }
}

void nl_rtattr_parse(const struct nlmsghdr *nlh, size_t offset,
                     nl_rtattr_parse_fn workfn, void *data)
{
    struct rtattr *attr;
    for (attr = (struct rtattr *)
             ((char *)nlh + NLMSG_HDRLEN + NLMSG_ALIGN(offset));
         rtattr_ok(attr, (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) -
                    (char *)attr);
         attr = (struct rtattr *)((char *)attr + NLMSG_ALIGN(attr->rta_len)))
    {
        if (workfn(attr, attr->rta_type, data) < 0)
            break;
    }
}

ssize_t nl_recv_buf(int fd, char *buf, size_t blen)
{
    struct sockaddr_nl addr;
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = blen,
    };
    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof addr,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    ssize_t ret;
  retry:
    ret = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (ret == -1) {
        if (errno == EINTR)
            goto retry;
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("nl_fill_buf: recvmsg failed: %s", strerror(errno));
            return -1;
        }
        return 0;
    }
    if (msg.msg_flags & MSG_TRUNC) {
        log_error("nl_fill_buf: Buffer not long enough for message.");
        return -1;
    }
    if (msg.msg_namelen != sizeof addr) {
        log_error("nl_fill_buf: Response was not of the same address family.");
        return -1;
    }
    return ret;
}

int nl_foreach_nlmsg(char *buf, size_t blen, uint32_t seq, uint32_t portid,
                     nlmsg_foreach_fn pfn, void *fnarg)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;

    assert(pfn);
    for (;NLMSG_OK(nlh, blen); nlh = NLMSG_NEXT(nlh, blen)) {
        // PortID should be zero for messages from the kernel.
        if (nlh->nlmsg_pid && portid && nlh->nlmsg_pid != portid)
            continue;
        log_line("%s: seq=%u nlh->nlmsg_seq=%u", __func__, seq, nlh->nlmsg_seq);
        if (seq && nlh->nlmsg_seq != seq)
            continue;

        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
            pfn(nlh, fnarg);
        } else {
            switch (nlh->nlmsg_type) {
                case NLMSG_ERROR:
                    log_line("nl: Received a NLMSG_ERROR: %s",
                             strerror(nlmsg_get_error(nlh)));
                    return -1;
                case NLMSG_DONE:
                    return 0;
                case NLMSG_OVERRUN:
                    log_line("nl: Received a NLMSG_OVERRUN.");
                case NLMSG_NOOP:
                default:
                    break;
            }
        }
    }
    return 0;
}

int nl_sendgetlink(int fd, int seq)
{
    char nlbuf[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)nlbuf;
    ssize_t r;

    memset(nlbuf, 0, sizeof nlbuf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof (struct rtattr));
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    nlh->nlmsg_seq = seq;

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };
retry_sendto:
    r = sendto(fd, nlbuf, nlh->nlmsg_len, 0,
               (struct sockaddr *)&addr, sizeof addr);
    if (r < 0) {
        if (errno == EINTR)
            goto retry_sendto;
        else {
            log_warning("%s: netlink sendto socket failed: %s",
                        __func__, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int nl_sendgetaddr(int fd, int seq, int ifindex)
{
    char nlbuf[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)nlbuf;
    struct ifaddrmsg *ifaddrmsg;
    ssize_t r;

    memset(nlbuf, 0, sizeof nlbuf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof (struct rtattr));
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    nlh->nlmsg_seq = seq;

    ifaddrmsg = NLMSG_DATA(nlh);
    ifaddrmsg->ifa_family = AF_INET;
    ifaddrmsg->ifa_index = ifindex;

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };
retry_sendto:
    r = sendto(fd, nlbuf, nlh->nlmsg_len, 0,
               (struct sockaddr *)&addr, sizeof addr);
    if (r < 0) {
        if (errno == EINTR)
            goto retry_sendto;
        else {
            log_warning("%s: netlink sendto socket failed: %s",
                        __func__, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int nl_open(int nltype, int nlgroup, int *nlportid)
{
    int fd;
    fd = socket(AF_NETLINK, SOCK_RAW, nltype);
    if (fd == -1) {
        log_error("nl_open: socket failed: %s", strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("nl_open: Set non-blocking failed: %s", strerror(errno));
        goto err_close;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        log_error("nl_open: Set close-on-exec failed: %s", strerror(errno));
        goto err_close;
    }
    socklen_t al;
    struct sockaddr_nl nlsock = {
        .nl_family = AF_NETLINK,
        .nl_groups = nlgroup,
    };
    if (bind(fd, (struct sockaddr *)&nlsock, sizeof nlsock) == -1) {
        log_error("nl_open: bind to group failed: %s", strerror(errno));
        goto err_close;
    }
    al = sizeof nlsock;
    if (getsockname(fd, (struct sockaddr *)&nlsock, &al) == -1) {
        log_error("nl_open: getsockname failed: %s", strerror(errno));
        goto err_close;
    }
    if (al != sizeof nlsock) {
        log_error("nl_open: Bound socket doesn't have right family size.");
        goto err_close;
    }
    if (nlsock.nl_family != AF_NETLINK) {
        log_error("nl_open: Bound socket isn't AF_NETLINK.");
        goto err_close;
    }
    if (nlportid)
        *nlportid = nlsock.nl_pid;
    return fd;
  err_close:
    close(fd);
    return -1;
}

