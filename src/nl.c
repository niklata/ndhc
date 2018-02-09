/* nl.c - low level netlink protocol functions
 *
 * Copyright (c) 2011-2017 Nicholas J. Kain <njkain at gmail dot com>
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
#include "nk/log.h"
#include "nk/io.h"
#include "nl.h"

int rtattr_assign(struct rtattr *attr, int type, void *data)
{
    struct rtattr **tb = data;
    if (type >= IFA_MAX)
        return 0;
    tb[type] = attr;
    return 0;
}

#define NLMSG_TAIL(nmsg)                               \
    ((struct rtattr *) (((uint8_t*) (nmsg)) +          \
                        NLMSG_ALIGN((nmsg)->nlmsg_len)))

int nl_add_rtattr(struct nlmsghdr *n, size_t max_length, int type,
                  const void *data, size_t data_length)
{
    size_t length = RTA_LENGTH(data_length);

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length) > max_length)
        return -E2BIG;

    struct rtattr *rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = length;
    memcpy(RTA_DATA(rta), data, data_length);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length);

    return 0;
}

void nl_rtattr_parse(const struct nlmsghdr *nlh, size_t offset,
                     nl_rtattr_parse_fn workfn, void *data)
{
    struct rtattr *attr =
        (struct rtattr *)((char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(offset));
    size_t rtlen = nlh->nlmsg_len - NLMSG_HDRLEN - NLMSG_ALIGN(offset);
    for (; RTA_OK(attr, rtlen); attr = RTA_NEXT(attr, rtlen)) {
        if (workfn(attr, attr->rta_type, data) < 0)
            break;
    }
}

ssize_t nl_recv_buf(int fd, char buf[static 1], size_t blen)
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
    ret = safe_recvmsg(fd, &msg, MSG_DONTWAIT);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        log_error("%s: recvmsg failed: %s", __func__, strerror(errno));
        return -1;
    }
    if (msg.msg_flags & MSG_TRUNC) {
        log_error("%s: Buffer not long enough for message.", __func__);
        return -1;
    }
    if (msg.msg_namelen != sizeof addr) {
        log_error("%s: Response was not of the same address family.",
                  __func__);
        return -1;
    }
    return ret;
}

int nl_foreach_nlmsg(char buf[static 1], size_t blen, uint32_t seq, uint32_t portid,
                     nlmsg_foreach_fn pfn, void *fnarg)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;

    assert(pfn);
    for (;NLMSG_OK(nlh, blen); nlh = NLMSG_NEXT(nlh, blen)) {
        // PortID should be zero for messages from the kernel.
        if (nlh->nlmsg_pid && portid && nlh->nlmsg_pid != portid)
            continue;
        if (seq && nlh->nlmsg_seq != seq)
            continue;

        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
            pfn(nlh, fnarg);
        } else {
            switch (nlh->nlmsg_type) {
                case NLMSG_ERROR:
                    log_line("%s: Received a NLMSG_ERROR: %s",
                             __func__, strerror(nlmsg_get_error(nlh)));
                    return -1;
                case NLMSG_DONE:
                    return 0;
                case NLMSG_OVERRUN:
                    log_line("%s: Received a NLMSG_OVERRUN.", __func__);
                case NLMSG_NOOP:
                default:
                    break;
            }
        }
    }
    return 0;
}

static int nl_sendgetlink_do(int fd, uint32_t seq, int ifindex, int by_ifindex)
{
    char nlbuf[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)nlbuf;
    struct ifinfomsg *ifinfomsg;

    memset(nlbuf, 0, sizeof nlbuf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    nlh->nlmsg_seq = seq;

    if (by_ifindex) {
        ifinfomsg = NLMSG_DATA(nlh);
        ifinfomsg->ifi_index = ifindex;
    }

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };
    ssize_t r = safe_sendto(fd, nlbuf, nlh->nlmsg_len, 0,
                            (struct sockaddr *)&addr, sizeof addr);
    if (r < 0 || (size_t)r != nlh->nlmsg_len) {
        if (r < 0)
            log_error("%s: sendto socket failed: %s", __func__,
                      strerror(errno));
        else
            log_error("%s: sendto short write: %z < %zu", __func__, r,
                      nlh->nlmsg_len);
        return -1;
    }
    return 0;
}

int nl_sendgetlinks(int fd, uint32_t seq)
{
    return nl_sendgetlink_do(fd, seq, 0, 0);
}

int nl_sendgetlink(int fd, uint32_t seq, int ifindex)
{
    return nl_sendgetlink_do(fd, seq, ifindex, 1);
}

static int nl_sendgetaddr_do(int fd, uint32_t seq, uint32_t ifindex, int by_ifindex,
                             int afamily, int by_afamily)
{
    char nlbuf[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)nlbuf;
    struct ifaddrmsg *ifaddrmsg;

    memset(nlbuf, 0, sizeof nlbuf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    nlh->nlmsg_seq = seq;

    ifaddrmsg = NLMSG_DATA(nlh);
    if (by_afamily)
        ifaddrmsg->ifa_family = afamily;
    if (by_ifindex)
        ifaddrmsg->ifa_index = ifindex;

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };
    ssize_t r = safe_sendto(fd, nlbuf, nlh->nlmsg_len, 0,
                            (struct sockaddr *)&addr, sizeof addr);
    if (r < 0 || (size_t)r != nlh->nlmsg_len) {
        if (r < 0)
            log_error("%s: sendto socket failed: %s", __func__,
                      strerror(errno));
        else
            log_error("%s: sendto short write: %z < %zu", __func__, r,
                      nlh->nlmsg_len);
        return -1;
    }
    return 0;
}

int nl_sendgetaddrs(int fd, uint32_t seq)
{
    return nl_sendgetaddr_do(fd, seq, 0, 0, 0, 0);
}

int nl_sendgetaddrs4(int fd, uint32_t seq)
{
    return nl_sendgetaddr_do(fd, seq, 0, 0, AF_INET, 1);
}

int nl_sendgetaddrs6(int fd, uint32_t seq)
{
    return nl_sendgetaddr_do(fd, seq, 0, 0, AF_INET6, 1);
}

int nl_sendgetaddr(int fd, uint32_t seq, uint32_t ifindex)
{
    return nl_sendgetaddr_do(fd, seq, ifindex, 1, 0, 0);
}

int nl_sendgetaddr4(int fd, uint32_t seq, uint32_t ifindex)
{
    return nl_sendgetaddr_do(fd, seq, ifindex, 1, AF_INET, 1);
}

int nl_sendgetaddr6(int fd, uint32_t seq, uint32_t ifindex)
{
    return nl_sendgetaddr_do(fd, seq, ifindex, 1, AF_INET6, 1);
}

int nl_open(int nltype, unsigned nlgroup, uint32_t *nlportid)
{
    int fd;
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, nltype);
    if (fd < 0) {
        log_error("%s: socket failed: %s", __func__, strerror(errno));
        return -1;
    }
    socklen_t al;
    struct sockaddr_nl nlsock = {
        .nl_family = AF_NETLINK,
        .nl_groups = nlgroup,
    };
    if (bind(fd, (struct sockaddr *)&nlsock, sizeof nlsock) < 0) {
        log_error("%s: bind to group failed: %s",
                  __func__, strerror(errno));
        goto err_close;
    }
    al = sizeof nlsock;
    if (getsockname(fd, (struct sockaddr *)&nlsock, &al) < 0) {
        log_error("%s: getsockname failed: %s",
                  __func__, strerror(errno));
        goto err_close;
    }
    if (al != sizeof nlsock) {
        log_error("%s: Bound socket doesn't have right family size.",
                  __func__);
        goto err_close;
    }
    if (nlsock.nl_family != AF_NETLINK) {
        log_error("%s: Bound socket isn't AF_NETLINK.",
                  __func__);
        goto err_close;
    }
    if (nlportid)
        *nlportid = nlsock.nl_pid;
    return fd;
  err_close:
    close(fd);
    return -1;
}

