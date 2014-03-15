/* ifset.c - Linux-specific net interface settings include
 *
 * Copyright (c) 2004-2014 Nicholas J. Kain <njkain at gmail dot com>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __USE_GNU 1
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pwd.h>
#include <grp.h>

#include <errno.h>

#include "ifset.h"
#include "ifchd.h"
#include "ndhc.h"
#include "log.h"
#include "ifch_proto.h"
#include "strl.h"
#include "nl.h"

static uint32_t ifset_nl_seq;

static int set_if_flag(short flag)
{
    int fd, ret = -1;
    struct ifreq ifrt;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (set_if_flag) failed to open interface socket: %s",
                 client_config.interface, strerror(errno));
        goto out0;
    }

    strnkcpy(ifrt.ifr_name, client_config.interface, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFFLAGS, &ifrt) < 0) {
        log_line("%s: unknown interface: %s", client_config.interface, strerror(errno));
        goto out1;
    }
    if (((ifrt.ifr_flags & flag ) ^ flag) & flag) {
        strnkcpy(ifrt.ifr_name, client_config.interface, IFNAMSIZ);
        ifrt.ifr_flags |= flag;
        if (ioctl(fd, SIOCSIFFLAGS, &ifrt) < 0) {
            log_line("%s: failed to set interface flags: %s",
                     client_config.interface, strerror(errno));
            goto out1;
        }
    } else
        ret = 0;

  out1:
    close(fd);
  out0:
    return ret;
}

// 32-bit position values are relatively prime to 37, so the residue mod37
// gives a unique mapping for each value.  Gives correct result for v=0.
static int trailz(uint32_t v)
{
    static const int bpm37[] = {
        32, 0, 1, 26, 2, 23, 27, 0, 3, 16, 24, 30, 28, 11, 0, 13, 4, 7, 17,
        0, 25, 22, 31, 15, 29, 10, 12, 6, 0, 21, 14, 9, 5, 20, 8, 19, 18
    };
    return bpm37[(-v & v) % 37];
}

// sn must be in network order
static inline int subnet4_to_prefixlen(uint32_t sn)
{
    return 32 - trailz(ntohl(sn));
}

struct ipbcpfx {
    int fd;
    uint32_t ipaddr;
    uint32_t bcast;
    uint8_t prefixlen;
    bool already_ok;
};

static int rtattr_assign(struct rtattr *attr, int type, void *data)
{
    struct rtattr **tb = data;
    if (type >= IFA_MAX)
        return 0;
    tb[type] = attr;
    return 0;
}

static ssize_t rtnl_addr_broadcast_send(int fd, int type, int ifa_flags,
                                        int ifa_scope, struct in_addr *ipaddr,
                                        struct in_addr *bcast,
                                        uint8_t prefixlen)
{
    uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
        NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
        RTA_LENGTH(sizeof(struct in6_addr))];
    uint8_t response[NLMSG_ALIGN(sizeof(struct nlmsghdr)) + 64];
    struct nlmsghdr *header;
    struct ifaddrmsg *ifaddrmsg;
    struct sockaddr_nl nl_addr;
    ssize_t r;

    if (!ipaddr && !bcast) {
        log_warning("%s: (%s) no ipaddr or bcast!",
                    client_config.interface, __func__);
        return -1;
    }

    memset(&request, 0, sizeof request);
    header = (struct nlmsghdr *)request;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    header->nlmsg_type = type;
    header->nlmsg_flags = NLM_F_REPLACE | NLM_F_ACK | NLM_F_REQUEST;
    header->nlmsg_seq = ifset_nl_seq++;

    ifaddrmsg = NLMSG_DATA(header);
    ifaddrmsg->ifa_family = AF_INET;
    ifaddrmsg->ifa_prefixlen = prefixlen;
    ifaddrmsg->ifa_flags = ifa_flags;
    ifaddrmsg->ifa_scope = ifa_scope;
    ifaddrmsg->ifa_index = client_config.ifindex;

    if (ipaddr) {
        if (nl_add_rtattr(header, sizeof request, IFA_LOCAL,
                          &ipaddr, sizeof ipaddr) < 0) {
            log_line("%s: (%s) couldn't add IFA_LOCAL to nlmsg",
                     client_config.interface, __func__);
            return -1;
        }
    }
    if (bcast) {
        if (nl_add_rtattr(header, sizeof request, IFA_BROADCAST,
                          &bcast, sizeof bcast) < 0) {
            log_line("%s: (%s) couldn't add IFA_BROADCAST to nlmsg",
                     client_config.interface, __func__);
            return -1;
        }
    }

    memset(&nl_addr, 0, sizeof nl_addr);
    nl_addr.nl_family = AF_NETLINK;

  retry_sendto:
    r = sendto(fd, request, header->nlmsg_len, 0,
               (struct sockaddr *)&nl_addr, sizeof nl_addr);
    if (r < 0) {
        if (errno == EINTR)
            goto retry_sendto;
        else {
            log_line("%s: (%s) netlink sendto failed: %s",
                     client_config.interface, __func__, strerror(errno));
            return -1;
        }
    }
  retry_recv:
    r = recv(fd, response, sizeof response, 0);
    if (r < 0) {
        if (errno == EINTR)
            goto retry_recv;
        else {
            log_line("%s: (%s) netlink recv failed: %s",
                     client_config.interface, __func__, strerror(errno));
            return -1;
        }
    }
    if ((size_t)r < sizeof(struct nlmsghdr)) {
        log_line("%s: (%s) netlink recv returned a headerless response",
                 client_config.interface, __func__);
        return -1;
    }
    uint32_t nr_type;
    memcpy(&nr_type, response + 4, 2);
    if (nr_type == NLMSG_ERROR) {
        log_line("%s: (%s) netlink sendto returned NLMSG_ERROR",
                 client_config.interface, __func__);
        return -1;
    }
    return 0;
}

static void ipbcpfx_clear_others_do(const struct nlmsghdr *nlh, void *data)
{
    struct rtattr *tb[IFA_MAX] = {0};
    struct ifaddrmsg *ifm = nlmsg_get_data(nlh);
    struct ipbcpfx *ipx = data;
    int r;

    switch(nlh->nlmsg_type) {
        case RTM_NEWADDR:
            if (ifm->ifa_index != (unsigned)client_config.ifindex) {
                printf("not correct ifindex\n");
                return;
            }
            if (ifm->ifa_family != AF_INET) {
                printf("not AF_INET\n");
                return;
            }
            if (!(ifm->ifa_flags & IFA_F_PERMANENT)) {
                printf("not F_PERMANENT\n");
                goto erase;
            }
            if (!(ifm->ifa_scope & RT_SCOPE_UNIVERSE)) {
                printf("not SCOPE_UNIVERSE\n");
                goto erase;
            }
            if (ifm->ifa_prefixlen != ipx->prefixlen) {
                printf("different prefixlen (%u)\n", ifm->ifa_prefixlen);
                goto erase;
            }
            nl_rtattr_parse(nlh, sizeof *ifm, rtattr_assign, tb);
            if (!tb[IFA_ADDRESS]) {
                printf("no IFA_ADDRESS\n");
                goto erase;
            }
            if (memcmp(rtattr_get_data(tb[IFA_ADDRESS]), &ipx->ipaddr,
                       sizeof ipx->ipaddr)) {
                printf("different IFA_ADDRESS\n");
                goto erase;
            }
            if (!tb[IFA_BROADCAST]) {
                printf("no IFA_BROADCAST\n");
                goto erase;
            }
            if (memcmp(rtattr_get_data(tb[IFA_BROADCAST]), &ipx->ipaddr,
                       sizeof ipx->ipaddr)) {
                printf("different IFA_BROADCAST\n");
                goto erase;
            }
            break;
        default:
            return;
    }
    // We already have the proper IP+broadcast+prefix.
    ipx->already_ok = true;
    return;

  erase:
    r = rtnl_addr_broadcast_send(ipx->fd, RTM_DELADDR, ifm->ifa_flags,
                                 ifm->ifa_scope,
                                 rtattr_get_data(tb[IFA_ADDRESS]),
                                 rtattr_get_data(tb[IFA_BROADCAST]),
                                 ifm->ifa_prefixlen);
    if (r < 0) {
        log_warning("%s: (%s) Failed to delete IP and broadcast addresses.",
                    client_config.interface, __func__);
    }
    return;
}

static int ipbcpfx_clear_others(int fd, uint32_t ipaddr, uint32_t bcast,
                                uint8_t prefixlen)
{
    char nlbuf[8192];
    struct ipbcpfx ipx = { .fd = fd, .ipaddr = ipaddr, .bcast = bcast,
                           .prefixlen = prefixlen, .already_ok = false };
    ssize_t ret;
    ret = nl_sendgetaddr(fd, ifset_nl_seq++, client_config.ifindex);
    if (ret < 0)
        return ret;

    do {
        ret = nl_recv_buf(fd, nlbuf, sizeof nlbuf);
        if (ret == -1)
            break;
        if (nl_foreach_nlmsg(nlbuf, ret, 0,
                             ipbcpfx_clear_others_do, &ipx) == -1)
            break;
    } while (ret > 0);
    return ret;
}

// str_bcast is optional.
void perform_ip_subnet_bcast(const char *str_ipaddr,
                             const char *str_subnet, const char *str_bcast)
{
    struct in_addr ipaddr, subnet, bcast;
    int fd, r;
    uint8_t prefixlen;

    if (!str_ipaddr) {
        log_line("%s: (%s) interface ip address is NULL",
                 client_config.interface, __func__);
        return;
    }
    if (!str_subnet) {
        log_line("%s: (%s) interface subnet address is NULL",
                 client_config.interface, __func__);
        return;
    }

    if (inet_pton(AF_INET, str_ipaddr, &ipaddr) <= 0) {
        log_line("%s: (%s) bad interface ip address: '%s'",
                 client_config.interface, __func__, str_ipaddr);
        return;
    }

    if (inet_pton(AF_INET, str_subnet, &subnet) <= 0) {
        log_line("%s: (%s) bad interface subnet address: '%s'",
                 client_config.interface, __func__, str_subnet);
        return;
    }
    prefixlen = subnet4_to_prefixlen(subnet.s_addr);

    if (str_bcast) {
        if (inet_pton(AF_INET, str_bcast, &bcast) <= 0) {
            log_line("%s: (%s) bad interface broadcast address: '%s'",
                     client_config.interface, __func__, str_bcast);
            return;
        }
    } else {
        // Generate the standard broadcast address if unspecified.
        bcast.s_addr = ipaddr.s_addr | htonl(0xfffffffflu >> prefixlen);
    }

    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        log_line("%s: (%s) netlink socket open failed: %s",
                 client_config.interface, __func__, strerror(errno));
        return;
    }

    r = ipbcpfx_clear_others(fd, ipaddr.s_addr, bcast.s_addr, prefixlen);
    if (r < 0) {
        close(fd);
        return;
    }

    r = rtnl_addr_broadcast_send(fd, RTM_NEWADDR, IFA_F_PERMANENT,
                                 RT_SCOPE_UNIVERSE, &ipaddr, &bcast,
                                 prefixlen);

    close(fd); // XXX: Move this when we also set the link flags.
    if (r < 0)
        return;

    log_line("Interface IP set to: '%s'", str_ipaddr);
    log_line("Interface subnet set to: '%s'", str_subnet);
    if (str_bcast)
        log_line("Broadcast address set to: '%s'", str_bcast);

    // XXX: Would be nice to do this via netlink, too.
    if (set_if_flag(IFF_UP | IFF_RUNNING))
        return;
}


void perform_router(const char *str, size_t len)
{
    struct rtentry rt;
    struct sockaddr_in *dest;
    struct sockaddr_in *gateway;
    struct sockaddr_in *mask;
    struct in_addr router;
    int fd;

    if (!str)
        return;
    if (len < 4)
        return;
    if (inet_pton(AF_INET, str, &router) <= 0)
        return;

    memset(&rt, 0, sizeof(struct rtentry));
    dest = (struct sockaddr_in *) &rt.rt_dst;
    dest->sin_family = AF_INET;
    dest->sin_addr.s_addr = 0x00000000;
    gateway = (struct sockaddr_in *) &rt.rt_gateway;
    gateway->sin_family = AF_INET;
    gateway->sin_addr = router;
    mask = (struct sockaddr_in *) &rt.rt_genmask;
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = 0x00000000;

    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    if (mask->sin_addr.s_addr == 0xffffffff) rt.rt_flags |= RTF_HOST;
    rt.rt_dev = client_config.interface;
    rt.rt_metric = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_router) failed to open interface socket: %s",
                 client_config.interface, strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCADDRT, &rt)) {
        if (errno != EEXIST)
            log_line("%s: failed to set route: %s",
                     client_config.interface, strerror(errno));
    } else
        log_line("Gateway router set to: '%s'", str);
    close(fd);
}

void perform_mtu(const char *str, size_t len)
{
    int fd;
    unsigned int mtu;
    struct ifreq ifrt;

    if (!str)
        return;
    if (len < 2)
        return;

    mtu = strtol(str, NULL, 10);
    // Minimum MTU for physical IPv4 links is 576 octets.
    if (mtu < 576)
        return;
    ifrt.ifr_mtu = mtu;
    strnkcpy(ifrt.ifr_name, client_config.interface, IFNAMSIZ);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_mtu) failed to open interface socket: %s",
                 client_config.interface, strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFMTU, &ifrt) < 0)
        log_line("%s: failed to set MTU (%d): %s", client_config.interface, mtu,
                 strerror(errno));
    else
        log_line("MTU set to: '%s'", str);
    close(fd);
}

