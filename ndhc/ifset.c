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

// str_bcast is optional.
void perform_ip_subnet_bcast(const char *str_ipaddr,
                             const char *str_subnet, const char *str_bcast)
{
    uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
        NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
        RTA_LENGTH(sizeof(struct in6_addr))];
    struct in_addr ipaddr, subnet, bcast;
    struct sockaddr_nl nl_addr;
    struct nlmsghdr *header;
    struct ifaddrmsg *ifaddrmsg;
    int nls, r;
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

    memset(&request, 0, sizeof request);
    header = (struct nlmsghdr *)request;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    header->nlmsg_type = RTM_NEWADDR;
    header->nlmsg_flags = NLM_F_REPLACE | NLM_F_ACK | NLM_F_REQUEST;
    header->nlmsg_seq = 1;

    ifaddrmsg = NLMSG_DATA(header);
    ifaddrmsg->ifa_family = AF_INET;
    ifaddrmsg->ifa_prefixlen = prefixlen;
    ifaddrmsg->ifa_flags = IFA_F_PERMANENT;
    ifaddrmsg->ifa_scope = RT_SCOPE_UNIVERSE;
    ifaddrmsg->ifa_index = client_config.ifindex;

    if (nl_add_rtattr(header, sizeof request, IFA_LOCAL,
                      &ipaddr, sizeof ipaddr) < 0) {
        log_line("%s: (%s) couldn't add IFA_LOCAL to nlmsg",
                 client_config.interface, __func__);
        return;
    }
    if (nl_add_rtattr(header, sizeof request, IFA_BROADCAST,
                      &bcast, sizeof bcast) < 0) {
        log_line("%s: (%s) couldn't add IFA_BROADCAST to nlmsg",
                 client_config.interface, __func__);
        return;
    }

    nls = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (nls < 0) {
        log_line("%s: (%s) netlink socket open failed: %s",
                 client_config.interface, __func__, strerror(errno));
        return;
    }

    memset(&nl_addr, 0, sizeof nl_addr);
    nl_addr.nl_family = AF_NETLINK;

retry_sendto:
    r = sendto(nls, request, header->nlmsg_len, 0,
               (struct sockaddr *)&nl_addr, sizeof nl_addr);
    if (r < 0) {
        if (errno == EINTR)
            goto retry_sendto;
        else {
            log_line("%s: (%s) netlink sendto socket failed: %s",
                     client_config.interface, __func__, strerror(errno));
            close(nls);
            return;
        }
    }
    close(nls);
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

