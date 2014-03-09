/* linux.c - ifchd Linux-specific functions
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

#include "ifchd-defines.h"
#include "log.h"
#include "ifch_proto.h"
#include "strl.h"

extern struct ifchd_client clients[SOCK_QUEUE];

static size_t numokif;
static char okif[MAX_IFACES][IFNAMSIZ];

/* Adds to the list of interface names ifchd clients are allowed to change. */
void add_permitted_if(char *s)
{
    if (numokif >= MAX_IFACES)
        return;
    strnkcpy(okif[numokif++], s, IFNAMSIZ);
}

/* Checks if changes are permitted to a given interface.  1 == allowed */
static int is_permitted(char *name)
{
    /* If empty, permit all. */
    if (!numokif)
        return 1;

    if (!name || strlen(name) == 0)
        return 0;
    for (size_t i = 0; i < numokif; ++i) {
        if (strcmp(name, okif[i]) == 0)
            return 1;
    }
    log_line("attempt to modify interface %s denied", name);
    return 0;
}

/* Verify that peer is authorized to connect (return 1 on success). */
int authorized_peer(int sk, pid_t pid, uid_t uid, gid_t gid)
{
    int ret = 0;
    unsigned int cl;
    struct ucred cr;

    /* No credentials to verify. */
    if ( !(pid || uid || gid) )
        return 1;

    /* Verify that peer has authorized uid/gid/pid. */
    cl = sizeof(struct ucred);
    if (getsockopt(sk, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != -1) {
        if ((pid == 0 || cr.pid == pid) ||
            (uid == 0 || cr.uid == uid) ||
            (gid == 0 || cr.gid == gid))
            ret = 1;
    } else
        log_line("getsockopt returned an error: %s", strerror(errno));
    return ret;
}

void perform_interface(struct ifchd_client *cl, const char *str, size_t len)
{
    if (!str)
        return;

    /* Update interface name. */
    memset(cl->ifnam, '\0', IFNAMSIZ);
    strnkcpy(cl->ifnam, str, IFNAMSIZ);
    log_line("Subsequent commands alter interface: '%s'", str);
}

static int set_if_flag(struct ifchd_client *cl, short flag)
{
    int fd, ret = -1;
    struct ifreq ifrt;

    if (!is_permitted(cl->ifnam))
        goto out0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (set_if_flag) failed to open interface socket: %s",
                 cl->ifnam, strerror(errno));
        goto out0;
    }

    strnkcpy(ifrt.ifr_name, cl->ifnam, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFFLAGS, &ifrt) < 0) {
        log_line("%s: unknown interface: %s", cl->ifnam, strerror(errno));
        goto out1;
    }
    if (((ifrt.ifr_flags & flag ) ^ flag) & flag) {
        strnkcpy(ifrt.ifr_name, cl->ifnam, IFNAMSIZ);
        ifrt.ifr_flags |= flag;
        if (ioctl(fd, SIOCSIFFLAGS, &ifrt) < 0) {
            log_line("%s: failed to set interface flags: %s",
                     cl->ifnam, strerror(errno));
            goto out1;
        }
    } else
        ret = 0;

  out1:
    close(fd);
  out0:
    return ret;
}

#define NLMSG_TAIL(nmsg)                               \
    ((struct rtattr *) (((uint8_t*) (nmsg)) +          \
                        NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int add_rtattr(struct nlmsghdr *n, size_t max_length, int type,
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

static int get_ifindex(const char *name)
{
    struct ifreq ifr;
    int sk, err;

    if (!name)
        return -1;

    sk = socket(PF_INET, SOCK_DGRAM, 0);
    if (sk < 0)
        return -1;

    memset(&ifr, 0, sizeof ifr);
    strnkcpy(ifr.ifr_name, name, sizeof ifr.ifr_name);

    err = ioctl(sk, SIOCGIFINDEX, &ifr);
    close(sk);
    if (err < 0)
        return -1;

    return ifr.ifr_ifindex;
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
    return 32 - trailz(sn);
}

// str_bcast is optional.
void perform_ip_subnet_bcast(struct ifchd_client *cl, const char *str_ipaddr,
                             const char *str_subnet, const char *str_bcast)
{
    uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
        NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
        RTA_LENGTH(sizeof(struct in6_addr))];
    struct in_addr ipaddr, subnet, bcast;
    struct sockaddr_nl nl_addr;
    struct nlmsghdr *header;
    struct ifaddrmsg *ifaddrmsg;
    int nls, ifidx, r;
    uint8_t prefixlen;

    if (!str_ipaddr) {
        log_line("%s: (%s) interface ip address is NULL",
                 cl->ifnam, __func__);
        return;
    }
    if (!str_subnet) {
        log_line("%s: (%s) interface subnet address is NULL",
                 cl->ifnam, __func__);
        return;
    }

    if (!is_permitted(cl->ifnam))
        return;
    ifidx = get_ifindex(cl->ifnam);
    if (ifidx < 0) {
        log_line("%s: (%s) can't get interface index",
                 cl->ifnam, __func__);
        return;
    }

    if (inet_pton(AF_INET, str_ipaddr, &ipaddr) <= 0) {
        log_line("%s: (%s) bad interface ip address: '%s'",
                 cl->ifnam, __func__, str_ipaddr);
        return;
    }

    if (inet_pton(AF_INET, str_subnet, &subnet) <= 0) {
        log_line("%s: (%s) bad interface subnet address: '%s'",
                 cl->ifnam, __func__, str_subnet);
        return;
    }
    prefixlen = subnet4_to_prefixlen(subnet.s_addr);

    if (str_bcast) {
        if (inet_pton(AF_INET, str_bcast, &bcast) <= 0) {
            log_line("%s: (%s) bad interface broadcast address: '%s'",
                     cl->ifnam, __func__, str_bcast);
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
    ifaddrmsg->ifa_index = ifidx;

    if (add_rtattr(header, sizeof request, IFA_LOCAL,
                   &ipaddr, sizeof ipaddr) < 0) {
        log_line("%s: (%s) couldn't add IFA_LOCAL to nlmsg",
                 cl->ifnam, __func__);
        return;
    }
    if (add_rtattr(header, sizeof request, IFA_BROADCAST,
                   &bcast, sizeof bcast) < 0) {
        log_line("%s: (%s) couldn't add IFA_BROADCAST to nlmsg",
                 cl->ifnam, __func__);
        return;
    }

    nls = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (nls < 0) {
        log_line("%s: (%s) netlink socket open failed: %s",
                 cl->ifnam, __func__, strerror(errno));
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
                     cl->ifnam, __func__, strerror(errno));
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
    if (set_if_flag(cl, (IFF_UP | IFF_RUNNING)))
        return;
}


/* Sets IP address on an interface and brings it up. */
void perform_ip(struct ifchd_client *cl, const char *str, size_t len)
{
    int fd;
    struct in_addr ipaddr;
    struct ifreq ifrt;
    struct sockaddr_in sin;

    if (!str)
        return;
    if (!is_permitted(cl->ifnam))
        return;
    if (inet_pton(AF_INET, str, &ipaddr) <= 0)
        return;
    if (set_if_flag(cl, (IFF_UP | IFF_RUNNING)))
        return;

    strnkcpy(ifrt.ifr_name, cl->ifnam, IFNAMSIZ);
    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    sin.sin_addr = ipaddr;
    memcpy(&ifrt.ifr_addr, &sin, sizeof(struct sockaddr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_ip) failed to open interface socket: %s",
                 cl->ifnam, strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFADDR, &ifrt) < 0)
        log_line("%s: failed to configure IP: %s",
                 cl->ifnam, strerror(errno));
    else
        log_line("Interface IP set to: '%s'", str);
    close(fd);
}

/* Sets the subnet mask on an interface. */
void perform_subnet(struct ifchd_client *cl, const char *str, size_t len)
{
    int fd;
    struct in_addr subnet;
    struct ifreq ifrt;
    struct sockaddr_in sin;

    if (!str)
        return;
    if (!is_permitted(cl->ifnam))
        return;
    if (inet_pton(AF_INET, str, &subnet) <= 0)
        return;

    strnkcpy(ifrt.ifr_name, cl->ifnam, IFNAMSIZ);
    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    sin.sin_addr = subnet;
    memcpy(&ifrt.ifr_addr, &sin, sizeof(struct sockaddr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_ip) failed to open interface socket: %s",
                 cl->ifnam, strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFNETMASK, &ifrt) < 0) {
        sin.sin_addr.s_addr = 0xffffffff;
        if (ioctl(fd, SIOCSIFNETMASK, &ifrt) < 0)
            log_line("%s: failed to configure subnet: %s",
                     cl->ifnam, strerror(errno));
    } else
        log_line("Interface subnet set to: '%s'", str);
    close(fd);
}

void perform_router(struct ifchd_client *cl, const char *str, size_t len)
{
    struct rtentry rt;
    struct sockaddr_in *dest;
    struct sockaddr_in *gateway;
    struct sockaddr_in *mask;
    struct in_addr router;
    int fd;

    if (!str)
        return;
    if (!is_permitted(cl->ifnam))
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
    rt.rt_dev = cl->ifnam;
    rt.rt_metric = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_router) failed to open interface socket: %s",
                 cl->ifnam, strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCADDRT, &rt)) {
        if (errno != EEXIST)
            log_line("%s: failed to set route: %s",
                     cl->ifnam, strerror(errno));
    } else
        log_line("Gateway router set to: '%s'", str);
    close(fd);
}

void perform_mtu(struct ifchd_client *cl, const char *str, size_t len)
{
    int fd;
    unsigned int mtu;
    struct ifreq ifrt;

    if (!str)
        return;
    if (!is_permitted(cl->ifnam))
        return;

    mtu = strtol(str, NULL, 10);
    // Minimum MTU for physical IPv4 links is 576 octets.
    if (mtu < 576)
        return;
    ifrt.ifr_mtu = mtu;
    strnkcpy(ifrt.ifr_name, cl->ifnam, IFNAMSIZ);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_mtu) failed to open interface socket: %s",
                 cl->ifnam, strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFMTU, &ifrt) < 0)
        log_line("%s: failed to set MTU (%d): %s", cl->ifnam, mtu,
                 strerror(errno));
    else
        log_line("MTU set to: '%s'", str);
    close(fd);
}

void perform_broadcast(struct ifchd_client *cl, const char *str, size_t len)
{
    int fd;
    struct in_addr broadcast;
    struct ifreq ifrt;
    struct sockaddr_in sin;

    if (!str)
        return;
    if (!is_permitted(cl->ifnam))
        return;
    if (inet_pton(AF_INET, str, &broadcast) <= 0)
        return;

    strnkcpy(ifrt.ifr_name, cl->ifnam, IFNAMSIZ);
    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    sin.sin_addr = broadcast;
    memcpy(&ifrt.ifr_addr, &sin, sizeof(struct sockaddr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_broadcast) failed to open interface socket: %s", cl->ifnam, strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFBRDADDR, &ifrt) < 0)
        log_line("%s: failed to set broadcast: %s",
                 cl->ifnam, strerror(errno));
    else
        log_line("Broadcast address set to: '%s'", str);
    close(fd);
}
