// Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
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
#include "nk/log.h"
#include "nk/io.h"

#include "ifset.h"
#include "ifchd.h"
#include "ndhc.h"
#include "nl.h"

static uint32_t ifset_nl_seq = 1;

// Portable ctz() that gives a defined result for x == 0.
static int trailz(uint32_t x)
{
    static const int ctzt[32] = {
        0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
        31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10,
    };
    return x ? ctzt[((x & -x) * 0x077cb531u) >> 27] : 32;
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

static ssize_t rtnl_do_send(int fd, const uint8_t *sbuf, size_t slen,
                            const char *fnname)
{
    uint8_t response[NLMSG_ALIGN(sizeof(struct nlmsghdr)) + 64];
    struct sockaddr_nl nl_addr;

    memset(&nl_addr, 0, sizeof nl_addr);
    nl_addr.nl_family = AF_NETLINK;

    ssize_t r = safe_sendto(fd, (const char *)sbuf, slen, 0,
                            (struct sockaddr *)&nl_addr, sizeof nl_addr);
    if (r < 0 || (size_t)r != slen) {
        if (r < 0)
            log_line("%s: (%s) netlink sendto failed: %s\n",
                     client_config.interface, fnname, strerror(errno));
        else
            log_line("%s: (%s) netlink sendto short write: %zd < %zu\n",
                     client_config.interface, fnname, r, slen);
        return -1;
    }
    struct iovec iov = {
        .iov_base = response,
        .iov_len = sizeof response,
    };
    struct msghdr msg = {
        .msg_name = &nl_addr,
        .msg_namelen = sizeof nl_addr,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    r = safe_recvmsg(fd, &msg, 0);
    if (r < 0) {
        log_line("%s: (%s) netlink recvmsg failed: %s\n",
                 client_config.interface, fnname, strerror(errno));
        return -1;
    }
    if (msg.msg_flags & MSG_TRUNC) {
        log_line("%s: (%s) Buffer not long enough for message.\n",
                 client_config.interface, fnname);
        return -1;
    }
    if ((size_t)r < sizeof(struct nlmsghdr)) {
        log_line("%s: (%s) netlink recvmsg returned a headerless response\n",
                 client_config.interface, fnname);
        return -1;
    }
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)response;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        int nlerr = nlmsg_get_error(nlh);
        if (nlerr == 0)
            return 0;
        else {
            if (nlerr == 132) {
                log_line("%s: (%s) RF-kill is set (%d).  Cannot change interface.\n",
                         client_config.interface, fnname, nlerr);
                return -3;
            }
            log_line("%s: (%s) netlink sendto returned NLMSG_ERROR: %s\n",
                     client_config.interface, fnname, strerror(nlerr));
            return -1;
        }
    }
    if (nlh->nlmsg_type == NLMSG_DONE)
        return -2;
    log_line("%s: (%s) netlink sendto returned an error.\n",
             client_config.interface, __func__);
    return -1;
}

static ssize_t rtnl_if_flags_send(int fd, int type, unsigned ifi_flags)
{
    uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                    NLMSG_ALIGN(sizeof(struct ifinfomsg))];
    struct nlmsghdr *header;
    struct ifinfomsg *ifinfomsg;

    memset(&request, 0, sizeof request);
    header = (struct nlmsghdr *)request;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    header->nlmsg_type = type;
    header->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST;
    header->nlmsg_seq = ifset_nl_seq++;

    ifinfomsg = NLMSG_DATA(header);
    ifinfomsg->ifi_flags = ifi_flags;
    ifinfomsg->ifi_index = client_config.ifindex;
    ifinfomsg->ifi_change = 0xffffffff;

    return rtnl_do_send(fd, request, header->nlmsg_len, __func__);
}

static ssize_t rtnl_addr_broadcast_send(int fd, int type, int ifa_flags,
                                        int ifa_scope, uint32_t *ipaddr,
                                        uint32_t *bcast, uint8_t prefixlen)
{
    uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                    NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
                    2 * RTA_LENGTH(sizeof(struct in6_addr))];
    struct nlmsghdr *header;
    struct ifaddrmsg *ifaddrmsg;

    if (!ipaddr && !bcast) {
        log_line("%s: (%s) no ipaddr or bcast!\n",
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
    // Linux is inconsistent about the type of ifindex.
    ifaddrmsg->ifa_index = (uint32_t)client_config.ifindex;

    if (ipaddr) {
        if (nl_add_rtattr(header, sizeof request, IFA_LOCAL,
                          ipaddr, sizeof *ipaddr) < 0) {
            log_line("%s: (%s) couldn't add IFA_LOCAL to nlmsg\n",
                     client_config.interface, __func__);
            return -1;
        }
    }
    if (bcast) {
        if (nl_add_rtattr(header, sizeof request, IFA_BROADCAST,
                          bcast, sizeof *bcast) < 0) {
            log_line("%s: (%s) couldn't add IFA_BROADCAST to nlmsg\n",
                     client_config.interface, __func__);
            return -1;
        }
    }

    return rtnl_do_send(fd, request, header->nlmsg_len, __func__);
}

static ssize_t rtnl_set_default_gw_v4(int fd, uint32_t gw4, int metric)
{
    uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                    NLMSG_ALIGN(sizeof(struct rtmsg)) +
                    3 * RTA_LENGTH(sizeof(struct in6_addr)) +
                    RTA_LENGTH(sizeof(int))];
    struct nlmsghdr *header;
    struct rtmsg *rtmsg;

    memset(&request, 0, sizeof request);
    header = (struct nlmsghdr *)request;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    header->nlmsg_type = RTM_NEWROUTE;
    header->nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK
                        | NLM_F_REQUEST;
    header->nlmsg_seq = ifset_nl_seq++;

    rtmsg = NLMSG_DATA(header);
    rtmsg->rtm_family = AF_INET;
    rtmsg->rtm_protocol = RTPROT_DHCP;
    rtmsg->rtm_scope = RT_SCOPE_UNIVERSE;
    rtmsg->rtm_type = RTN_UNICAST;

    uint32_t dstaddr4 = 0;
    if (nl_add_rtattr(header, sizeof request, RTA_DST,
                      &dstaddr4, sizeof dstaddr4) < 0) {
        log_line("%s: (%s) couldn't add RTA_DST to nlmsg\n",
                 client_config.interface, __func__);
        return -1;
    }
    if (nl_add_rtattr(header, sizeof request, RTA_OIF,
                      &client_config.ifindex,
                      sizeof client_config.ifindex) < 0) {
        log_line("%s: (%s) couldn't add RTA_OIF to nlmsg\n",
                 client_config.interface, __func__);
        return -1;
    }
    if (nl_add_rtattr(header, sizeof request, RTA_GATEWAY,
                      &gw4, sizeof gw4) < 0) {
        log_line("%s: (%s) couldn't add RTA_GATEWAY to nlmsg\n",
                 client_config.interface, __func__);
        return -1;
    }
    if (metric > 0) {
        if (nl_add_rtattr(header, sizeof request, RTA_PRIORITY,
                          &metric, sizeof metric) < 0) {
            log_line("%s: (%s) couldn't add RTA_PRIORITY to nlmsg\n",
                     client_config.interface, __func__);
            return -1;
        }
    }

    return rtnl_do_send(fd, request, header->nlmsg_len, __func__);
}

struct link_flag_data {
    int fd;
    uint32_t flags;
    bool got_flags;
};

static void link_flags_get_do(const struct nlmsghdr *nlh, void *data)
{
    struct ifinfomsg *ifm = NLMSG_DATA(nlh);
    struct link_flag_data *ifd = data;

    switch(nlh->nlmsg_type) {
        case RTM_NEWLINK:
            if (ifm->ifi_index != client_config.ifindex)
                break;
            ifd->flags = ifm->ifi_flags;
            ifd->got_flags = true;
            break;
        case RTM_DELLINK:
            log_line("%s: got RTM_DELLINK\n", __func__);
            break;
        default:
            log_line("%s: got %u\n", __func__, nlh->nlmsg_type);
            break;
    }
}

static int link_flags_get(int fd, uint32_t *flags)
{
    char nlbuf[8192];
    struct link_flag_data ipx = { .fd = fd, .flags = 0, .got_flags = false };
    ssize_t ret;
    uint32_t seq = ifset_nl_seq++;
    if (nl_sendgetlink(fd, seq, client_config.ifindex) < 0)
        return -1;

    do {
        ret = nl_recv_buf(fd, nlbuf, sizeof nlbuf);
        if (ret < 0)
            return -2;
        if (nl_foreach_nlmsg(nlbuf, (size_t)ret, seq, 0, link_flags_get_do, &ipx) < 0)
            return -3;
    } while (ret > 0);
    if (ipx.got_flags) {
        *flags = ipx.flags;
        return 0;
    }
    return -4;
}

int perform_carrier(void)
{
    int ret = -1;
    uint32_t flags;
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        log_line("%s: (%s) netlink socket open failed: %s\n",
                 client_config.interface, __func__, strerror(errno));
        goto fail;
    }

    if (link_flags_get(fd, &flags) < 0)
        goto fail_fd;
    if ((flags & IFF_RUNNING) && (flags & IFF_UP))
        ret = 0;
fail_fd:
    close(fd);
fail:
    return ret;
}

// Return  0 if flags were successfully changed.
// Return  1 if flags were already set.
// Return -1 on error.
// Return -2 if NL response had no status notification.
// Return -3 if RFKILL is set and flags cannot be changed.
static int link_set_flags(int fd, uint32_t flags)
{
    uint32_t oldflags;

    int r = link_flags_get(fd, &oldflags);
    if (r < 0) {
        log_line("%s: (%s) failed to get old link flags: %u\n",
                 client_config.interface, __func__, r);
        return -1;
    }
    if ((oldflags & flags) == flags)
        return 1;
    return (int)rtnl_if_flags_send(fd, RTM_SETLINK, flags | oldflags);
}

#if 0
static int link_unset_flags(int fd, uint32_t flags)
{
    uint32_t oldflags;

    int r = link_flags_get(fd, &oldflags);
    if (r < 0) {
        log_line("%s: (%s) failed to get old link flags: %u\n",
                 client_config.interface, __func__, r);
        return -1;
    }
    if ((oldflags & flags) == 0)
        return 1;
    return (int)rtnl_if_flags_send(fd, RTM_SETLINK, oldflags & ~flags);
}
#endif

static void ipbcpfx_clear_others_do(const struct nlmsghdr *nlh, void *data)
{
    struct rtattr *tb[IFA_MAX] = {0};
    struct ifaddrmsg *ifm = NLMSG_DATA(nlh);
    struct ipbcpfx *ipx = data;
    int r;

    nl_rtattr_parse(nlh, sizeof *ifm, rtattr_assign, tb);
    switch(nlh->nlmsg_type) {
        case RTM_NEWADDR:
            if (ifm->ifa_index != (unsigned)client_config.ifindex)
                return;
            if (ifm->ifa_family != AF_INET)
                return;
            if (!(ifm->ifa_flags & IFA_F_PERMANENT))
                goto erase;
            if (ifm->ifa_scope != RT_SCOPE_UNIVERSE)
                goto erase;
            if (ifm->ifa_prefixlen != ipx->prefixlen)
                goto erase;
            if (!tb[IFA_ADDRESS])
                goto erase;
            if (memcmp(RTA_DATA(tb[IFA_ADDRESS]), &ipx->ipaddr,
                       sizeof ipx->ipaddr))
                goto erase;
            if (!tb[IFA_BROADCAST])
                goto erase;
            if (memcmp(RTA_DATA(tb[IFA_BROADCAST]), &ipx->bcast,
                       sizeof ipx->bcast))
                goto erase;
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
                                 tb[IFA_ADDRESS] ? RTA_DATA(tb[IFA_ADDRESS]) : (uint32_t *)0,
                                 tb[IFA_BROADCAST] ? RTA_DATA(tb[IFA_BROADCAST]) : (uint32_t *)0,
                                 ifm->ifa_prefixlen);
    if (r < 0 && r != -2) {
        log_line("%s: (%s) Failed to delete IP and broadcast addresses.\n",
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
    uint32_t seq = ifset_nl_seq++;
    if (nl_sendgetaddr4(fd, seq, (uint32_t)client_config.ifindex) < 0)
        return -1;

    do {
        ret = nl_recv_buf(fd, nlbuf, sizeof nlbuf);
        if (ret < 0)
            return -2;
        if (nl_foreach_nlmsg(nlbuf, (size_t)ret, seq, 0,
                             ipbcpfx_clear_others_do, &ipx) < 0)
            return -3;
    } while (ret > 0);
    return ipx.already_ok ? 1 : 0;
}

static ssize_t rtnl_if_mtu_set(int fd, unsigned int mtu)
{
    uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                    NLMSG_ALIGN(sizeof(struct ifinfomsg)) +
                    RTA_LENGTH(sizeof(unsigned int))];
    struct nlmsghdr *header;
    struct ifinfomsg *ifinfomsg;
    uint32_t oldflags;

    int r = link_flags_get(fd, &oldflags);
    if (r < 0) {
        log_line("%s: (%s) failed to get old link flags: %u\n",
                 client_config.interface, __func__, r);
        return -1;
    }

    memset(&request, 0, sizeof request);
    header = (struct nlmsghdr *)request;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    header->nlmsg_type = RTM_SETLINK;
    header->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST;
    header->nlmsg_seq = ifset_nl_seq++;

    ifinfomsg = NLMSG_DATA(header);
    ifinfomsg->ifi_flags = oldflags;
    ifinfomsg->ifi_index = client_config.ifindex;
    ifinfomsg->ifi_change = 0xffffffff;

    if (nl_add_rtattr(header, sizeof request, IFLA_MTU,
                      &mtu, sizeof mtu) < 0) {
        log_line("%s: (%s) couldn't add IFLA_MTU to nlmsg\n",
                 client_config.interface, __func__);
        return -1;
    }

    return rtnl_do_send(fd, request, header->nlmsg_len, __func__);
}

int perform_ifup(void)
{
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        log_line("%s: (%s) netlink socket open failed: %s\n",
                 client_config.interface, __func__, strerror(errno));
        return fd;
    }

    int r = link_set_flags(fd, IFF_UP);
    if (r < 0) {
        if (r != -3)
            log_line("%s: (%s) Failed to set link to be up.\n",
                     client_config.interface, __func__);
        else
            log_line("%s: (%s) rfkill is set; waiting until it is unset\n",
                     client_config.interface, __func__);
    }
    close(fd);
    return r;
}

// str_bcast is optional.
int perform_ip_subnet_bcast(const char *str_ipaddr,
                            const char *str_subnet,
                            const char *str_bcast)
{
    struct in_addr ipaddr, subnet, bcast;
    int fd, r, ret = -99;
    uint8_t prefixlen;

    if (inet_pton(AF_INET, str_ipaddr, &ipaddr) <= 0) {
        log_line("%s: (%s) bad interface ip address: '%s'\n",
                 client_config.interface, __func__, str_ipaddr);
        goto fail;
    }

    if (inet_pton(AF_INET, str_subnet, &subnet) <= 0) {
        log_line("%s: (%s) bad interface subnet address: '%s'\n",
                 client_config.interface, __func__, str_subnet);
        goto fail;
    }
    prefixlen = subnet4_to_prefixlen(subnet.s_addr);

    if (str_bcast) {
        if (inet_pton(AF_INET, str_bcast, &bcast) <= 0) {
            log_line("%s: (%s) bad interface broadcast address: '%s'\n",
                     client_config.interface, __func__, str_bcast);
            goto fail;
        }
    } else {
        // Generate the standard broadcast address if unspecified.
        bcast.s_addr = ipaddr.s_addr | htonl(0xfffffffflu >> prefixlen);
    }

    fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        log_line("%s: (%s) netlink socket open failed: %s\n",
                 client_config.interface, __func__, strerror(errno));
        goto fail;
    }

    r = ipbcpfx_clear_others(fd, ipaddr.s_addr, bcast.s_addr, prefixlen);
    if (r < 0 && r > -3) {
        if (r == -1)
            log_line("%s: (%s) error requesting link ip address list\n",
                     client_config.interface, __func__);
        else if (r == -2)
            log_line("%s: (%s) error receiving link ip address list\n",
                     client_config.interface, __func__);
        goto fail_fd;
    }

    if (r < 1) {
        r = rtnl_addr_broadcast_send(fd, RTM_NEWADDR, IFA_F_PERMANENT,
                                     RT_SCOPE_UNIVERSE, &ipaddr.s_addr, &bcast.s_addr,
                                     prefixlen);
        if (r < 0)
            goto fail_fd;

        log_line("%s: Interface IP set to: '%s'\n", client_config.interface,
                 str_ipaddr);
        log_line("%s: Interface subnet set to: '%s'\n", client_config.interface,
                 str_subnet);
        if (str_bcast)
            log_line("%s: Broadcast address set to: '%s'\n",
                     client_config.interface, str_bcast);
    } else
        log_line("%s: Interface IP, subnet, and broadcast were already OK.\n",
                 client_config.interface);

    if (link_set_flags(fd, IFF_UP | IFF_RUNNING) < 0) {
        ret = -1;
        log_line("%s: (%s) Failed to set link to be up and running.\n",
                 client_config.interface, __func__);
        goto fail_fd;
    }
    ret = 0;
fail_fd:
    close(fd);
fail:
    return ret;
}


int perform_router(const char *str_router, size_t len)
{
    int ret = -99;
    if (len < 7)
        goto fail;
    struct in_addr router;
    if (inet_pton(AF_INET, str_router, &router) <= 0) {
        log_line("%s: (%s) bad router ip address: '%s'\n",
                 client_config.interface, __func__, str_router);
        goto fail;
    }

    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        log_line("%s: (%s) netlink socket open failed: %s\n",
                 client_config.interface, __func__, strerror(errno));
        goto fail;
    }

    if (rtnl_set_default_gw_v4(fd, router.s_addr, client_config.metric) < 0) {
        log_line("%s: (%s) failed to set route: %s\n",
                 client_config.interface, __func__, strerror(errno));
        goto fail_fd;
    }
    log_line("%s: Gateway router set to: '%s'\n", client_config.interface,
             str_router);
    ret = 0;
fail_fd:
    close(fd);
fail:
    return ret;
}

int perform_mtu(const char *str, size_t len)
{
    unsigned int mtu;
    int fd, ret = -99;
    if (len < 2)
        goto fail;

    char *estr;
    long tmtu = strtol(str, &estr, 10);
    if (estr == str) {
        log_line("%s: (%s) provided mtu arg isn't a valid number\n",
                 client_config.interface, __func__);
        goto fail;
    }
    if ((tmtu == LONG_MAX || tmtu == LONG_MIN) && errno == ERANGE) {
        log_line("%s: (%s) provided mtu arg would overflow a long\n",
                 client_config.interface, __func__);
        goto fail;
    }
    if (tmtu > INT_MAX) {
        log_line("%s: (%s) provided mtu arg would overflow int\n",
                 client_config.interface, __func__);
        goto fail;
    }
    // 68 bytes for IPv4.  1280 bytes for IPv6.
    if (tmtu < 68) {
        log_line("%s: (%s) provided mtu arg (%ld) less than minimum MTU (68)\n",
                 client_config.interface, __func__, tmtu);
        goto fail;
    }
    mtu = (unsigned int)tmtu;

    fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        log_line("%s: (%s) netlink socket open failed: %s\n",
                 client_config.interface, __func__, strerror(errno));
        goto fail;
    }

    if (rtnl_if_mtu_set(fd, mtu) < 0) {
        log_line("%s: (%s) failed to set MTU [%d]\n",
                 client_config.interface, __func__, mtu);
        goto fail_fd;
    }
    log_line("%s: MTU set to: '%s'\n", client_config.interface, str);
    ret = 0;
fail_fd:
    close(fd);
fail:
    return ret;
}

