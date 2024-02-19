// Copyright 2011-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include "nk/log.h"

#include "netlink.h"
#include "nl.h"
#include "state.h"

// Returns true if the current interface state is UP.
bool nl_event_carrier_wentup(int state)
{
    switch (state) {
    case IFS_UP:
        log_line("%s: Carrier up.\n", client_config.interface);
        return true;
    case IFS_DOWN:
        // Interface configured, but no hardware carrier.
        log_line("%s: Carrier down.\n", client_config.interface);
        return false;
    case IFS_SHUT:
        // User shut down the interface.
        log_line("%s: Interface shut down.\n", client_config.interface);
        return false;
    case IFS_REMOVED:
        log_line("Interface removed.  Exiting.\n");
        exit(EXIT_SUCCESS);
    default: return false;
    }
}

static int nl_process_msgs_return;
static void nl_process_msgs(const struct nlmsghdr *nlh, void *data)
{
    (void)data;
    struct ifinfomsg *ifm = NLMSG_DATA(nlh);

    if (ifm->ifi_index != client_config.ifindex)
        return;

    if (nlh->nlmsg_type == RTM_NEWLINK) {
        // IFF_UP corresponds to ifconfig down or ifconfig up.
        // IFF_RUNNING is the hardware carrier.
        if (ifm->ifi_flags & IFF_UP) {
            if (ifm->ifi_flags & IFF_RUNNING)
                nl_process_msgs_return = IFS_UP;
            else
                nl_process_msgs_return = IFS_DOWN;
        } else {
            nl_process_msgs_return = IFS_SHUT;
        }
    } else if (nlh->nlmsg_type == RTM_DELLINK)
        nl_process_msgs_return = IFS_REMOVED;
}

int nl_event_get(struct client_state_t *cs)
{
    char nlbuf[8192];
    ssize_t ret;
    assert(cs->nlFd != -1);
    nl_process_msgs_return = IFS_NONE;
    do {
        ret = nl_recv_buf(cs->nlFd, nlbuf, sizeof nlbuf);
        if (ret < 0)
            break;
        if (nl_foreach_nlmsg(nlbuf, (size_t)ret, 0, cs->nlPortId, nl_process_msgs, 0) < 0)
            break;
    } while (ret > 0);
    return nl_process_msgs_return;
}

static int get_if_index_and_mac(const struct nlmsghdr *nlh,
                                struct ifinfomsg *ifm)
{
    struct rtattr *tb[IFLA_MAX] = {0};
    nl_rtattr_parse(nlh, sizeof *ifm, rtattr_assign, tb);
    if (tb[IFLA_IFNAME] && !strncmp(client_config.interface,
                                    RTA_DATA(tb[IFLA_IFNAME]),
                                    sizeof client_config.interface)) {
        client_config.ifindex = ifm->ifi_index;
        if (!tb[IFLA_ADDRESS])
            suicide("FATAL: Adapter %s lacks a hardware address.\n", client_config.interface);
        int maclen = tb[IFLA_ADDRESS]->rta_len - 4;
        if (maclen != 6)
            suicide("FATAL: Adapter hardware address length should be 6, but is %u.\n",
                    maclen);

        const unsigned char *mac = RTA_DATA(tb[IFLA_ADDRESS]);
        log_line("%s hardware address %x:%x:%x:%x:%x:%x\n",
                 client_config.interface,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        memcpy(client_config.arp, mac, 6);
        return 1;
    }
    return 0;
}

static void do_handle_getifdata(const struct nlmsghdr *nlh, void *data)
{
    int *got_ifdata = (int *)data;
    struct ifinfomsg *ifm = NLMSG_DATA(nlh);

    switch(nlh->nlmsg_type) {
        case RTM_NEWLINK:
            *got_ifdata |= get_if_index_and_mac(nlh, ifm);
            break;
        default:
            break;
    }
}

static int handle_getifdata(int fd, uint32_t seq)
{
    char nlbuf[8192];
    ssize_t ret;
    int got_ifdata = 0;
    do {
        ret = nl_recv_buf(fd, nlbuf, sizeof nlbuf);
        if (ret < 0)
            return -1;
        if (nl_foreach_nlmsg(nlbuf, (size_t)ret, seq, 0,
                             do_handle_getifdata, &got_ifdata) < 0)
            return -1;
    } while (ret > 0);
    return got_ifdata ? 0 : -1;
}

int nl_getifdata(void)
{
    int ret = -1;
    int fd = socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        log_line("%s: (%s) netlink socket open failed: %s\n",
                 client_config.interface, __func__, strerror(errno));
        goto fail;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        log_line("%s: (%s) clock_gettime failed\n",
                 client_config.interface, __func__);
        goto fail_fd;
    }
    uint32_t seq = ts.tv_nsec;
    if (nl_sendgetlinks(fd, seq)) {
        log_line("%s: (%s) nl_sendgetlinks failed\n",
                 client_config.interface, __func__);
        goto fail_fd;
    }

    for (int pr = 0; !pr;) {
        pr = poll(&((struct pollfd){.fd=fd,.events=POLLIN}), 1, -1);
        if (pr == 1)
            ret = handle_getifdata(fd, seq);
        else if (pr < 0 && errno != EINTR)
            goto fail_fd;
    }
  fail_fd:
    close(fd);
  fail:
    return ret;
}

