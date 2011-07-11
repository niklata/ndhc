/* netlink.c - netlink physical link notification handling and info retrieval
 *
 * (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

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

#include "netlink.h"
#include "log.h"
#include "nl.h"
#include "state.h"

static char nlbuf[8192];
int nlportid;

static int nlrtattr_assign(struct nlattr *attr, int type, void *data)
{
    struct nlattr **tb = data;
    if (type >= IFLA_MAX)
        return 0;
    tb[type] = attr;
    return 0;
}

static void get_if_index_and_mac(const struct nlmsghdr *nlh,
                                 struct ifinfomsg *ifm)
{
    struct nlattr *tb[IFLA_MAX] = {0};
    nl_attr_parse(nlh, sizeof *ifm, nlrtattr_assign, tb);
    if (!tb[IFLA_IFNAME])
        return;
    if (!strcmp(client_config.interface, nlattr_get_data(tb[IFLA_IFNAME]))) {
        client_config.ifindex = ifm->ifi_index;
        if (!tb[IFLA_ADDRESS])
            suicide("FATAL: Adapter %s lacks a hardware address.");
        int maclen = nlattr_get_len(tb[IFLA_ADDRESS]) - 4;
        if (maclen != 6)
            suicide("FATAL: Adapter hardware address length should be 6, but is %u.",
                    maclen);

        const unsigned char *mac =
            (unsigned char *)nlattr_get_data(tb[IFLA_ADDRESS]);
        log_line("%s hardware address %x:%x:%x:%x:%x:%x",
                 client_config.interface,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        memcpy(client_config.arp, mac, 6);
    }
}

static int nl_process_msgs(const struct nlmsghdr *nlh, void *data)
{
    struct ifinfomsg *ifm = nlmsg_get_data(nlh);
    struct client_state_t *cs = data;

    switch(nlh->nlmsg_type) {
        case RTM_NEWLINK:
            if (!client_config.ifindex)
                get_if_index_and_mac(nlh, ifm);
            if (ifm->ifi_index != client_config.ifindex)
                break;
            // IFF_UP corresponds to ifconfig down or ifconfig up.
            if (ifm->ifi_flags & IFF_UP) {
                // IFF_RUNNING is the hardware carrier.
                if (ifm->ifi_flags & IFF_RUNNING) {
                    if (cs->ifsPrevState != IFS_UP) {
                        cs->ifsPrevState = IFS_UP;
                        ifup_action(cs);
                    }
                } else if (cs->ifsPrevState != IFS_DOWN) {
                    // Interface configured, but no hardware carrier.
                    cs->ifsPrevState = IFS_DOWN;
                    ifnocarrier_action(cs);
                }
            } else if (cs->ifsPrevState != IFS_SHUT) {
                // User shut down the interface.
                cs->ifsPrevState = IFS_SHUT;
                ifdown_action(cs);
            }
            break;
        case RTM_DELLINK:
            if (ifm->ifi_index != client_config.ifindex)
                break;
            if (cs->ifsPrevState != IFS_REMOVED) {
                cs->ifsPrevState = IFS_REMOVED;
                log_line("Interface removed.  Exiting.");
                exit(EXIT_SUCCESS);
            }
            break;
        default:
            break;
    }
    return 1;
}

void handle_nl_message(struct client_state_t *cs)
{
    ssize_t ret;
    assert(cs->nlFd != -1);
    do {
        ret = nl_recv_buf(cs->nlFd, nlbuf, sizeof nlbuf);
        if (ret == -1)
            break;
        if (nl_foreach_nlmsg(nlbuf, ret, nlportid, nl_process_msgs, cs) == -1)
            break;
    } while (ret > 0);
}

int nl_getifdata(const char *ifname, struct client_state_t *cs)
{
    char buf[8192];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifinfo;
    size_t msgsize = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof *ifinfo);

    memset(buf, 0, msgsize);
    nlh->nlmsg_len = msgsize;
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    nlh->nlmsg_seq = time(NULL);
    ifinfo = (struct ifinfomsg *)((char *)buf + NLMSG_HDRLEN);
    ifinfo->ifi_family = AF_UNSPEC;

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };
    if (sendto(cs->nlFd, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&addr,
               sizeof addr) == -1)
        return -1;

    for (int pr = 0; !pr;) {
        pr = poll(&((struct pollfd){.fd=cs->nlFd,.events=POLLIN}), 1, -1);
        if (pr == 1)
            handle_nl_message(cs);
        else if (pr == -1)
            suicide("nl: poll failed");
    }
    return 0;
}

