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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>
#include <libmnl/libmnl.h>
#include <errno.h>

#include "netlink.h"
#include "ifchange.h"
#include "arp.h"
#include "log.h"

enum {
    IFS_NONE = 0,
    IFS_UP,
    IFS_DOWN,
    IFS_SHUT,
    IFS_REMOVED
};

static struct mnl_socket *mls;

static void nl_close(struct client_state_t *cs)
{
    mnl_socket_close(mls);
    cs->nlFd = -1;
}

int nl_open(struct client_state_t *cs)
{
    assert(cs->nlFd == -1);
    if ((mls = mnl_socket_open(NETLINK_ROUTE)) == (struct mnl_socket *)-1)
        return -1;
    cs->nlFd = mnl_socket_get_fd(mls);
    if (fcntl(cs->nlFd, F_SETFD, FD_CLOEXEC))
        goto err_close;
    if (mnl_socket_bind(mls, RTMGRP_LINK, 0))
        goto err_close;
    return 0;
  err_close:
    nl_close(cs);
    return -1;
}

static void takedown_if(struct client_state_t *cs)
{
    log_line("nl: taking down interface");
    // XXX: Same as packet.c - merge somehow?
    ifchange(NULL, IFCHANGE_DECONFIG);
    cs->dhcpState = DS_SELECTING;
    cs->timeout = 0;
    cs->clientAddr = 0;
    cs->packetNum = 0;
    set_listen_raw(cs);
}

static int data_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
        return MNL_CB_OK;
    switch (type) {
        case IFLA_IFNAME:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                log_warning("nl: IFLA_IFNAME failed validation.");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_ADDRESS:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                log_warning("nl: IFLA_ADDRESS failed validation.");
                return MNL_CB_ERROR;
            }
            break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static void get_if_index_and_mac(const struct nlmsghdr *nlh,
                                 struct ifinfomsg *ifm,
                                 const struct nlattr **tb)
{
    mnl_attr_parse(nlh, sizeof(*ifm), data_attr_cb, tb);
    if (!tb[IFLA_IFNAME])
        return;
    if (!strcmp(client_config.interface, mnl_attr_get_str(tb[IFLA_IFNAME]))) {
        client_config.ifindex = ifm->ifi_index;
        if (!tb[IFLA_ADDRESS])
            suicide("FATAL: adapter %s lacks a hardware address");
        int maclen = mnl_attr_get_len(tb[IFLA_ADDRESS]) - 4;
        if (maclen != 6)
            suicide("FATAL: adapter hardware address length should be 6, but is %u",
                    maclen);

        const unsigned char *mac =
            (unsigned char *)mnl_attr_get_str(tb[IFLA_ADDRESS]);
        log_line("%s hardware address %x:%x:%x:%x:%x:%x",
                 client_config.interface,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        memcpy(client_config.arp, mac, 6);
    }
}

// XXX: Rather than exit, go into RELEASE state until a new hardware event
// forces wakeup.
static int data_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nlattr *tb[IFLA_MAX+1] = {0};
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
    struct client_state_t *cs = data;

    switch(nlh->nlmsg_type) {
        case RTM_NEWLINK:
            if (!client_config.ifindex)
                get_if_index_and_mac(nlh, ifm, (const struct nlattr **)tb);
            if (ifm->ifi_index != client_config.ifindex)
                break;
            if (ifm->ifi_flags & IFF_UP) {
                if (ifm->ifi_flags & IFF_RUNNING) {
                    if (cs->ifsPrevState != IFS_UP) {
                        cs->ifsPrevState = IFS_UP;
                        // If we have a lease, then check to see
                        // if our gateway is still valid (via ARP).
                        // If it fails, state -> SELECTING.
                        if (cs->dhcpState == DS_BOUND) {
                            if (arp_gw_check(cs) == -1)
                                log_warning("nl: arp_gw_check could not make arp socket, assuming lease is still OK");
                            else
                                log_line("nl: interface back, revalidating lease");
                        // If we don't have a lease, state -> SELECTING.
                        } else if (cs->dhcpState != DS_SELECTING) {
                            log_line("nl: interface back, querying for new lease");
                            takedown_if(cs);
                        }
                    }
                } else {
                    if (cs->ifsPrevState != IFS_DOWN) {
                        // Interface was marked up but not running.
                        // Get a new lease from scratch.
                        cs->ifsPrevState = IFS_DOWN;
                        takedown_if(cs);
                    }
                }
            } else {
                // No hardware carrier.
                if (cs->ifsPrevState != IFS_SHUT) {
                    cs->ifsPrevState = IFS_SHUT;
                    log_line("Interface shut down; exiting.");
                    exit(EXIT_SUCCESS);
                }
            }
            break;
        case RTM_DELLINK:
            if (ifm->ifi_index != client_config.ifindex)
                break;
            if (cs->ifsPrevState != IFS_REMOVED) {
                cs->ifsPrevState = IFS_REMOVED;
                log_line("Interface removed; exiting.");
                exit(EXIT_SUCCESS);
            }
            break;
        default:
            break;
    }
    return MNL_CB_OK;
}

void handle_nl_message(struct client_state_t *cs)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int ret;
    assert(cs->nlFd != -1);
    do {
        ret = mnl_socket_recvfrom(mls, buf, sizeof buf);
        ret = mnl_cb_run(buf, ret, 0, 0, data_cb, cs);
    } while (ret > 0);
    if (ret == -1)
        log_line("nl callback function returned error: %s", strerror(errno));
}

int nl_getifdata(const char *ifname, struct client_state_t *cs)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifinfo;
    unsigned int seq;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    nlh->nlmsg_seq = seq = time(NULL);

    ifinfo = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifinfo->ifi_family = AF_UNSPEC;

    if (mnl_socket_sendto(mls, nlh, nlh->nlmsg_len) < 0)
        return -1;

    handle_nl_message(cs);
    return 0;
}

