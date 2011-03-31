/*
 * Copyright 2011 Nicholas J. Kain <njkain@gmail.com>
 * Copyright 2006, 2007 Stefan Rompf <sux@loplof.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation
 *
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

#include "netlink.h"
#include "ifchange.h"
#include "arp.h"
#include "log.h"

#define NLMSG_RECVSIZE 8192

static unsigned int nl_seq;

/* internal callback handling */
static void (*nlcb_function)(struct nlmsghdr *msg, void **args);
static void *nlcb_args[3];
static __u32 nlcb_pid;
static unsigned int nlcb_seq;
static char nlcb_run;

int nl_open(struct client_state_t *cs)
{
    struct sockaddr_nl nlsock = {
        .nl_family = AF_NETLINK,
        .nl_pad = 0,
        .nl_pid = getpid(),
        .nl_groups = RTMGRP_LINK
    };

    nlcb_pid = nlsock.nl_pid;

    assert(cs->nlFd == -1);

    cs->nlFd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (cs->nlFd == -1)
        return -1;

    if (bind(cs->nlFd, (const struct sockaddr *)&nlsock, sizeof(nlsock)))
        goto err_close;

    if (fcntl(cs->nlFd, F_SETFD, FD_CLOEXEC))
        goto err_close;

    return 0;

  err_close:
    nl_close(cs);
    return -1;
}

void nl_close(struct client_state_t *cs)
{
    close(cs->nlFd);
    cs->nlFd = -1;
}

void nl_queryifstatus(int ifidx, struct client_state_t *cs)
{
    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg ifinfo;
    } req;

    req.hdr.nlmsg_len = sizeof req;
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.hdr.nlmsg_seq = ++nl_seq;
    req.hdr.nlmsg_pid = nlcb_pid;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = ifidx; /* Doesn't work... */
    req.ifinfo.ifi_flags = IFF_UP;
    req.ifinfo.ifi_change = 0xffffffff;

    send(cs->nlFd, &req, sizeof req, 0);
}

static void takedown_if(struct client_state_t *cs)
{
    log_line("nl: taking down interface");
    // Same as packet.c: line 258
    ifchange(NULL, IFCHANGE_DECONFIG);
    cs->dhcpState = DS_INIT_SELECTING;
    cs->timeout = 0;
    cs->requestedIP = 0;
    cs->packetNum = 0;
    change_listen_mode(cs, LM_RAW);
}

// Decode netlink messages and process them
static void nl_handlemsg(struct nlmsghdr *msg, unsigned int len,
                         struct client_state_t *cs)
{
    if (len < sizeof(*msg)) return;

    while(NLMSG_OK(msg,len)) {
        if (nlcb_run &&
            nlcb_pid == msg->nlmsg_pid &&
            nlcb_seq == msg->nlmsg_seq) {
            nlcb_function(msg, nlcb_args);

            if (msg->nlmsg_type == NLMSG_DONE ||
                msg->nlmsg_type == NLMSG_ERROR) nlcb_run = 0;
        }

        if (NLMSG_PAYLOAD(msg, msg->nlmsg_len) >= sizeof(struct ifinfomsg)) {
            struct ifinfomsg *ifinfo = NLMSG_DATA(msg);

            switch(msg->nlmsg_type) {
                case RTM_NEWLINK:
                    if (ifinfo->ifi_index != client_config.ifindex)
                        break;
                    if (ifinfo->ifi_flags & IFF_UP) {
                        if (ifinfo->ifi_flags & IFF_RUNNING) {
                            if (cs->ifsPrevState != IFS_UP) {
                                cs->ifsPrevState = IFS_UP;
                                /*
                                 * If we have a lease, then check to see
                                 * if our gateway is still valid (via ARP).
                                 * If it fails, state -> INIT.
                                 *
                                 * If we don't have a lease, state -> INIT.
                                 */
                                if (cs->dhcpState == DS_BOUND) {
                                    arp_gw_check(cs);
                                } else if (cs->dhcpState != DS_INIT_SELECTING)
                                    takedown_if(cs);
                            }
                        } else {
                            if (cs->ifsPrevState != IFS_DOWN) {
                                cs->ifsPrevState = IFS_DOWN;
                                takedown_if(cs);
                            }
                        }
                    } else {
                        if (cs->ifsPrevState != IFS_SHUT) {
                            cs->ifsPrevState = IFS_SHUT;
                            log_line("Interface shut down; exiting.");
                            exit(EXIT_SUCCESS);
                        }
                    }
                    break;
                case RTM_DELLINK:
                    if (ifinfo->ifi_index != client_config.ifindex)
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
        }
        msg = NLMSG_NEXT(msg,len);
    }
}

void handle_nl_message(struct client_state_t *cs)
{
    char c[NLMSG_RECVSIZE];
    struct nlmsghdr *msg = (struct nlmsghdr *)c;
    int n;

    assert(cs->nlFd != -1);
    n = recv(cs->nlFd, c, NLMSG_RECVSIZE, 0);
    nl_handlemsg(msg, n, cs);
}

// Wait for and synchronously process netlink replies until a callback completes
static void nl_sync_dump(struct client_state_t *cs)
{
    char c[NLMSG_RECVSIZE];
    struct nlmsghdr *msg = (struct nlmsghdr *)c;
    int n;

    nlcb_seq = nl_seq;
    for(nlcb_run = 1; nlcb_run;) {
        n = recv(cs->nlFd, c, NLMSG_RECVSIZE, 0);
        assert(n >= 0);
        nl_handlemsg(msg, n, cs);
    }
}

// Callback function for getting interface mac address and index.
static void copy_ifdata(struct nlmsghdr *msg, void **args)
{
    struct ifinfomsg *ifinfo = NLMSG_DATA(msg);
    struct rtattr *rta = IFLA_RTA(ifinfo);
    int len = NLMSG_PAYLOAD(msg, sizeof(*ifinfo));
    int found = 0;

    if (msg->nlmsg_type != RTM_NEWLINK)
        return;
    if (client_config.ifindex)
        return;

    for(; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch(rta->rta_type) {
            case IFLA_IFNAME:
                if (!strncmp(client_config.interface,
                             (char *)RTA_DATA(rta), RTA_PAYLOAD(rta))) {
                    client_config.ifindex = ifinfo->ifi_index;
                    log_line("adapter index %d", ifinfo->ifi_index);
                    found |= 1;
                }
                break;
            case IFLA_ADDRESS:
                if (found != 1)
                    break;
                /* We can only handle ethernet like devices with 6 octet MAC */
                if (RTA_PAYLOAD(rta) == 6) {
                    memcpy(client_config.arp, RTA_DATA(rta), 6);
                    log_line("adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                             client_config.arp[0], client_config.arp[1],
                             client_config.arp[2], client_config.arp[3],
                             client_config.arp[4], client_config.arp[5]);
                    found |= 2;
                }
                break;
        }
    }
    if (found == 3)
        nlcb_args[0] = (void *)1;
}

// Gets interface mac address and index (synchronous).
int nl_getifdata(const char *ifname, struct client_state_t *cs)
{
    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg ifinfo;
    } req;

    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.hdr.nlmsg_seq = ++nl_seq;
    req.hdr.nlmsg_pid = nlcb_pid;
    req.ifinfo.ifi_family = AF_UNSPEC;

    if (send(cs->nlFd, &req, sizeof(req), 0) != sizeof(req)) return -1;

    nlcb_function = copy_ifdata;
    nlcb_args[0] = NULL;

    nl_sync_dump(cs);

    return nlcb_args[0]?0:-1;
}
