/*
 * socket.c -- DHCP server client/server socket creation
 *
 * Copyright (C) 2004-2010 Nicholas J. Kain <njkain at gmail dot com>
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <linux/filter.h>
#include "log.h"
#include "strl.h"
#include "dhcpd.h" /* For SERVER_PORT and CLIENT_PORT */

static int set_sock_nonblock(int fd)
{
    int ret = 0, flags;
    flags = fcntl(fd, F_GETFL);
    ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return ret;
}

/* Given an interface name in @interface, return its index number,
 * IPv4 address, and MAC in @ifindex, @addr (optional), and @mac.*/
int read_interface(char *interface, int *ifindex, uint32_t *addr, uint8_t *mac)
{
    int fd, ret = -1;
    struct ifreq ifr;
    struct sockaddr_in *our_ip;

    memset(&ifr, 0, sizeof(struct ifreq));
    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        log_error("socket failed!: %s", strerror(errno));
        goto out;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strlcpy(ifr.ifr_name, interface, IFNAMSIZ);

    if (addr) {
        if (ioctl(fd, SIOCGIFADDR, &ifr)) {
            log_error("Couldn't get IP for %s.", strerror(errno));
            goto out_fd;
        }
        our_ip = (struct sockaddr_in *) &ifr.ifr_addr;
        *addr = our_ip->sin_addr.s_addr;
        log_line("%s (our ip) = %s", ifr.ifr_name,
                 inet_ntoa(our_ip->sin_addr));
    }

    if (ioctl(fd, SIOCGIFINDEX, &ifr)) {
        log_error("SIOCGIFINDEX failed!: %s", strerror(errno));
        goto out_fd;
    }

    log_line("adapter index %d", ifr.ifr_ifindex);
    *ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        log_error("Couldn't get MAC for %s", strerror(errno));
        goto out_fd;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    log_line("adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ret = 0;
  out_fd:
    close(fd);
  out:
    return ret;
}

/* Returns fd of new listen socket bound to @ip:@port on interface @inf
 * on success, or -1 on failure. */
int listen_socket(unsigned int ip, int port, char *inf)
{
    struct ifreq interface;
    int fd;
    struct sockaddr_in addr;
    int opt = 1;

    log_line("Opening listen socket on 0x%08x:%d %s", ip, port, inf);
    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_error("listen_socket: socket failed: %s", strerror(errno));
        goto out;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1)
        goto out_fd;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) == -1)
        goto out_fd;

    /* Restrict operations to the physical device @inf */
    strlcpy(interface.ifr_ifrn.ifrn_name, inf, IFNAMSIZ);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   &interface, sizeof interface) < 0)
        goto out_fd;

    set_sock_nonblock(fd);

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ip;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1)
        goto out_fd;

    return fd;
  out_fd:
    close(fd);
  out:
    return -1;
}

int raw_socket(int ifindex)
{
    int fd;
    struct sockaddr_ll sock;

    /*
     * Comment:
     *
     *   I've selected not to see LL header, so BPF doesn't see it, too.
     *   The filter may also pass non-IP and non-ARP packets, but we do
     *   a more complete check when receiving the message in userspace.
     *
     * and filter shamelessly stolen from:
     *
     *   http://www.flamewarmaster.de/software/dhcpclient/
     *
     * There are a few other interesting ideas on that page (look under
     * "Motivation").  Use of netlink events is most interesting.  Think
     * of various network servers listening for events and reconfiguring.
     * That would obsolete sending HUP signals and/or make use of restarts.
     *
     *  Copyright: 2006, 2007 Stefan Rompf <sux@loplof.de>.
     *  License: GPL v2.
     */
#define SERVER_AND_CLIENT_PORTS  ((67 << 16) + 68)
    static const struct sock_filter filter_instr[] = {
        /* check for udp */
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 9),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 2, 0),     /* L5, L1, is UDP? */
        /* ugly check for arp on ethernet-like and IPv4 */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 2),                      /* L1: */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x08000604, 3, 4),      /* L3, L4 */
        /* skip IP header */
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0),                     /* L5: */
        /* check udp source and destination ports */
        BPF_STMT(BPF_LD|BPF_W|BPF_IND, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SERVER_AND_CLIENT_PORTS, 0, 1),/* L3, L4 */
        /* returns */
        BPF_STMT(BPF_RET|BPF_K, 0x0fffffff ),                   /* L3: pass */
        BPF_STMT(BPF_RET|BPF_K, 0),                             /* L4: reject */
    };
    static const struct sock_fprog filter_prog = {
        .len = sizeof(filter_instr) / sizeof(filter_instr[0]),
        /* casting const away: */
        .filter = (struct sock_filter *) filter_instr,
    };

    memset(&sock, 0, sizeof sock);
    log_line("Opening raw socket on ifindex %d", ifindex);
    if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        log_error("socket call failed: %s", strerror(errno));
        return -1;
    }

    if (SERVER_PORT == 67 && CLIENT_PORT == 68) {
        /* Use only if standard ports are in use */
        /* Ignoring error (kernel may lack support for this) */
        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog,
                       sizeof filter_prog) >= 0)
            log_line("Attached filter to raw socket fd %d", fd);
    }

    set_sock_nonblock(fd);

    sock.sll_family = AF_PACKET;
    sock.sll_protocol = htons(ETH_P_IP);
    sock.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sock, sizeof(sock)) < 0) {
        log_error("bind call failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}
