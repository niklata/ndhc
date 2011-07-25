/* linux.c - ifchd Linux-specific functions
 *
 * Copyright (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
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
#include <pwd.h>
#include <grp.h>

#include <errno.h>

#include "ifchd-defines.h"
#include "log.h"
#include "strlist.h"
#include "ifch_proto.h"
#include "strl.h"

/* Symbolic name of the interface associated with a connection. */
static char ifnam[SOCK_QUEUE][IFNAMSIZ];
static strlist_t *okif;

/* Clear a specified ifnam structure. */
void clear_if_data(int idx)
{
    memset(ifnam[idx], '\0', IFNAMSIZ);
}

/* Clear all ifnam structures. */
void initialize_if_data(void)
{
    int i;
    for (i = 0; i < SOCK_QUEUE; i++) {
        clear_if_data(i);
    }
}

/* Adds to the list of interface names ifchd clients are allowed to change. */
void add_permitted_if(char *s)
{
    if (!s)
        return;
    add_to_strlist(&okif, s);
}

/* Checks if changes are permitted to a given interface.  1 == allowed */
static int is_permitted(char *name)
{
    strlist_t *p;

    /* If empty, permit all. */
    if (!okif)
        return 1;

    if (!name || strlen(name) == 0)
        return 0;
    p = okif;
    while (p) {
        if (strcmp(name, p->str) == 0)
            return 1;
        p = p->next;
    }
    log_line("attempt to modify interface %s denied\n", name);
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
        log_line("getsockopt returned an error: %s\n", strerror(errno));
    return ret;
}

void perform_interface(int idx, char *str)
{
    if (!str)
        return;

    /* Update interface name. */
    memset(ifnam[idx], '\0', IFNAMSIZ);
    strlcpy(ifnam[idx], str, IFNAMSIZ);
}

static int set_if_flag(int idx, short flag)
{
    int fd, ret = -1;
    struct ifreq ifrt;

    if (!is_permitted(ifnam[idx]))
        goto out0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (set_if_flag) failed to open interface socket: %s\n",
		 ifnam[idx], strerror(errno));
        goto out0;
    }

    strlcpy(ifrt.ifr_name, ifnam[idx], IFNAMSIZ);
    if (ioctl(fd, SIOCGIFFLAGS, &ifrt) < 0) {
        log_line("%s: unknown interface: %s\n", ifnam[idx], strerror(errno));
        goto out1;
    }
    if (((ifrt.ifr_flags & flag ) ^ flag) & flag) {
        strlcpy(ifrt.ifr_name, ifnam[idx], IFNAMSIZ);
        ifrt.ifr_flags |= flag;
        if (ioctl(fd, SIOCSIFFLAGS, &ifrt) < 0) {
            log_line("%s: failed to set interface flags: %s\n",
                     ifnam[idx], strerror(errno));
            goto out1;
        }
    } else
        ret = 0;

  out1:
    close(fd);
  out0:
    return ret;
}

/* Sets IP address on an interface and brings it up. */
void perform_ip(int idx, char *str)
{
    int fd;
    struct in_addr ipaddr;
    struct ifreq ifrt;
    struct sockaddr_in sin;

    if (!str)
        return;
    if (!is_permitted(ifnam[idx]))
        return;
    if (!inet_pton(AF_INET, str, &ipaddr))
        return;
    if (set_if_flag(idx, (IFF_UP | IFF_RUNNING)))
        return;

    strlcpy(ifrt.ifr_name, ifnam[idx], IFNAMSIZ);
    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    sin.sin_addr = ipaddr;
    memcpy(&ifrt.ifr_addr, &sin, sizeof(struct sockaddr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_ip) failed to open interface socket: %s\n",
		 ifnam[idx], strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFADDR, &ifrt) < 0)
        log_line("%s: failed to configure IP: %s\n",
		 ifnam[idx], strerror(errno));
    close(fd);
}

/* Sets the subnet mask on an interface. */
void perform_subnet(int idx, char *str)
{
    int fd;
    struct in_addr subnet;
    struct ifreq ifrt;
    struct sockaddr_in sin;

    if (!str)
        return;
    if (!is_permitted(ifnam[idx]))
        return;
    if (!inet_pton(AF_INET, str, &subnet))
        return;

    strlcpy(ifrt.ifr_name, ifnam[idx], IFNAMSIZ);
    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    sin.sin_addr = subnet;
    memcpy(&ifrt.ifr_addr, &sin, sizeof(struct sockaddr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_ip) failed to open interface socket: %s\n",
		 ifnam[idx], strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFNETMASK, &ifrt) < 0) {
        sin.sin_addr.s_addr = 0xffffffff;
        if (ioctl(fd, SIOCSIFNETMASK, &ifrt) < 0)
            log_line("%s: failed to configure subnet: %s\n",
		     ifnam[idx], strerror(errno));
    }
    close(fd);
}

void perform_router(int idx, char *str)
{
    struct rtentry rt;
    struct sockaddr_in *dest;
    struct sockaddr_in *gateway;
    struct sockaddr_in *mask;
    struct in_addr router;
    int fd;

    if (!str)
        return;
    if (!is_permitted(ifnam[idx]))
        return;
    if (!inet_pton(AF_INET, str, &router))
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
    rt.rt_dev = ifnam[idx];
    rt.rt_metric = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_router) failed to open interface socket: %s\n",
		 ifnam[idx], strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCADDRT, &rt)) {
        if (errno != EEXIST)
            log_line("%s: failed to set route: %s\n",
                     ifnam[idx], strerror(errno));
    }
    close(fd);
}

void perform_mtu(int idx, char *str)
{
    int fd;
    unsigned int mtu;
    struct ifreq ifrt;

    if (!str)
        return;
    if (!is_permitted(ifnam[idx]))
        return;

    mtu = strtol(str, NULL, 10);
    ifrt.ifr_mtu = mtu;
    strlcpy(ifrt.ifr_name, ifnam[idx], IFNAMSIZ);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_mtu) failed to open interface socket: %s\n",
		 ifnam[idx], strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFMTU, &ifrt) < 0)
        log_line("%s: failed to set MTU (%d): %s\n", ifnam[idx], mtu,
		 strerror(errno));
    close(fd);
}

void perform_broadcast(int idx, char *str)
{
    int fd;
    struct in_addr broadcast;
    struct ifreq ifrt;
    struct sockaddr_in sin;

    if (!str)
        return;
    if (!is_permitted(ifnam[idx]))
        return;
    if (!inet_pton(AF_INET, str, &broadcast))
        return;

    strlcpy(ifrt.ifr_name, ifnam[idx], IFNAMSIZ);
    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    sin.sin_addr = broadcast;
    memcpy(&ifrt.ifr_addr, &sin, sizeof(struct sockaddr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_line("%s: (perform_broadcast) failed to open interface socket: %s\n", ifnam[idx], strerror(errno));
        return;
    }
    if (ioctl(fd, SIOCSIFBRDADDR, &ifrt) < 0)
        log_line("%s: failed to set broadcast: %s\n",
		 ifnam[idx], strerror(errno));
    close(fd);
}
