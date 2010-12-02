/*
 * Derived from busybox's udhcpc variant, which in turn was...
 * Mostly stolen from: dhcpcd - DHCP client daemon
 * by Yoichi Hariguchi <yoichi@fore.com>
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <errno.h>
#include "arpping.h"
#include "dhcpd.h"
#include "log.h"
#include "strl.h"
#include "io.h"

static unsigned long long curms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

/* Returns fd of the arp socket, or -1 on failure. */
int arpping(uint32_t test_nip, const uint8_t *safe_mac, uint32_t from_ip,
            uint8_t *from_mac, const char *interface)
{
    int arpfd;
    int opt = 1;
    struct sockaddr addr;   /* for interface name */
    struct arpMsg arp;

    arpfd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
    if (arpfd == -1) {
        log_warning("arpping: failed to create socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(arpfd, SOL_SOCKET, SO_BROADCAST,
                   &opt, sizeof opt) == -1) {
        log_warning("arpping: failed to set broadcast: %s", strerror(errno));
        close(arpfd);
        return -1;
    }

    /* send arp request */
    memset(&arp, 0, sizeof arp);
    memset(arp.h_dest, 0xff, 6);                    /* MAC DA */
    memcpy(arp.h_source, from_mac, 6);              /* MAC SA */
    arp.h_proto = htons(ETH_P_ARP);                 /* protocol type (Ethernet) */
    arp.htype = htons(ARPHRD_ETHER);                /* hardware type */
    arp.ptype = htons(ETH_P_IP);                    /* protocol type (ARP message) */
    arp.hlen = 6;                                   /* hardware address length */
    arp.plen = 4;                                   /* protocol address length */
    arp.operation = htons(ARPOP_REQUEST);           /* ARP op code */
    memcpy(arp.sHaddr, from_mac, 6);                /* source hardware address */
    memcpy(arp.sInaddr, &from_ip, sizeof from_ip);  /* source IP address */
    /* tHaddr is zero-filled */                     /* target hardware address */
    memcpy(arp.tInaddr, &test_nip, sizeof test_nip);/* target IP address */

    memset(&addr, 0, sizeof addr);
    strlcpy(addr.sa_data, interface, sizeof addr.sa_data);
    if (safe_sendto(arpfd, (const char *)&arp, sizeof arp,
                    0, &addr, sizeof addr) < 0) {
        log_error("arpping: sendto failed: %s", strerror(errno));
        close(arpfd);
        return -1;
    }
    return arpfd;
}
