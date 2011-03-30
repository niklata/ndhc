/*
 * Derived from busybox's udhcpc variant, which in turn was...
 * Mostly stolen from: dhcpcd - DHCP client daemon
 * by Yoichi Hariguchi <yoichi@fore.com>
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include "arp.h"
#include "dhcpmsg.h"
#include "packet.h"
#include "socket.h"
#include "sys.h"
#include "ifchange.h"
#include "log.h"
#include "strl.h"
#include "io.h"

static struct arpMsg arpreply;
static int arpreply_offset;
static struct dhcpMessage arp_dhcp_packet;

/* Returns fd of the arp socket, or -1 on failure. */
static int arpping(uint32_t test_nip, const uint8_t *safe_mac,
                   uint32_t from_ip, uint8_t *from_mac, const char *interface)
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

    set_sock_nonblock(arpfd);

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

void arp_check(struct client_state_t *cs, struct dhcpMessage *packet)
{
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_ARP_CHECK;
    memcpy(&arp_dhcp_packet, packet, sizeof (struct dhcpMessage));
    cs->arpFd = arpping(arp_dhcp_packet.yiaddr, NULL, 0,
                       client_config.arp, client_config.interface);
    epoll_add(cs, cs->arpFd);
    cs->timeout = 2000;
    memset(&arpreply, 0, sizeof arpreply);
    arpreply_offset = 0;
}

static void arp_failed(struct client_state_t *cs)
{
    log_line("Offered address is in use: declining.");
    epoll_del(cs, cs->arpFd);
    cs->arpFd = -1;
    send_decline(cs->xid, cs->serverAddr, arp_dhcp_packet.yiaddr);

    if (cs->arpPrevState != DS_REQUESTING)
        ifchange(NULL, IFCHANGE_DECONFIG);
    cs->dhcpState = DS_INIT_SELECTING;
    cs->requestedIP = 0;
    cs->timeout = 0;
    cs->packetNum = 0;
    change_listen_mode(cs, LM_RAW);
}

void arp_success(struct client_state_t *cs)
{
    struct in_addr temp_addr;

    epoll_del(cs, cs->arpFd);
    cs->arpFd = -1;

    /* enter bound state */
    cs->t1 = cs->lease >> 1;
    /* little fixed point for n * .875 */
    cs->t2 = (cs->lease * 0x7) >> 3;
    cs->timeout = cs->t1 * 1000;
    cs->leaseStartTime = curms();

    temp_addr.s_addr = arp_dhcp_packet.yiaddr;
    log_line("Lease of %s obtained, lease time %ld.",
             inet_ntoa(temp_addr), cs->lease);
    cs->requestedIP = arp_dhcp_packet.yiaddr;
    ifchange(&arp_dhcp_packet,
             ((cs->arpPrevState == DS_RENEWING ||
               cs->arpPrevState == DS_REBINDING)
              ? IFCHANGE_RENEW : IFCHANGE_BOUND));

    cs->dhcpState = DS_BOUND;
    change_listen_mode(cs, LM_NONE);
    if (client_config.quit_after_lease)
        exit(EXIT_SUCCESS);
    if (!client_config.foreground)
        background(cs);
}

typedef uint32_t aliased_uint32_t __attribute__((__may_alias__));
void handle_arp_response(struct client_state_t *cs)
{
    if (arpreply_offset < sizeof arpreply) {
        int r = safe_read(cs->arpFd, (char *)&arpreply + arpreply_offset,
                          sizeof arpreply - arpreply_offset);
        if (r < 0) {
            arp_failed(cs);
            return;
        } else
            arpreply_offset += r;
    }

    //log3("sHaddr %02x:%02x:%02x:%02x:%02x:%02x",
    //arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2],
    //arp.sHaddr[3], arp.sHaddr[4], arp.sHaddr[5]);

    if (arpreply_offset >= ARP_MSG_SIZE) {
        if (arpreply.operation == htons(ARPOP_REPLY)
            /* don't check: Linux returns invalid tHaddr (fixed in 2.6.24?) */
            /* && memcmp(arpreply.tHaddr, from_mac, 6) == 0 */
            && *(aliased_uint32_t*)arpreply.sInaddr == arp_dhcp_packet.yiaddr)
        {
            /* if ARP source MAC matches safe_mac
             * (which is client's MAC), then it's not a conflict
             * (client simply already has this IP and replies to ARPs!)
             */
            /* if (memcmp(safe_mac, arpreply.sHaddr, 6) == 0) */
            /*     arp_success(); */
            arp_failed(cs);
        } else {
            memset(&arpreply, 0, sizeof arpreply);
            arpreply_offset = 0;
        }
    }
}
