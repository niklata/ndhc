/* arp.c - arp ping checking
 * Time-stamp: <2011-06-16 21:37:52 njk>
 *
 * Copyright 2010-2011 Nicholas J. Kain <njkain@gmail.com>
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <errno.h>
#include "arp.h"
#include "packet.h"
#include "sys.h"
#include "ifchange.h"
#include "leasefile.h"
#include "log.h"
#include "io.h"

#define ARP_MSG_SIZE 0x2a
#define ARP_RETRY_COUNT 3

static struct arpMsg arpreply;
static int arpreply_offset;
static struct dhcpmsg arp_dhcp_packet;
static int arp_packet_num;

static int arp_open_fd(struct client_state_t *cs)
{
    if (cs->arpFd != -1)
        return 0;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd == -1) {
        log_error("arp: failed to create socket: %s", strerror(errno));
        goto out;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) == -1) {
        log_error("arp: failed to set broadcast: %s", strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("arp: failed to set non-blocking: %s", strerror(errno));
        goto out_fd;
    }
    struct sockaddr_ll saddr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ARP),
        .sll_ifindex = client_config.ifindex,
    };
    if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll)) < 0) {
        log_error("arp: bind failed: %s", strerror(errno));
        goto out_fd;
    }

    cs->arpFd = fd;
    epoll_add(cs, fd);
    return 0;
out_fd:
    close(fd);
out:
    return -1;
}

static void arp_close_fd(struct client_state_t *cs)
{
    if (cs->arpFd == -1)
        return;
    epoll_del(cs, cs->arpFd);
    close(cs->arpFd);
    cs->arpFd = -1;
}

// Returns 0 on success, -1 on failure.
static int arpping(struct client_state_t *cs, uint32_t test_ip)
{
    if (arp_open_fd(cs) == -1)
        return -1;

    struct arpMsg arp = {
        .h_proto = htons(ETH_P_ARP),
        .htype = htons(ARPHRD_ETHER),
        .ptype = htons(ETH_P_IP),
        .hlen = 6,
        .plen = 4,
        .operation = htons(ARPOP_REQUEST),
    };
    memset(arp.h_dest, 0xff, 6);
    memcpy(arp.h_source, client_config.arp, 6);
    memcpy(arp.smac, client_config.arp, 6);
    memcpy(arp.dip4, &test_ip, sizeof test_ip);

    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(addr.sll_addr, client_config.arp, 6);

    if (safe_sendto(cs->arpFd, (const char *)&arp, sizeof arp,
                    0, (struct sockaddr *)&addr, sizeof addr) < 0) {
        log_error("arp: sendto failed: %s", strerror(errno));
        arp_close_fd(cs);
        return -1;
    }
    arp_packet_num = 0;
    return 0;
}

static void arpreply_clear()
{
    memset(&arpreply, 0, sizeof arpreply);
    arpreply_offset = 0;
}

int arp_check(struct client_state_t *cs, struct dhcpmsg *packet)
{
    if (arpping(cs, arp_dhcp_packet.yiaddr) == -1)
        return -1;
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_ARP_CHECK;
    cs->timeout = 2000;
    memcpy(&arp_dhcp_packet, packet, sizeof (struct dhcpmsg));
    arpreply_clear();
    return 0;
}

int arp_gw_check(struct client_state_t *cs)
{
    if (arpping(cs, cs->routerAddr) == -1)
        return -1;
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_ARP_GW_CHECK;
    cs->oldTimeout = cs->timeout;
    cs->timeout = 2000;
    memset(&arp_dhcp_packet, 0, sizeof (struct dhcpmsg));
    arpreply_clear();
    return 0;
}

int arp_get_gw_hwaddr(struct client_state_t *cs)
{
    if (cs->dhcpState != DS_BOUND)
        log_error("arp_get_gw_hwaddr: called when state != DS_BOUND");
    if (arpping(cs, cs->routerAddr) == -1)
        return -1;
    log_line("arp: Searching for gw address");
    memset(&arp_dhcp_packet, 0, sizeof (struct dhcpmsg));
    arpreply_clear();
    return 0;
}

static void arp_failed(struct client_state_t *cs)
{
    log_line("arp: Offered address is in use -- declining");
    arp_close_fd(cs);
    send_decline(cs->xid, cs->serverAddr, arp_dhcp_packet.yiaddr);

    if (cs->arpPrevState != DS_REQUESTING)
        ifchange(NULL, IFCHANGE_DECONFIG);
    cs->dhcpState = DS_INIT_SELECTING;
    cs->requestedIP = 0;
    cs->timeout = 0;
    cs->packetNum = 0;
    change_listen_mode(cs, LM_RAW);
}

void arp_gw_failed(struct client_state_t *cs)
{
    log_line("arp: Gateway appears to have changed, getting new lease");
    arp_close_fd(cs);

    // Same as packet.c: line 258
    ifchange(NULL, IFCHANGE_DECONFIG);
    cs->dhcpState = DS_INIT_SELECTING;
    cs->oldTimeout = 0;
    cs->timeout = 0;
    cs->requestedIP = 0;
    cs->packetNum = 0;
    change_listen_mode(cs, LM_RAW);
}

void arp_success(struct client_state_t *cs)
{
    struct in_addr temp_addr;

    arp_close_fd(cs);

    cs->t1 = cs->lease >> 1;
    cs->t2 = (cs->lease * 0x7) >> 3; // T2 = lease * 0.875
    cs->timeout = cs->t1 * 1000;
    cs->leaseStartTime = curms();

    temp_addr.s_addr = arp_dhcp_packet.yiaddr;
    log_line("arp: Lease of %s obtained, lease time %ld",
             inet_ntoa(temp_addr), cs->lease);
    cs->requestedIP = arp_dhcp_packet.yiaddr;
    cs->dhcpState = DS_BOUND;
    ifchange(&arp_dhcp_packet,
             ((cs->arpPrevState == DS_RENEWING ||
               cs->arpPrevState == DS_REBINDING)
              ? IFCHANGE_RENEW : IFCHANGE_BOUND));
    change_listen_mode(cs, LM_NONE);
    write_leasefile(temp_addr);
    if (client_config.quit_after_lease)
        exit(EXIT_SUCCESS);
    if (!client_config.foreground)
        background(cs);
}

static void arp_gw_success(struct client_state_t *cs)
{
    log_line("arp: Gateway seems unchanged");
    arp_close_fd(cs);

    cs->timeout = cs->oldTimeout;
    cs->dhcpState = cs->arpPrevState;
}

// Note that this function will see all ARP traffic on the interface.
// Therefore the validation shouldn't be noisy, and should silently
// reject non-malformed ARP packets that are irrelevant.
static int arp_validate(struct arpMsg *am)
{
    if (!am)
        return 0;
    if (am->h_proto != htons(ETH_P_ARP)) {
        log_warning("arp: IP header does not indicate ARP protocol");
        return 0;
    }
    if (am->htype != htons(ARPHRD_ETHER)) {
        log_warning("arp: ARP hardware type field invalid");
        return 0;
    }
    if (am->ptype != htons(ETH_P_IP)) {
        log_warning("arp: ARP protocol type field invalid");
        return 0;
    }
    if (am->hlen != 6) {
        log_warning("arp: ARP hardware address length invalid");
        return 0;
    }
    if (am->plen != 4) {
        log_warning("arp: ARP protocol address length invalid");
        return 0;
    }
    if (am->operation != htons(ARPOP_REPLY)) {
        /* log_warning("arp: ARP operation type is not 'reply': %x", */
        /*             ntohs(am->operation)); */
        return 0;
    }
    if (memcmp(am->h_dest, client_config.arp, 6)) {
        /* log_warning("arp: Ethernet destination does not equal our MAC"); */
        return 0;
    }
    if (memcmp(am->dmac, client_config.arp, 6)) {
        /* log_warning("arp: ARP destination does not equal our MAC"); */
        return 0;
    }
    return 1;
}

void handle_arp_response(struct client_state_t *cs)
{
    if (arpreply_offset < sizeof arpreply) {
        int r = safe_read(cs->arpFd, (char *)&arpreply + arpreply_offset,
                          sizeof arpreply - arpreply_offset);
        if (r < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return;
            log_error("arp: ARP response read failed: %s", strerror(errno));
            switch (cs->dhcpState) {
                case DS_ARP_CHECK: arp_failed(cs); break;
                case DS_ARP_GW_CHECK: arp_gw_failed(cs); break;
                case DS_BOUND: break; // keep trying for finding gw mac
                default: break;
            }
        } else
            arpreply_offset += r;
    }

    if (arpreply_offset < ARP_MSG_SIZE) {
        log_warning("arp: Received short ARP message -- ignoring");
        return;
    }

    if (!arp_validate(&arpreply))
        return;

    ++arp_packet_num;
    switch (cs->dhcpState) {
    case DS_ARP_CHECK:
        if (!memcmp(arpreply.sip4, &arp_dhcp_packet.yiaddr, 4)) {
            // Check to see if we replied to our own ARP query.
            if (!memcmp(client_config.arp, arpreply.smac, 6))
                arp_success(cs);
            else
                arp_failed(cs);
            return;
        } else {
            log_line("arp: Ping noise while waiting for check timeout");
            arpreply_clear();
        }
        break;
    case DS_ARP_GW_CHECK:
        if (!memcmp(arpreply.sip4, &cs->routerAddr, 4)) {
            // Success only if the router/gw MAC matches stored value
            if (!memcmp(cs->routerArp, arpreply.smac, 6))
                arp_gw_success(cs);
            else
                arp_gw_failed(cs);
            return;
        } else {
            log_line("arp: Still waiting for gateway to reply to arp ping");
            arpreply_clear();
        }
        break;
    case DS_BOUND:
        if (!memcmp(arpreply.sip4, &cs->routerAddr, 4)) {
            memcpy(cs->routerArp, arpreply.smac, 6);
            arp_close_fd(cs);

            log_line("arp: Gateway hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                     cs->routerArp[0], cs->routerArp[1],
                     cs->routerArp[2], cs->routerArp[3],
                     cs->routerArp[4], cs->routerArp[5]);
            return;
        } else {
            log_line("arp: Still looking for gateway hardware address");
            arpreply_clear();
        }
        break;
    default:
        arp_close_fd(cs);
        log_error("handle_arp_response: called in invalid state 0x%02x",
                  cs->dhcpState);
        return;
    }
    if (arp_packet_num >= ARP_RETRY_COUNT) {
        switch (cs->dhcpState) {
            case DS_BOUND:
                if (arpping(cs, cs->routerAddr) == -1)
                    log_warning("arp: Failed to retransmit arp packet for finding gw mac addr");
                break;
            default:
                log_line("arp: Not yet bothering with arp retransmit for non-DS_BOUND state");
                break;
        }
    }
}
