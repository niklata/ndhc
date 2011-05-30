/* packet.h - send and react to DHCP message packets
 * Time-stamp: <2011-03-30 23:57:02 nk>
 *
 * (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
 * (c) 2001 Russ Dill <Russ.Dill@asu.edu>
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

#ifndef PACKET_H_
#define PACKET_H_

#include <netinet/udp.h>
#include <netinet/ip.h>

#include "config.h"

struct dhcpMessage {
    uint8_t op; // Message type: 1 = BOOTREQUEST for clients.
    uint8_t htype; // ARP HW address type: always '1' for 10MB ethernet.
    uint8_t hlen; // Hardware address length: always '6' for 10MB ethernet.
    uint8_t hops; // Client sets to zero.
    uint32_t xid;  // Transaction ID: random number identifying session
    uint16_t secs; // Filled by client: seconds since client began address
                   // aquisition or renewal process.
    uint16_t flags; // DHCP flags
    uint32_t ciaddr; // Client IP: only filled in if client is inBOUND, RENEW,
                     // or REBINDING and can reply to ARP requests
    uint32_t yiaddr; // 'your' (client) IP address
    uint32_t siaddr; // IP address of next server to use in bootstrap; returned
                     // in DHCPOFFER or DHCPACK by server
    uint32_t giaddr; // relay agent IP: used when booting via relay agent
    uint8_t chaddr[16]; // Client MAC address
    uint8_t sname[64]; // Server host name (optional); null-terminated string
    uint8_t file[128]; // boot file name, null-terminated string
    uint32_t cookie;
    uint8_t options[308]; /* 312 - cookie */
};

struct ip_udp_dhcp_packet {
    struct iphdr ip;
    struct udphdr udp;
    struct dhcpMessage data;
};

struct udp_dhcp_packet {
    struct udphdr udp;
    struct dhcpMessage data;
};

enum {
    IP_UPD_DHCP_SIZE = sizeof(struct ip_udp_dhcp_packet),
    UPD_DHCP_SIZE    = sizeof(struct udp_dhcp_packet),
    DHCP_SIZE        = sizeof(struct dhcpMessage),
};

int get_packet(struct dhcpMessage *packet, int fd);
uint16_t checksum(void *addr, int count);
int raw_packet(struct dhcpMessage *payload, uint32_t source_ip,
               int source_port, uint32_t dest_ip, int dest_port,
               uint8_t *dest_arp, int ifindex);
int kernel_packet(struct dhcpMessage *payload, uint32_t source_ip,
                  int source_port, uint32_t dest_ip, int dest_port);
void change_listen_mode(struct client_state_t *cs, int new_mode);
void handle_packet(struct client_state_t *cs);
#endif
