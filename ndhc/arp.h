/* arp.h - functions to call the interface change daemon
 * Time-stamp: <2011-07-05 12:54:21 njk>
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
#ifndef ARP_H_
#define ARP_H_

#include <stdint.h>
#include <net/if_arp.h>

#include "config.h"
#include "dhcp.h"

struct arpMsg {
    // Ethernet header
    uint8_t  h_dest[6];     // 00 destination ether addr
    uint8_t  h_source[6];   // 06 source ether addr
    uint16_t h_proto;       // 0c packet type ID field

    // ARP packet
    uint16_t htype;         // 0e hardware type (must be ARPHRD_ETHER)
    uint16_t ptype;         // 10 protocol type (must be ETH_P_IP)
    uint8_t  hlen;          // 12 hardware address length (must be 6)
    uint8_t  plen;          // 13 protocol address length (must be 4)
    uint16_t operation;     // 14 ARP opcode
    uint8_t  smac[6];       // 16 sender's hardware address
    uint8_t  sip4[4];       // 1c sender's IP address
    uint8_t  dmac[6];       // 20 target's hardware address
    uint8_t  dip4[4];       // 26 target's IP address
    uint8_t  pad[18];       // 2a pad for min. ethernet payload (60 bytes)
};

extern int arp_relentless_def;

int arp_close_fd(struct client_state_t *cs);
int arp_check(struct client_state_t *cs, struct dhcpmsg *packet);
int arp_gw_check(struct client_state_t *cs);
void arp_success(struct client_state_t *cs);
void arp_gw_failed(struct client_state_t *cs);
void arp_retransmit(struct client_state_t *cs);
void handle_arp_response(struct client_state_t *cs);

#endif /* ARP_H_ */
