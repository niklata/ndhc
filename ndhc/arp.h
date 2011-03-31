/* arp.h - functions to call the interface change daemon
 * Time-stamp: <2011-03-31 02:28:59 nk>
 *
 * Copyright 2010-2011 Nicholas J. Kain <njkain@gmail.com>
 *
 * Originally derived from busybox's udhcpc variant, which in turn was...
 * Mostly stolen from: dhcpcd - DHCP client daemon
 * by Yoichi Hariguchi <yoichi@fore.com>
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
#ifndef ARPPING_H_
#define ARPPING_H_

#include <stdint.h>
#include <net/if_arp.h>

#include "config.h"
#include "packet.h"

struct arpMsg {
    /* Ethernet header */
    uint8_t  h_dest[6];     /* 00 destination ether addr */
    uint8_t  h_source[6];   /* 06 source ether addr */
    uint16_t h_proto;       /* 0c packet type ID field */

    /* ARP packet */
    uint16_t htype;         /* 0e hardware type (must be ARPHRD_ETHER) */
    uint16_t ptype;         /* 10 protocol type (must be ETH_P_IP) */
    uint8_t  hlen;          /* 12 hardware address length (must be 6) */
    uint8_t  plen;          /* 13 protocol address length (must be 4) */
    uint16_t operation;     /* 14 ARP opcode */
    uint8_t  sHaddr[6];     /* 16 sender's hardware address */
    uint8_t  sInaddr[4];    /* 1c sender's IP address */
    uint8_t  tHaddr[6];     /* 20 target's hardware address */
    uint8_t  tInaddr[4];    /* 26 target's IP address */
    uint8_t  pad[18];       /* 2a pad for min. ethernet payload (60 bytes) */
};

int arp_check(struct client_state_t *cs, struct dhcpMessage *packet);
int arp_gw_check(struct client_state_t *cs);
int arp_get_gw_hwaddr(struct client_state_t *cs);
void arp_success(struct client_state_t *cs);
void arp_gw_failed(struct client_state_t *cs);
void handle_arp_response(struct client_state_t *cs);

#endif /* ARPPING_H_ */
