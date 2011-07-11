/* config.h - internal configuration and state for ndhc
 * Time-stamp: <2011-07-05 15:43:16 njk>
 *
 * (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef NDHC_CONFIG_H_
#define NDHC_CONFIG_H_

#include <stdint.h>

struct client_state_t {
    unsigned long long leaseStartTime;
    int dhcpState;
    int arpPrevState;
    int ifsPrevState;
    int listenMode;
    int epollFd, signalFd, listenFd, arpFd, nlFd;
    uint32_t clientAddr, serverAddr, routerAddr;
    uint32_t lease, renewTime, rebindTime, xid;
    uint8_t routerArp[6], serverArp[6];
    uint8_t using_dhcp_bpf, init, got_router_arp, got_server_arp;
};

struct client_config_t {
    char foreground;             // Do not fork
    char quit_after_lease;       // Quit after obtaining lease
    char abort_if_no_lease;      // Abort if no lease
    char background_if_no_lease; // Fork to background if no lease
    char clientid_mac;           // If true, then the clientid is a MAC addr
    char *interface;             // The name of the interface to use
    char clientid[64];           // Optional client id to use
    char hostname[64];           // Optional hostname to use
    char vendor[64];             // Vendor identification that will be sent
    int ifindex;                 // Index number of the interface to use
    uint8_t arp[6];              // Our arp address
};

extern struct client_config_t client_config;

#endif /* NDHC_CONFIG_H_ */

