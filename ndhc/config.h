/* config.h - internal configuration and state for ndhc
 * Time-stamp: <2011-03-31 01:38:03 nk>
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

enum {
    IFS_NONE = 0,
    IFS_UP,
    IFS_DOWN,
    IFS_SHUT,
    IFS_REMOVED
};

struct client_state_t {
    unsigned long long leaseStartTime;
    int dhcpState;
    int arpPrevState;
    int ifsPrevState;
    int listenMode;
    int packetNum;
    int epollFd, signalFd, listenFd, arpFd, nlFd;
    int timeout, oldTimeout;
    uint32_t requestedIP, serverAddr, routerAddr;
    uint32_t lease, renewTime, rebindTime, xid;
    int using_dhcp_bpf;
    uint8_t routerArp[6];
    uint8_t init;
};

struct client_config_t {
    char foreground;             /* Do not fork */
    char quit_after_lease;       /* Quit after obtaining lease */
    char abort_if_no_lease;      /* Abort if no lease */
    char background_if_no_lease;    /* Fork to background if no lease */
    char *interface;             /* The name of the interface to use */
    uint8_t *clientid;           /* Optional client id to use (unterminated) */
    uint8_t *hostname;           /* Optional hostname to use (unterminated) */
    int ifindex;                 /* Index number of the interface to use */
    uint8_t arp[6];              /* Our arp address */
};

extern struct client_config_t client_config;

#endif /* NDHC_CONFIG_H_ */

