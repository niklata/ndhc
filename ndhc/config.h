/* config.h - internal configuration and state for ndhc
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

#ifndef NDHC_CONFIG_H_
#define NDHC_CONFIG_H_

#include <stdint.h>
#include <net/if.h>

struct client_state_t {
    unsigned long long leaseStartTime;
    int dhcpState;
    int arpPrevState;
    int ifsPrevState;
    int listenMode;
    int epollFd, signalFd, listenFd, arpFd, nlFd;
    int nlPortId;
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
    char interface[IFNAMSIZ];    // The name of the interface to use
    char clientid[64];           // Optional client id to use
    char hostname[64];           // Optional hostname to use
    char vendor[64];             // Vendor identification that will be sent
    int ifindex;                 // Index number of the interface to use
    uint8_t arp[6];              // Our arp address
};

extern struct client_config_t client_config;

#endif /* NDHC_CONFIG_H_ */

