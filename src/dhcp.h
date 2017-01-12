/* dhcp.h - general DHCP protocol handling
 *
 * Copyright (c) 2004-2017 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef NDHC_DHCP_H_
#define NDHC_DHCP_H_

#include <stdint.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include "ndhc.h"

#define DHCP_SERVER_PORT        67
#define DHCP_CLIENT_PORT        68
#define DHCP_MAGIC              0x63825363

enum {
    DHCPDISCOVER = 1,
    DHCPOFFER    = 2,
    DHCPREQUEST  = 3,
    DHCPDECLINE  = 4,
    DHCPACK  = 5,
    DHCPNAK  = 6,
    DHCPRELEASE  = 7,
    DHCPINFORM   = 8
};

struct dhcpmsg {
    uint8_t op;      // Message type: 1 = BOOTREQUEST for clients.
    uint8_t htype;   // ARP HW address type: always '1' for ethernet.
    uint8_t hlen;    // Hardware address length: always '6' for ethernet.
    uint8_t hops;    // Client sets to zero.
    uint32_t xid;    // Transaction ID: random number identifying session
    uint16_t secs;   // Filled by client: seconds since client began address
                     // aquisition or renewal process.
    uint16_t flags;  // DHCP flags
    uint32_t ciaddr; // Client IP: only filled in if client is in BOUND, RENEW,
                     // or REBINDING and can reply to ARP requests
    uint32_t yiaddr; // 'your' (client) IP address
    uint32_t siaddr; // Always zero -- unused.
    uint32_t giaddr; // Always zero -- unused.
    uint8_t chaddr[16];  // Client MAC address
    uint8_t sname[64];   // More DHCP options (#3)
    uint8_t file[128];   // More DHCP options (#2)
    uint32_t cookie;     // Magic number cookie that starts DHCP options
    uint8_t options[308]; // DHCP options field (#1)
};

struct ip_udp_dhcp_packet {
    struct iphdr ip;
    struct udphdr udp;
    struct dhcpmsg data;
};

struct udp_dhcp_packet {
    struct udphdr udp;
    struct dhcpmsg data;
};

void start_dhcp_listen(struct client_state_t cs[static 1]);
void stop_dhcp_listen(struct client_state_t cs[static 1]);
bool dhcp_packet_get(struct client_state_t cs[static 1],
                     struct dhcpmsg packet[static 1],
                     uint8_t msgtype[static 1],
                     uint32_t srcaddr[static 1]);
ssize_t send_discover(struct client_state_t cs[static 1]);
ssize_t send_selecting(struct client_state_t cs[static 1]);
ssize_t send_renew(struct client_state_t cs[static 1]);
ssize_t send_rebind(struct client_state_t cs[static 1]);
ssize_t send_decline(struct client_state_t cs[static 1], uint32_t server);
ssize_t send_release(struct client_state_t cs[static 1]);

#endif
