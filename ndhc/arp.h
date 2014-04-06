/* arp.h - functions to call the interface change daemon
 *
 * Copyright (c) 2010-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#ifndef ARP_H_
#define ARP_H_

#include <stdint.h>
#include <net/if_arp.h>
#include "ndhc.h"
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

extern int arp_probe_wait;
extern int arp_probe_num;
extern int arp_probe_min;
extern int arp_probe_max;
extern int arp_relentless_def;

void arp_reset_send_stats(void);
void arp_close_fd(struct client_state_t *cs);
int arp_check(struct client_state_t *cs, struct dhcpmsg *packet);
int arp_gw_check(struct client_state_t *cs);
void arp_set_defense_mode(struct client_state_t *cs);
void arp_success(struct client_state_t *cs);
void handle_arp_response(struct client_state_t *cs);
void handle_arp_timeout(struct client_state_t *cs, long long nowts);
long long arp_get_wake_ts(void);

#endif /* ARP_H_ */
