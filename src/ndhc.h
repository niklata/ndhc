/* ndhc.h - DHCP client
 *
 * Copyright (c) 2014-2015 Nicholas J. Kain <njkain at gmail dot com>
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
#ifndef NJK_NDHC_NDHC_H_
#define NJK_NDHC_NDHC_H_

#include <stdint.h>
#include <limits.h>
#include <net/if.h>
#include "nk/random.h"

struct client_state_t {
    unsigned long long leaseStartTime;
    int dhcpState;
    int arpPrevState;
    int ifsPrevState;
    int ifchWorking; // ifch is performing interface changes.
    int ifDeconfig; // Set if the interface has already been deconfigured.
    int epollFd, signalFd, listenFd, arpFd, nlFd, rfkillFd;
    int nlPortId;
    uint32_t clientAddr, serverAddr, srcAddr, routerAddr;
    uint32_t lease, renewTime, rebindTime, xid;
    struct nk_random_state_u32 rnd32_state;
    uint8_t routerArp[6], serverArp[6];
    uint8_t using_dhcp_bpf, init, got_router_arp, got_server_arp;
    uint8_t rfkill_set, rfkill_at_init;
};

struct client_config_t {
    char foreground;             // Do not fork
    char quit_after_lease;       // Quit after obtaining lease
    char abort_if_no_lease;      // Abort if no lease
    char background_if_no_lease; // Fork to background if no lease
    char enable_rfkill;          // Listen for rfkill events
    char interface[IFNAMSIZ];    // The name of the interface to use
    char clientid[64];           // Optional client id to use
    uint8_t clientid_len;        // Length of the clientid
    char hostname[64];           // Optional hostname to use
    char vendor[64];             // Vendor identification that will be sent
    int metric;                  // Metric for the default route
    int ifindex;                 // Index number of the interface to use
    uint32_t rfkillIdx;          // Index of the corresponding rfkill device
    uint8_t arp[6];              // Our arp address
};

extern struct client_config_t client_config;

extern int ifchSock[2];
extern int ifchStream[2];
extern int sockdSock[2];
extern int sockdStream[2];
extern char state_dir[PATH_MAX];
extern char chroot_dir[PATH_MAX];
extern char resolv_conf_d[PATH_MAX];
extern char pidfile[PATH_MAX];
extern uid_t ndhc_uid;
extern gid_t ndhc_gid;

void set_client_addr(const char *v);
void show_usage(void);
int get_clientid_string(char *str, size_t slen);
void background(void);
void print_version(void);

#endif /* NJK_NDHC_NDHC_H_ */
