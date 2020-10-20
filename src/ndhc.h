/* ndhc.h - DHCP client
 *
 * Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdbool.h>
#include <limits.h>
#include <net/if.h>
#include "nk/random.h"

enum arp_state {
    ARP_QUERY = 0,
    ARP_FOUND,
    ARP_FAILED,
};

struct client_state_t {
    struct nk_random_state rnd_state;
    long long leaseStartTime, renewTime, rebindTime;
    long long dhcp_wake_ts;
    int ifDeconfig; // Set if the interface has already been deconfigured.
    int epollFd, listenFd, arpFd, nlFd, rfkillFd;
    int server_arp_sent, router_arp_sent;
    uint32_t nlPortId;
    unsigned int num_dhcp_requests, num_dhcp_renews;
    uint32_t clientAddr, serverAddr, srcAddr, routerAddr;
    uint32_t lease, xid;
    uint8_t routerArp[6], serverArp[6];
    enum arp_state server_arp_state, router_arp_state;
    bool using_dhcp_bpf, arp_is_defense, check_fingerprint, program_init,
         sent_renew_or_rebind;
    bool sent_gw_query, sent_first_announce, sent_second_announce,
         init_fingerprint_inprogress;
};

struct client_config_t {
    char interface[IFNAMSIZ];    // The name of the interface to use
    char clientid[64];           // Optional client id to use
    char hostname[64];           // Optional hostname to use
    char vendor[64];             // Vendor identification that will be sent
    uint8_t arp[6];              // Our arp address
    uint32_t rfkillIdx;          // Index of the corresponding rfkill device
    int metric;                  // Metric for the default route
    int ifindex;                 // Index number of the interface to use
    uint8_t clientid_len;        // Length of the clientid
    bool quit_after_lease;       // Quit after obtaining lease
    bool abort_if_no_lease;      // Abort if no lease
    bool background_if_no_lease; // Fork to background if no lease
    bool enable_rfkill;          // Listen for rfkill events
};

enum {
    SIGNAL_NONE = 0,
    SIGNAL_EXIT,
    SIGNAL_RENEW,
    SIGNAL_RELEASE
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
extern bool write_pid_enabled;

int signals_flagged(void);
void set_client_addr(const char v[static 1]);
void show_usage(void);
void signal_exit(int status);
int get_clientid_string(const char str[static 1], size_t slen);
void background(void);
void print_version(void);

#endif /* NJK_NDHC_NDHC_H_ */
