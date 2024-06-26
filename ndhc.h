// Copyright 2014-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
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

enum fprint_state {
    FPRINT_NONE = 0,
    FPRINT_INPROGRESS,
    FPRINT_DONE,
};

struct client_state_t {
    struct nk_random_state rnd_state;
    long long leaseStartTime, renewTime, rebindTime;
    long long dhcp_wake_ts;
    int ifDeconfig; // Set if the interface has already been deconfigured.
    int listenFd, arpFd, nlFd, rfkillFd;
    int server_arp_sent, router_arp_sent;
    uint32_t nlPortId;
    unsigned int num_dhcp_requests;
    uint32_t clientAddr, serverAddr, srcAddr, routerAddr;
    uint32_t clientSubnet;
    uint32_t lease, xid;
    uint8_t routerArp[6], serverArp[6];
    enum arp_state server_arp_state, router_arp_state;
    enum fprint_state fp_state;
    bool using_dhcp_bpf, arp_is_defense, check_fingerprint, program_init,
         sent_renew_or_rebind, carrier_up;
    bool sent_gw_query, sent_first_announce, sent_second_announce;
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
    int s6_notify_fd;            // File descriptor for s6 notify mechanism
    uint8_t clientid_len;        // Length of the clientid
    bool abort_if_no_lease;      // Abort if no lease
    bool enable_rfkill;          // Listen for rfkill events
    bool enable_s6_notify;       // Perform s6 startup notification
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
extern int scriptdSock[2];
extern int scriptdStream[2];
extern char state_dir[PATH_MAX];
extern char chroot_dir[PATH_MAX];
extern char resolv_conf_d[PATH_MAX];
extern char script_file[PATH_MAX];
extern uid_t ndhc_uid;
extern gid_t ndhc_gid;

int signals_flagged(void);
bool carrier_isup(void);
void set_client_addr(const char *v);
void show_usage(void);
void signal_exit(int status);
void print_version(void);

static inline void advance_xid(struct client_state_t *cs) {
    uint32_t o = cs->xid;
    do {
        cs->xid = nk_random_u32(&cs->rnd_state);
    } while (cs->xid == o);
}

#endif

