/* arp.c - arp ping checking
 *
 * Copyright (c) 2010-2015 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <errno.h>
#include "nk/log.h"
#include "nk/io.h"
#include "arp.h"
#include "state.h"
#include "dhcp.h"
#include "sys.h"
#include "ifchange.h"
#include "options.h"
#include "leasefile.h"
#include "sockd.h"

#define ARP_MSG_SIZE 0x2a
#define ARP_RETRANS_DELAY 5000 // ms

// From RFC5227
int arp_probe_wait = 1000;         // initial random delay (ms)
int arp_probe_num = 3;             // number of probe packets
int arp_probe_min = 1000;          // minimum delay until repeated probe (ms)
int arp_probe_max = 2000;          // maximum delay until repeated probe (ms)
#define ANNOUNCE_WAIT 2000         // delay before announcing
#define ANNOUNCE_NUM 2             // number of Announcement packets
#define ANNOUNCE_INTERVAL 2000     // time between Announcement packets
#define MAX_CONFLICTS 10           // max conflicts before rate-limiting
#define RATE_LIMIT_INTERVAL 60000  // delay between successive attempts
#define DEFEND_INTERVAL 10000      // minimum interval between defensive ARPs

typedef enum {
    AS_NONE = 0,        // Nothing to react to wrt ARP
    AS_COLLISION_CHECK, // Checking to see if another host has our IP before
                        // accepting a new lease.
    AS_GW_CHECK,        // Seeing if the default GW still exists on the local
                        // segment after the hardware link was lost.
    AS_GW_QUERY,        // Finding the default GW MAC address.
    AS_DEFENSE,         // Defending our IP address (RFC5227)
    AS_MAX,
} arp_state_t;

typedef enum {
    ASEND_COLLISION_CHECK,
    ASEND_GW_PING,
    ASEND_ANNOUNCE,
    ASEND_MAX,
} arp_send_t;

struct arp_stats {
    long long ts;
    int count;
};

struct arp_data {
    struct dhcpmsg dhcp_packet;   // Used only for AS_COLLISION_CHECK
    struct arpMsg reply;
    struct arp_stats send_stats[ASEND_MAX];
    long long wake_ts[AS_MAX];
    long long last_conflict_ts;   // TS of the last conflicting ARP seen.
    long long arp_check_start_ts; // TS of when we started the
                                  // AS_COLLISION_CHECK state.
    size_t reply_offset;
    arp_state_t state;
    unsigned int total_conflicts; // Total number of address conflicts on
                                  // the interface.  Never decreases.
    int gw_check_initpings;       // Initial count of ASEND_GW_PING when
                                  // AS_GW_CHECK was entered.
    uint16_t probe_wait_time;     // Time to wait for a COLLISION_CHECK reply
                                  // (in ms?).
    bool using_bpf:1;             // Is a BPF installed on the ARP socket?
    bool relentless_def:1;        // Don't give up defense no matter what.
    bool router_replied:1;
    bool server_replied:1;
};

static struct arp_data garp = {
    .state = AS_NONE,
    .wake_ts = { -1, -1, -1, -1, -1 },
    .send_stats = {{0},{0},{0}},
    .last_conflict_ts = 0,
    .gw_check_initpings = 0,
    .arp_check_start_ts = 0,
    .total_conflicts = 0,
    .probe_wait_time = 0,
    .reply_offset = 0,
    .using_bpf = false,
    .relentless_def = false,
    .router_replied = false,
    .server_replied = false,
};

void set_arp_relentless_def(bool v) { garp.relentless_def = v; }

static void arp_reply_clear(void)
{
    memset(&garp.reply, 0, sizeof garp.reply);
    garp.reply_offset = 0;
}

void arp_reset_send_stats(void)
{
    for (int i = 0; i < ASEND_MAX; ++i) {
        garp.send_stats[i].ts = 0;
        garp.send_stats[i].count = 0;
    }
}

static int get_arp_basic_socket(void)
{
    char resp;
    int fd = request_sockd_fd("a", 1, &resp);
    switch (resp) {
        case 'A': garp.using_bpf = true; break;
        case 'a': garp.using_bpf = false; break;
        default: suicide("%s: (%s) expected a or A sockd reply but got %c",
                         client_config.interface, __func__, resp);
    }
    return fd;
}

static int get_arp_defense_socket(struct client_state_t cs[static 1])
{
    char buf[32];
    size_t buflen = 0;
    buf[0] = 'd';
    buflen += 1;
    memcpy(buf + buflen, &cs->clientAddr, sizeof cs->clientAddr);
    buflen += sizeof cs->clientAddr;
    memcpy(buf + buflen, client_config.arp, 6);
    buflen += 6;
    char resp;
    int fd = request_sockd_fd(buf, buflen, &resp);
    switch (resp) {
        case 'D': garp.using_bpf = true; break;
        case 'd': garp.using_bpf = false; break;
        default: suicide("%s: (%s) expected d or D sockd reply but got %c",
                         client_config.interface, __func__, resp);
    }
    return fd;
}

static int arp_open_fd(struct client_state_t cs[static 1], arp_state_t state)
{
    if (cs->arpFd >= 0) {
        log_warning("%s: (%s) called but fd already exists",
                    client_config.interface, __func__);
        return 0;
    }
    switch (state) {
    default:
        log_warning("%s: (%s) called for 'default' state",
                    client_config.interface, __func__);
        return 0;
    case AS_COLLISION_CHECK:
    case AS_GW_QUERY:
    case AS_GW_CHECK: cs->arpFd = get_arp_basic_socket(); break;
    case AS_DEFENSE: cs->arpFd = get_arp_defense_socket(cs); break;
    }
    if (cs->arpFd < 0) {
        log_error("%s: (%s) Failed to create socket: %s",
                  client_config.interface, __func__, strerror(errno));
        return -1;
    }
    epoll_add(cs->epollFd, cs->arpFd);
    arp_reply_clear();
    return 0;
}

static void arp_min_close_fd(struct client_state_t cs[static 1])
{
    if (cs->arpFd < 0)
        return;
    epoll_del(cs->epollFd, cs->arpFd);
    close(cs->arpFd);
    cs->arpFd = -1;
    garp.state = AS_NONE;
}

static void arp_switch_state(struct client_state_t cs[static 1], arp_state_t state)
{
    if (garp.state == state || garp.state >= AS_MAX)
        return;
    if (state == AS_NONE) {
        arp_close_fd(cs);
        return;
    }
    bool force_reopen = state == AS_DEFENSE || garp.state == AS_DEFENSE;
    if (force_reopen)
        arp_min_close_fd(cs);
    if (cs->arpFd < 0) {
        if (arp_open_fd(cs, state) < 0)
            suicide("%s: (%s) Failed to open arpFd when changing state %u -> %u",
                    client_config.interface, __func__, garp.state, state);
    }
    garp.state = state;
}

void arp_close_fd(struct client_state_t cs[static 1])
{
    arp_min_close_fd(cs);
    for (int i = 0; i < AS_MAX; ++i)
        garp.wake_ts[i] = -1;
}

static void arp_reopen_fd(struct client_state_t cs[static 1])
{
    arp_state_t prev_state = garp.state;
    arp_min_close_fd(cs);
    arp_switch_state(cs, prev_state);
}

static int arp_send(struct client_state_t cs[static 1], struct arpMsg *arp)
{
    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(addr.sll_addr, client_config.arp, 6);

    if (cs->arpFd < 0) {
        log_warning("%s: arp: Send attempted when no ARP fd is open.",
                    client_config.interface);
        return -1;
    }

    ssize_t r;
    if (!check_carrier(cs->arpFd)) {
        log_error("%s: (%s) carrier down; sendto would fail",
                  client_config.interface, __func__);
        goto carrier_down;
    }
    r = safe_sendto(cs->arpFd, (const char *)arp, sizeof *arp, 0,
                    (struct sockaddr *)&addr, sizeof addr);
    if (r < 0 || (size_t)r != sizeof *arp) {
        if (r < 0)
            log_error("%s: (%s) sendto failed: %s",
                      client_config.interface, __func__, strerror(errno));
        else
            log_error("%s: (%s) sendto short write: %z < %zu",
                      client_config.interface, __func__, r, sizeof *arp);
carrier_down:
        arp_reopen_fd(cs);
        return -1;
    }
    return 0;
}

#define BASE_ARPMSG() struct arpMsg arp = {                             \
        .h_proto = htons(ETH_P_ARP),                                    \
        .htype = htons(ARPHRD_ETHER),                                   \
        .ptype = htons(ETH_P_IP),                                       \
        .hlen = 6, .plen = 4,                                           \
        .operation = htons(ARPOP_REQUEST),                              \
        .smac = {0},                                                    \
    };                                                                  \
    memcpy(arp.h_source, client_config.arp, 6);                         \
    memset(arp.h_dest, 0xff, 6);                                        \
    memcpy(arp.smac, client_config.arp, 6)

// Returns 0 on success, -1 on failure.
static int arp_ping(struct client_state_t cs[static 1], uint32_t test_ip)
{
    BASE_ARPMSG();
    memcpy(arp.sip4, &cs->clientAddr, sizeof cs->clientAddr);
    memcpy(arp.dip4, &test_ip, sizeof test_ip);
    if (arp_send(cs, &arp) < 0)
        return -1;
    garp.send_stats[ASEND_GW_PING].count++;
    garp.send_stats[ASEND_GW_PING].ts = curms();
    return 0;
}

// Returns 0 on success, -1 on failure.
static int arp_ip_anon_ping(struct client_state_t cs[static 1], uint32_t test_ip)
{
    BASE_ARPMSG();
    memcpy(arp.dip4, &test_ip, sizeof test_ip);
    log_line("%s: arp: Probing for hosts that may conflict with our lease...",
             client_config.interface);
    if (arp_send(cs, &arp) < 0)
        return -1;
    garp.send_stats[ASEND_COLLISION_CHECK].count++;
    garp.send_stats[ASEND_COLLISION_CHECK].ts = curms();
    return 0;
}

static int arp_announcement(struct client_state_t cs[static 1])
{
    BASE_ARPMSG();
    memcpy(arp.sip4, &cs->clientAddr, 4);
    memcpy(arp.dip4, &cs->clientAddr, 4);
    if (arp_send(cs, &arp) < 0)
        return -1;
    garp.send_stats[ASEND_ANNOUNCE].count++;
    garp.send_stats[ASEND_ANNOUNCE].ts = curms();
    return 0;
}
#undef BASE_ARPMSG

// Callable from DS_REQUESTING, DS_RENEWING, or DS_REBINDING via an_packet()
int arp_check(struct client_state_t cs[static 1], struct dhcpmsg *packet)
{
    memcpy(&garp.dhcp_packet, packet, sizeof (struct dhcpmsg));
    arp_switch_state(cs, AS_COLLISION_CHECK);
    if (arp_ip_anon_ping(cs, garp.dhcp_packet.yiaddr) < 0)
        return -1;
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_COLLISION_CHECK;
    garp.arp_check_start_ts = garp.send_stats[ASEND_COLLISION_CHECK].ts;
    garp.probe_wait_time = arp_probe_wait;
    garp.wake_ts[AS_COLLISION_CHECK] = garp.arp_check_start_ts
                                       + garp.probe_wait_time;
    return 0;
}

// Callable only from DS_BOUND via state.c:ifup_action().
int arp_gw_check(struct client_state_t cs[static 1])
{
    if (garp.state == AS_GW_CHECK)  // Guard against state bounce.
        return 0;
    garp.gw_check_initpings = garp.send_stats[ASEND_GW_PING].count;
    garp.server_replied = false;
    if (arp_ping(cs, cs->srcAddr) < 0)
        return -1;
    if (cs->routerAddr) {
        garp.router_replied = false;
        if (arp_ping(cs, cs->routerAddr) < 0)
            return -1;
    } else
        garp.router_replied = true;
    arp_switch_state(cs, AS_GW_CHECK);
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_BOUND_GW_CHECK;
    garp.wake_ts[AS_GW_CHECK] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY + 250;
    return 0;
}

// Should only be called from DS_BOUND state.
static int arp_get_gw_hwaddr(struct client_state_t cs[static 1])
{
    if (cs->dhcpState != DS_BOUND)
        log_error("arp_get_gw_hwaddr: called when state != DS_BOUND");
    arp_switch_state(cs, AS_GW_QUERY);
    if (cs->routerAddr)
        log_line("%s: arp: Searching for dhcp server and gw addresses...",
                 client_config.interface);
    else
        log_line("%s: arp: Searching for dhcp server address...",
                 client_config.interface);
    cs->got_server_arp = 0;
    if (arp_ping(cs, cs->srcAddr) < 0)
        return -1;
    if (cs->routerAddr) {
        cs->got_router_arp = 0;
        if (arp_ping(cs, cs->routerAddr) < 0)
            return -1;
    } else
        cs->got_router_arp = 1;
    garp.wake_ts[AS_GW_QUERY] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY + 250;
    return 0;
}

static void arp_failed(struct client_state_t cs[static 1])
{
    log_line("%s: arp: Offered address is in use.  Declining.",
             client_config.interface);
    send_decline(cs, garp.dhcp_packet.yiaddr);
    garp.wake_ts[AS_COLLISION_CHECK] = -1;
    reinit_selecting(cs, garp.total_conflicts < MAX_CONFLICTS ?
                     0 : RATE_LIMIT_INTERVAL);
}

static void arp_gw_failed(struct client_state_t cs[static 1])
{
    garp.wake_ts[AS_GW_CHECK] = -1;
    reinit_selecting(cs, 0);
}

static int act_if_arp_gw_failed(struct client_state_t cs[static 1])
{
    if (garp.send_stats[ASEND_GW_PING].count >= garp.gw_check_initpings + 6) {
        if (garp.router_replied && !garp.server_replied)
            log_line("%s: arp: DHCP agent didn't reply.  Getting new lease.",
                     client_config.interface);
        else if (!garp.router_replied && garp.server_replied)
            log_line("%s: arp: Gateway didn't reply.  Getting new lease.",
                     client_config.interface);
        else
            log_line("%s: arp: DHCP agent and gateway didn't reply.  Getting new lease.",
                     client_config.interface);
        arp_gw_failed(cs);
        return 1;
    }
    return 0;
}

void arp_set_defense_mode(struct client_state_t cs[static 1])
{
    arp_switch_state(cs, AS_DEFENSE);
}

void arp_success(struct client_state_t cs[static 1])
{
    char clibuf[INET_ADDRSTRLEN];
    struct in_addr temp_addr = {.s_addr = garp.dhcp_packet.yiaddr};
    inet_ntop(AF_INET, &temp_addr, clibuf, sizeof clibuf);
    log_line("%s: Lease of %s obtained.  Lease time is %ld seconds.",
             client_config.interface, clibuf, cs->lease);
    cs->clientAddr = garp.dhcp_packet.yiaddr;
    cs->dhcpState = DS_BOUND;
    cs->init = 0;
    garp.last_conflict_ts = 0;
    garp.wake_ts[AS_COLLISION_CHECK] = -1;
    ifchange_bind(cs, &garp.dhcp_packet);
    if (cs->arpPrevState == DS_RENEWING || cs->arpPrevState == DS_REBINDING) {
        arp_switch_state(cs, AS_DEFENSE);
    } else {
        cs->routerAddr = get_option_router(&garp.dhcp_packet);
        arp_get_gw_hwaddr(cs);
    }
    stop_dhcp_listen(cs);
    write_leasefile(temp_addr);
    arp_announcement(cs);
    if (client_config.quit_after_lease)
        exit(EXIT_SUCCESS);
    if (!client_config.foreground)
        background();
}

static void arp_gw_success(struct client_state_t cs[static 1])
{
    log_line("%s: arp: Network seems unchanged.  Resuming normal operation.",
             client_config.interface);
    arp_switch_state(cs, AS_DEFENSE);
    arp_announcement(cs);

    garp.wake_ts[AS_GW_CHECK] = -1;
    cs->dhcpState = cs->arpPrevState;
}

// ARP validation functions that will be performed by the BPF if it is
// installed.
static int arp_validate_bpf(struct arpMsg *am)
{
    if (am->h_proto != htons(ETH_P_ARP)) {
        log_warning("%s: arp: IP header does not indicate ARP protocol",
                    client_config.interface);
        return 0;
    }
    if (am->htype != htons(ARPHRD_ETHER)) {
        log_warning("%s: arp: ARP hardware type field invalid",
                    client_config.interface);
        return 0;
    }
    if (am->ptype != htons(ETH_P_IP)) {
        log_warning("%s: arp: ARP protocol type field invalid",
                    client_config.interface);
        return 0;
    }
    if (am->hlen != 6) {
        log_warning("%s: arp: ARP hardware address length invalid",
                    client_config.interface);
        return 0;
    }
    if (am->plen != 4) {
        log_warning("%s: arp: ARP protocol address length invalid",
                    client_config.interface);
        return 0;
    }
    return 1;
}

// ARP validation functions that will be performed by the BPF if it is
// installed.
static int arp_validate_bpf_defense(struct client_state_t cs[static 1],
                                    struct arpMsg *am)
{
    if (memcmp(am->sip4, &cs->clientAddr, 4))
        return 0;
    if (!memcmp(am->smac, client_config.arp, 6))
        return 0;
    return 1;
}

static int arp_is_query_reply(struct arpMsg *am)
{
    if (am->operation != htons(ARPOP_REPLY))
        return 0;
    if (memcmp(am->h_dest, client_config.arp, 6))
        return 0;
    if (memcmp(am->dmac, client_config.arp, 6))
        return 0;
    return 1;
}

static int arp_gen_probe_wait(struct client_state_t cs[static 1])
{
    // This is not a uniform distribution but it doesn't matter here.
    return arp_probe_min + (nk_random_u32(&cs->rnd32_state) & 0x7fffffffu)
        % (arp_probe_max - arp_probe_min);
}

static void arp_defense_timeout(struct client_state_t cs[static 1], long long nowts)
{
    (void)nowts; // Suppress warning; parameter necessary but unused.
    if (garp.wake_ts[AS_DEFENSE] != -1) {
        log_line("%s: arp: Defending our lease IP.", client_config.interface);
        arp_announcement(cs);
        garp.wake_ts[AS_DEFENSE] = -1;
    }
}

static void arp_gw_check_timeout(struct client_state_t cs[static 1], long long nowts)
{
    arp_defense_timeout(cs, nowts);

    if (act_if_arp_gw_failed(cs))
        return;
    long long rtts = garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    if (nowts < rtts) {
        garp.wake_ts[AS_GW_CHECK] = rtts;
        return;
    }
    if (!garp.router_replied) {
        log_line("%s: arp: Still waiting for gateway to reply to arp ping...",
                 client_config.interface);
        if (arp_ping(cs, cs->routerAddr) < 0)
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
    }
    if (!garp.server_replied) {
        log_line("%s: arp: Still waiting for DHCP agent to reply to arp ping...",
                 client_config.interface);
        if (arp_ping(cs, cs->srcAddr) < 0)
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
    }
    garp.wake_ts[AS_GW_CHECK] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
}

static void arp_do_gw_query_done(struct client_state_t cs[static 1])
{
    garp.wake_ts[AS_GW_QUERY] = -1;
    arp_switch_state(cs, AS_DEFENSE);
    arp_announcement(cs);  // Do a second announcement.
}

static void arp_gw_query_timeout(struct client_state_t cs[static 1], long long nowts)
{
    arp_defense_timeout(cs, nowts);

    long long rtts = garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    if (nowts < rtts) {
        garp.wake_ts[AS_GW_QUERY] = rtts;
        return;
    }
    if (!cs->got_router_arp) {
        log_line("%s: arp: Still looking for gateway hardware address...",
                 client_config.interface);
        if (arp_ping(cs, cs->routerAddr) < 0)
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
    }
    if (!cs->got_server_arp) {
        log_line("%s: arp: Still looking for DHCP agent hardware address...",
                 client_config.interface);
        if (arp_ping(cs, cs->srcAddr) < 0)
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
    }
    garp.wake_ts[AS_GW_QUERY] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
}

static void arp_collision_timeout(struct client_state_t cs[static 1], long long nowts)
{
    arp_defense_timeout(cs, nowts);

    if (nowts >= garp.arp_check_start_ts + ANNOUNCE_WAIT ||
        garp.send_stats[ASEND_COLLISION_CHECK].count >= arp_probe_num) {
        arp_success(cs);
        return;
    }
    long long rtts = garp.send_stats[ASEND_COLLISION_CHECK].ts +
        garp.probe_wait_time;
    if (nowts < rtts) {
        garp.wake_ts[AS_COLLISION_CHECK] = rtts;
        return;
    }
    if (arp_ip_anon_ping(cs, garp.dhcp_packet.yiaddr) < 0)
        log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                    client_config.interface);
    garp.probe_wait_time = arp_gen_probe_wait(cs);
    garp.wake_ts[AS_COLLISION_CHECK] =
        garp.send_stats[ASEND_COLLISION_CHECK].ts + garp.probe_wait_time;
}

static void arp_do_defense(struct client_state_t cs[static 1])
{
    // Even though the BPF will usually catch this case, sometimes there are
    // packets still in the socket buffer that arrived before the defense
    // BPF was installed, so it's necessary to check here.
    if (!arp_validate_bpf_defense(cs, &garp.reply))
        return;

    log_warning("%s: arp: Detected a peer attempting to use our IP!", client_config.interface);
    long long nowts = curms();
    garp.wake_ts[AS_DEFENSE] = -1;
    if (!garp.last_conflict_ts ||
        nowts - garp.last_conflict_ts < DEFEND_INTERVAL) {
        log_warning("%s: arp: Defending our lease IP.", client_config.interface);
        arp_announcement(cs);
    } else if (!garp.relentless_def) {
        log_warning("%s: arp: Conflicting peer is persistent.  Requesting new lease.",
                    client_config.interface);
        send_release(cs);
        reinit_selecting(cs, 0);
    } else {
        garp.wake_ts[AS_DEFENSE] =
            garp.send_stats[ASEND_ANNOUNCE].ts + DEFEND_INTERVAL;
    }
    garp.total_conflicts++;
    garp.last_conflict_ts = nowts;
}

static void arp_do_gw_query(struct client_state_t cs[static 1])
{
    if (!arp_is_query_reply(&garp.reply)) {
        arp_do_defense(cs);
        return;
    }
    if (!memcmp(garp.reply.sip4, &cs->routerAddr, 4)) {
        memcpy(cs->routerArp, garp.reply.smac, 6);
        log_line("%s: arp: Gateway hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                 client_config.interface, cs->routerArp[0], cs->routerArp[1],
                 cs->routerArp[2], cs->routerArp[3],
                 cs->routerArp[4], cs->routerArp[5]);
        cs->got_router_arp = 1;
        if (cs->routerAddr == cs->srcAddr)
            goto server_is_router;
        if (cs->got_server_arp)
            arp_do_gw_query_done(cs);
        return;
    }
    if (!memcmp(garp.reply.sip4, &cs->srcAddr, 4)) {
server_is_router:
        memcpy(cs->serverArp, garp.reply.smac, 6);
        log_line("%s: arp: DHCP agent hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                 client_config.interface, cs->serverArp[0], cs->serverArp[1],
                 cs->serverArp[2], cs->serverArp[3],
                 cs->serverArp[4], cs->serverArp[5]);
        cs->got_server_arp = 1;
        if (cs->got_router_arp)
            arp_do_gw_query_done(cs);
        return;
    }
    arp_do_defense(cs);
}

static void arp_do_collision_check(struct client_state_t cs[static 1])
{
    if (!arp_is_query_reply(&garp.reply))
        return;
    // If this packet was sent from our lease IP, and does not have a
    // MAC address matching our own (the latter check guards against stupid
    // hubs or repeaters), then it's a conflict and thus a failure.
    if (!memcmp(garp.reply.sip4, &garp.dhcp_packet.yiaddr, 4) &&
        !memcmp(client_config.arp, garp.reply.smac, 6)) {
        garp.total_conflicts++;
        arp_failed(cs);
    }
}

static void arp_do_gw_check(struct client_state_t cs[static 1])
{
    if (!arp_is_query_reply(&garp.reply))
        return;
    if (!memcmp(garp.reply.sip4, &cs->routerAddr, 4)) {
        // Success only if the router/gw MAC matches stored value
        if (!memcmp(cs->routerArp, garp.reply.smac, 6)) {
            garp.router_replied = true;
            if (cs->routerAddr == cs->srcAddr)
                goto server_is_router;
            if (garp.server_replied)
                arp_gw_success(cs);
        } else {
            log_line("%s: arp: Gateway is different.  Getting a new lease.",
                     client_config.interface);
            arp_gw_failed(cs);
        }
        return;
    }
    if (!memcmp(garp.reply.sip4, &cs->srcAddr, 4)) {
server_is_router:
        // Success only if the server MAC matches stored value
        if (!memcmp(cs->serverArp, garp.reply.smac, 6)) {
            garp.server_replied = true;
            if (garp.router_replied)
                arp_gw_success(cs);
        } else {
            log_line("%s: arp: DHCP agent is different.  Getting a new lease.",
                     client_config.interface);
            arp_gw_failed(cs);
        }
    }
}

static void arp_do_invalid(struct client_state_t cs[static 1])
{
    log_error("%s: (%s) called in invalid state %u", client_config.interface,
              __func__, garp.state);
    arp_close_fd(cs);
}

typedef struct {
    void (*packet_fn)(struct client_state_t cs[static 1]);
    void (*timeout_fn)(struct client_state_t cs[static 1], long long nowts);
} arp_state_fn_t;

static const arp_state_fn_t arp_states[] = {
    { arp_do_invalid, 0 }, // AS_NONE
    { arp_do_collision_check, arp_collision_timeout }, // AS_COLLISION_CHECK
    { arp_do_gw_check, arp_gw_check_timeout }, // AS_GW_CHECK
    { arp_do_gw_query, arp_gw_query_timeout }, // AS_GW_QUERY
    { arp_do_defense, arp_defense_timeout }, // AS_DEFENSE
    { arp_do_invalid, 0 }, // AS_MAX
};

void handle_arp_response(struct client_state_t cs[static 1])
{
    ssize_t r = 0;
    if (garp.reply_offset < sizeof garp.reply) {
        r = safe_read(cs->arpFd, (char *)&garp.reply + garp.reply_offset,
                      sizeof garp.reply - garp.reply_offset);
        if (r < 0) {
            log_error("%s: (%s) ARP response read failed: %s",
                      client_config.interface, __func__, strerror(errno));
            switch (garp.state) {
            case AS_COLLISION_CHECK: arp_failed(cs); break;
            case AS_GW_CHECK: arp_gw_failed(cs); break;
            default: arp_reopen_fd(cs); break;
            }
        } else
            garp.reply_offset += (size_t)r;
    }

    if (r <= 0) {
        handle_arp_timeout(cs, curms());
        return;
    }

    if (garp.reply_offset < ARP_MSG_SIZE)
        return;

    // Emulate the BPF filters if they are not in use.
    if (!garp.using_bpf &&
        (!arp_validate_bpf(&garp.reply) ||
         (garp.state == AS_DEFENSE &&
          !arp_validate_bpf_defense(cs, &garp.reply)))) {
        arp_reply_clear();
        return;
    }

    if (arp_states[garp.state].packet_fn)
        arp_states[garp.state].packet_fn(cs);
    arp_reply_clear();
}

// Perform retransmission if necessary.
void handle_arp_timeout(struct client_state_t cs[static 1], long long nowts)
{
    if (arp_states[garp.state].timeout_fn)
        arp_states[garp.state].timeout_fn(cs, nowts);
}

long long arp_get_wake_ts(void)
{
    long long mt = -1;
    for (int i = 0; i < AS_MAX; ++i) {
        if (garp.wake_ts[i] < 0)
            continue;
        if (mt < 0 || mt > garp.wake_ts[i])
            mt = garp.wake_ts[i];
    }
    return mt;
}

