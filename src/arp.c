/* arp.c - arp ping checking
 *
 * Copyright (c) 2010-2017 Nicholas J. Kain <njkain at gmail dot com>
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
#include "netlink.h"

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

static struct arp_data garp = {
    .wake_ts = { -1, -1, -1, -1, -1, -1, -1 },
    .send_stats = {{0,0},{0,0},{0,0}},
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

void arp_reply_clear(void)
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

static int get_arp_basic_socket(struct client_state_t cs[static 1])
{
    char resp;
    int fd = request_sockd_fd("a", 1, &resp);
    switch (resp) {
        case 'A': garp.using_bpf = true; break;
        case 'a': garp.using_bpf = false; break;
        default: suicide("%s: (%s) expected a or A sockd reply but got %c",
                         client_config.interface, __func__, resp);
    }
    cs->arp_is_defense = false;
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
    cs->arp_is_defense = true;
    return fd;
}

static void arp_min_close_fd(struct client_state_t cs[static 1])
{
    if (cs->arpFd < 0)
        return;
    epoll_del(cs->epollFd, cs->arpFd);
    close(cs->arpFd);
    cs->arpFd = -1;
    cs->arp_is_defense = false;
}

void arp_close_fd(struct client_state_t cs[static 1])
{
    arp_min_close_fd(cs);
    for (int i = 0; i < AS_MAX; ++i)
        garp.wake_ts[i] = -1;
}

static int arp_open_fd(struct client_state_t cs[static 1], bool defense)
{
    if (cs->arpFd >= 0 && defense == cs->arp_is_defense)
        return 0;
    arp_min_close_fd(cs);
    cs->arpFd = defense ? get_arp_defense_socket(cs)
                        : get_arp_basic_socket(cs);
    if (cs->arpFd < 0) {
        log_error("%s: (%s) Failed to create socket: %s",
                  client_config.interface, __func__, strerror(errno));
        return -1;
    }
    epoll_add(cs->epollFd, cs->arpFd);
    arp_reply_clear();
    return 0;
}

static int arp_send(struct client_state_t cs[static 1],
                    struct arpMsg arp[static 1])
{
    int ret = -1;
    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(addr.sll_addr, client_config.arp, 6);

    if (cs->arpFd < 0) {
        log_warning("%s: arp: Send attempted when no ARP fd is open.",
                    client_config.interface);
        return ret;
    }

    if (!carrier_isup()) {
        log_error("%s: (%s) carrier down; sendto would fail",
                  client_config.interface, __func__);
        ret = -99;
        goto carrier_down;
    }
    ret = safe_sendto(cs->arpFd, (const char *)arp, sizeof *arp, 0,
                    (struct sockaddr *)&addr, sizeof addr);
    if (ret < 0 || (size_t)ret != sizeof *arp) {
        if (ret < 0)
            log_error("%s: (%s) sendto failed: %s",
                      client_config.interface, __func__, strerror(errno));
        else
            log_error("%s: (%s) sendto short write: %d < %zu",
                      client_config.interface, __func__, ret, sizeof *arp);
carrier_down:
        return ret;
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
    int r = arp_send(cs, &arp);
    if (r < 0)
        return r;
    garp.send_stats[ASEND_GW_PING].count++;
    garp.send_stats[ASEND_GW_PING].ts = curms();
    return 0;
}

// Returns 0 on success, -1 on failure.
static int arp_ip_anon_ping(struct client_state_t cs[static 1],
                            uint32_t test_ip)
{
    BASE_ARPMSG();
    memcpy(arp.dip4, &test_ip, sizeof test_ip);
    log_line("%s: arp: Probing for hosts that may conflict with our lease...",
             client_config.interface);
    int r = arp_send(cs, &arp);
    if (r < 0)
        return r;
    garp.send_stats[ASEND_COLLISION_CHECK].count++;
    garp.send_stats[ASEND_COLLISION_CHECK].ts = curms();
    return 0;
}

static int arp_announcement(struct client_state_t cs[static 1])
{
    BASE_ARPMSG();
    memcpy(arp.sip4, &cs->clientAddr, 4);
    memcpy(arp.dip4, &cs->clientAddr, 4);
    int r = arp_send(cs, &arp);
    if (r < 0)
        return r;
    garp.send_stats[ASEND_ANNOUNCE].count++;
    garp.send_stats[ASEND_ANNOUNCE].ts = curms();
    return 0;
}
#undef BASE_ARPMSG

// Checks to see if there is another host that has our assigned IP.
int arp_check(struct client_state_t cs[static 1],
              struct dhcpmsg packet[static 1])
{
    memcpy(&garp.dhcp_packet, packet, sizeof (struct dhcpmsg));
    if (arp_open_fd(cs, false) < 0)
        return -1;
    if (arp_ip_anon_ping(cs, garp.dhcp_packet.yiaddr) < 0)
        return -1;
    garp.arp_check_start_ts = garp.send_stats[ASEND_COLLISION_CHECK].ts;
    garp.probe_wait_time = arp_probe_wait;
    garp.wake_ts[AS_COLLISION_CHECK] = garp.arp_check_start_ts
                                       + garp.probe_wait_time;
    return 0;
}

// Confirms that we're still on the fingerprinted network.
int arp_gw_check(struct client_state_t cs[static 1])
{
    if (arp_open_fd(cs, false) < 0)
        return -1;
    garp.gw_check_initpings = garp.send_stats[ASEND_GW_PING].count;
    garp.server_replied = false;
    cs->check_fingerprint = true;
    int r;
    if ((r = arp_ping(cs, cs->srcAddr)) < 0)
        return r;
    if (cs->routerAddr) {
        garp.router_replied = false;
        if ((r = arp_ping(cs, cs->routerAddr)) < 0)
            return r;
    } else
        garp.router_replied = true;
    garp.wake_ts[AS_GW_CHECK] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY + 250;
    return 0;
}

// Gathers the fingerprinting info for the associated network.
static int arp_get_gw_hwaddr(struct client_state_t cs[static 1])
{
    if (arp_open_fd(cs, false) < 0)
        return -1;
    if (cs->routerAddr)
        log_line("%s: arp: Searching for dhcp server and gw addresses...",
                 client_config.interface);
    else
        log_line("%s: arp: Searching for dhcp server address...",
                 client_config.interface);
    cs->got_server_arp = false;
    if (arp_ping(cs, cs->srcAddr) < 0)
        return -1;
    if (cs->routerAddr) {
        cs->got_router_arp = false;
        if (arp_ping(cs, cs->routerAddr) < 0)
            return -1;
    } else
        cs->got_router_arp = true;
    garp.wake_ts[AS_GW_QUERY] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY + 250;
    return 0;
}

int arp_set_defense_mode(struct client_state_t cs[static 1])
{
    return arp_open_fd(cs, true);
}

static int arp_gw_success(struct client_state_t cs[static 1])
{
    log_line("%s: arp: Network seems unchanged.  Resuming normal operation.",
             client_config.interface);
    if (arp_open_fd(cs, true) < 0)
        return ARPR_FAIL;
    garp.wake_ts[AS_GW_CHECK] = -1;
    if (arp_announcement(cs) < 0)
        return ARPR_FAIL;
    return ARPR_FREE;
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
                                    struct arpMsg am[static 1])
{
    if (memcmp(am->sip4, &cs->clientAddr, 4))
        return 0;
    if (!memcmp(am->smac, client_config.arp, 6))
        return 0;
    return 1;
}

static int arp_is_query_reply(struct arpMsg am[static 1])
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

int arp_defense_timeout(struct client_state_t cs[static 1], long long nowts)
{
    (void)nowts; // Suppress warning; parameter necessary but unused.
    int ret = 0;
    if (garp.wake_ts[AS_DEFENSE] != -1) {
        log_line("%s: arp: Defending our lease IP.", client_config.interface);
        garp.wake_ts[AS_DEFENSE] = -1;
        ret = arp_announcement(cs);
    }
    return ret;
}

int arp_gw_check_timeout(struct client_state_t cs[static 1], long long nowts)
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
        garp.wake_ts[AS_GW_CHECK] = -1;
        return ARPR_CONFLICT;
    }
    long long rtts = garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    if (nowts < rtts) {
        garp.wake_ts[AS_GW_CHECK] = rtts;
        return ARPR_OK;
    }
    if (!garp.router_replied) {
        log_line("%s: arp: Still waiting for gateway to reply to arp ping...",
                 client_config.interface);
        if (arp_ping(cs, cs->routerAddr) < 0) {
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
            return ARPR_FAIL;
        }
    }
    if (!garp.server_replied) {
        log_line("%s: arp: Still waiting for DHCP agent to reply to arp ping...",
                 client_config.interface);
        if (arp_ping(cs, cs->srcAddr) < 0) {
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
            return ARPR_FAIL;
        }
    }
    garp.wake_ts[AS_GW_CHECK] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    return ARPR_OK;
}

int arp_gw_query_timeout(struct client_state_t cs[static 1], long long nowts)
{
    long long rtts = garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    if (nowts < rtts) {
        garp.wake_ts[AS_GW_QUERY] = rtts;
        return ARPR_OK;
    }
    if (!cs->got_router_arp) {
        log_line("%s: arp: Still looking for gateway hardware address...",
                 client_config.interface);
        if (arp_ping(cs, cs->routerAddr) < 0) {
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
            return ARPR_FAIL;
        }
    }
    if (!cs->got_server_arp) {
        log_line("%s: arp: Still looking for DHCP agent hardware address...",
                 client_config.interface);
        if (arp_ping(cs, cs->srcAddr) < 0) {
            log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                        client_config.interface);
            return ARPR_FAIL;
        }
    }
    garp.wake_ts[AS_GW_QUERY] =
        garp.send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    return ARPR_OK;
}

// Failure here is difficult to handle gracefully, as we do have a valid
// IP but have not yet announced it to other hosts on our ethernet
// segment.  We try to do so for one minute.  We must measure the time
// directly so that carrier loss or suspend are handled properly.
__attribute__((noreturn))
static void quit_after_lease_handler(struct client_state_t cs[static 1])
{
    long long init_ts = curms();
    for (;;) {
        if (arp_announcement(cs) >= 0)
            exit(EXIT_SUCCESS);
        log_warning("%s: (%s) Failed to send ARP announcement: %s",
                    client_config.interface, __func__, strerror(errno));
        if (curms() - init_ts > (60LL * 1000LL)) break;
    }
    exit(EXIT_FAILURE);
}

int arp_collision_timeout(struct client_state_t cs[static 1], long long nowts)
{
    if (nowts >= garp.arp_check_start_ts + ANNOUNCE_WAIT ||
        garp.send_stats[ASEND_COLLISION_CHECK].count >= arp_probe_num)
    {
        char clibuf[INET_ADDRSTRLEN];
        struct in_addr temp_addr = {.s_addr = garp.dhcp_packet.yiaddr};
        inet_ntop(AF_INET, &temp_addr, clibuf, sizeof clibuf);
        log_line("%s: Lease of %s obtained.  Lease time is %ld seconds.",
                 client_config.interface, clibuf, cs->lease);
        cs->clientAddr = garp.dhcp_packet.yiaddr;
        cs->program_init = false;
        garp.last_conflict_ts = 0;
        garp.wake_ts[AS_COLLISION_CHECK] = -1;
        if (ifchange_bind(cs, &garp.dhcp_packet) < 0) {
            suicide("%s: Failed to set the interface IP address and properties!",
                    client_config.interface);
        }
        cs->routerAddr = get_option_router(&garp.dhcp_packet);
        stop_dhcp_listen(cs);
        write_leasefile(temp_addr);
        if (client_config.quit_after_lease)
            quit_after_lease_handler(cs);
        return ARPR_FREE;
    }
    long long rtts = garp.send_stats[ASEND_COLLISION_CHECK].ts +
        garp.probe_wait_time;
    if (nowts < rtts) {
        garp.wake_ts[AS_COLLISION_CHECK] = rtts;
        return ARPR_OK;
    }
    if (arp_ip_anon_ping(cs, garp.dhcp_packet.yiaddr) < 0) {
        log_warning("%s: arp: Failed to send ARP ping in retransmission.",
                    client_config.interface);
        return ARPR_FAIL;
    }
    garp.probe_wait_time = arp_gen_probe_wait(cs);
    garp.wake_ts[AS_COLLISION_CHECK] =
        garp.send_stats[ASEND_COLLISION_CHECK].ts + garp.probe_wait_time;
    return ARPR_OK;
}

int arp_query_gateway(struct client_state_t cs[static 1])
{
    if (cs->sent_gw_query) {
        garp.wake_ts[AS_QUERY_GW_SEND] = -1;
        return ARPR_OK;
    }
    if (arp_get_gw_hwaddr(cs) < 0) {
        log_warning("%s: (%s) Failed to send request to get gateway and agent hardware addresses: %s",
                    client_config.interface, __func__, strerror(errno));
        garp.wake_ts[AS_QUERY_GW_SEND] = curms() + ARP_RETRANS_DELAY;
        return ARPR_FAIL;
    }
    cs->sent_gw_query = true;
    garp.wake_ts[AS_QUERY_GW_SEND] = -1;
    return ARPR_OK;
}

// 1 == not yet time, 0 == timed out, success, -1 == timed out, failure
int arp_query_gateway_timeout(struct client_state_t cs[static 1], long long nowts)
{
    long long rtts = garp.wake_ts[AS_QUERY_GW_SEND];
    if (rtts == -1) return 0;
    if (nowts < rtts) return 1;
    return arp_query_gateway(cs) == ARPR_OK ? 0 : -1;
}

int arp_announce(struct client_state_t cs[static 1])
{
    if (cs->sent_first_announce && cs->sent_second_announce) {
        garp.wake_ts[AS_ANNOUNCE] = -1;
        return ARPR_OK;
    }
    if (arp_announcement(cs) < 0) {
        log_warning("%s: (%s) Failed to send ARP announcement: %s",
                    client_config.interface, __func__, strerror(errno));
        garp.wake_ts[AS_ANNOUNCE] = curms() + ARP_RETRANS_DELAY ;
        return ARPR_FAIL;
    }
    if (!cs->sent_first_announce)
        cs->sent_first_announce = true;
    else if (!cs->sent_second_announce)
        cs->sent_second_announce = true;
    if (!cs->sent_first_announce || !cs->sent_second_announce)
        garp.wake_ts[AS_ANNOUNCE] = curms() + ARP_RETRANS_DELAY;
    else
        garp.wake_ts[AS_ANNOUNCE] = -1;
    return ARPR_OK;
}

// 1 == not yet time, 0 == timed out, success, -1 == timed out, failure
int arp_announce_timeout(struct client_state_t cs[static 1], long long nowts)
{
    long long rtts = garp.wake_ts[AS_ANNOUNCE];
    if (rtts == -1) return 0;
    if (nowts < rtts) return 1;
    return arp_announce(cs) == ARPR_OK ? 0 : -1;
}

int arp_do_defense(struct client_state_t cs[static 1])
{
    // Even though the BPF will usually catch this case, sometimes there are
    // packets still in the socket buffer that arrived before the defense
    // BPF was installed, so it's necessary to check here.
    if (!arp_validate_bpf_defense(cs, &garp.reply))
        return ARPR_OK;

    log_warning("%s: arp: Detected a peer attempting to use our IP!", client_config.interface);
    long long nowts = curms();
    garp.wake_ts[AS_DEFENSE] = -1;
    if (!garp.last_conflict_ts ||
        nowts - garp.last_conflict_ts < DEFEND_INTERVAL) {
        log_warning("%s: arp: Defending our lease IP.", client_config.interface);
        if (arp_announcement(cs) < 0)
            return ARPR_FAIL;
    } else if (!garp.relentless_def) {
        log_warning("%s: arp: Conflicting peer is persistent.  Requesting new lease.",
                    client_config.interface);
        send_release(cs);
        return ARPR_CONFLICT;
    } else {
        garp.wake_ts[AS_DEFENSE] =
            garp.send_stats[ASEND_ANNOUNCE].ts + DEFEND_INTERVAL;
    }
    garp.total_conflicts++;
    garp.last_conflict_ts = nowts;
    return ARPR_OK;
}

int arp_do_gw_query(struct client_state_t cs[static 1])
{
    if (!arp_is_query_reply(&garp.reply))
        return ARPR_OK;
    if (!memcmp(garp.reply.sip4, &cs->routerAddr, 4)) {
        memcpy(cs->routerArp, garp.reply.smac, 6);
        log_line("%s: arp: Gateway hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                 client_config.interface, cs->routerArp[0], cs->routerArp[1],
                 cs->routerArp[2], cs->routerArp[3],
                 cs->routerArp[4], cs->routerArp[5]);
        cs->got_router_arp = true;
        if (cs->routerAddr == cs->srcAddr)
            goto server_is_router;
        if (cs->got_server_arp) {
            garp.wake_ts[AS_GW_QUERY] = -1;
            if (arp_open_fd(cs, true) < 0)
                return ARPR_FAIL;
            return ARPR_FREE;
        }
        return ARPR_OK;
    }
    if (!memcmp(garp.reply.sip4, &cs->srcAddr, 4)) {
server_is_router:
        memcpy(cs->serverArp, garp.reply.smac, 6);
        log_line("%s: arp: DHCP agent hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                 client_config.interface, cs->serverArp[0], cs->serverArp[1],
                 cs->serverArp[2], cs->serverArp[3],
                 cs->serverArp[4], cs->serverArp[5]);
        cs->got_server_arp = true;
        if (cs->got_router_arp) {
            garp.wake_ts[AS_GW_QUERY] = -1;
            if (arp_open_fd(cs, true) < 0)
                return ARPR_FAIL;
            return ARPR_FREE;
        }
        return ARPR_OK;
    }
    return ARPR_OK;
}

int arp_do_collision_check(struct client_state_t cs[static 1])
{
    if (!arp_is_query_reply(&garp.reply))
        return ARPR_OK;
    // If this packet was sent from our lease IP, and does not have a
    // MAC address matching our own (the latter check guards against stupid
    // hubs or repeaters), then it's a conflict and thus a failure.
    if (!memcmp(garp.reply.sip4, &garp.dhcp_packet.yiaddr, 4) &&
        !memcmp(client_config.arp, garp.reply.smac, 6))
    {
        garp.total_conflicts++;
        garp.wake_ts[AS_COLLISION_CHECK] = -1;
        log_line("%s: arp: Offered address is in use.  Declining.",
                 client_config.interface);
        int r = send_decline(cs, garp.dhcp_packet.yiaddr);
        if (r < 0) {
            log_warning("%s: Failed to send a decline notice packet.",
                        client_config.interface);
            return ARPR_FAIL;
        }
        return ARPR_CONFLICT;
    }
    return ARPR_OK;
}

int arp_do_gw_check(struct client_state_t cs[static 1])
{
    if (!arp_is_query_reply(&garp.reply))
        return ARPR_OK;
    if (!memcmp(garp.reply.sip4, &cs->routerAddr, 4)) {
        // Success only if the router/gw MAC matches stored value
        if (!memcmp(cs->routerArp, garp.reply.smac, 6)) {
            garp.router_replied = true;
            if (cs->routerAddr == cs->srcAddr)
                goto server_is_router;
            if (garp.server_replied)
                return arp_gw_success(cs); // FREE or FAIL
            return ARPR_OK;
        }
        log_line("%s: arp: Gateway is different.  Getting a new lease.",
                 client_config.interface);
        garp.wake_ts[AS_GW_CHECK] = -1;
        return ARPR_CONFLICT;
    }
    if (!memcmp(garp.reply.sip4, &cs->srcAddr, 4)) {
server_is_router:
        // Success only if the server MAC matches stored value
        if (!memcmp(cs->serverArp, garp.reply.smac, 6)) {
            garp.server_replied = true;
            if (garp.router_replied)
                return arp_gw_success(cs); // FREE or FAIL
            return ARPR_OK;
        }
        log_line("%s: arp: DHCP agent is different.  Getting a new lease.",
                 client_config.interface);
        garp.wake_ts[AS_GW_CHECK] = -1;
        return ARPR_CONFLICT;
    }
    return ARPR_OK;
}

bool arp_packet_get(struct client_state_t cs[static 1])
{
    ssize_t r = 0;
    if (garp.reply_offset < sizeof garp.reply) {
        r = safe_read(cs->arpFd, (char *)&garp.reply + garp.reply_offset,
                      sizeof garp.reply - garp.reply_offset);
        if (r == 0)
            return false;
        if (r < 0) {
            log_error("%s: (%s) ARP response read failed: %s",
                      client_config.interface, __func__, strerror(errno));
            // Timeouts will trigger anyway without being forced.
            arp_min_close_fd(cs);
            if (arp_open_fd(cs, cs->arp_is_defense) < 0)
                suicide("%s: (%s) Failed to reopen ARP fd: %s",
                        client_config.interface, __func__, strerror(errno));
            return false;
        }
        garp.reply_offset += (size_t)r;
    }

    if (garp.reply_offset < ARP_MSG_SIZE)
        return false;

    // Emulate the BPF filters if they are not in use.
    if (!garp.using_bpf &&
        (!arp_validate_bpf(&garp.reply) ||
         (cs->arp_is_defense &&
          !arp_validate_bpf_defense(cs, &garp.reply)))) {
        arp_reply_clear();
        return false;
    }
    return true;
}

// XXX: Move into client_state
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

