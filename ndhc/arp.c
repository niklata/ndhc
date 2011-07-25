/* arp.c - arp ping checking
 *
 * Copyright (c) 2010-2011 Nicholas J. Kain <njkain at gmail dot com>
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <errno.h>
#include "arp.h"
#include "state.h"
#include "dhcp.h"
#include "sys.h"
#include "ifchange.h"
#include "options.h"
#include "leasefile.h"
#include "log.h"
#include "io.h"

#define ARP_MSG_SIZE 0x2a
#define ARP_RETRANS_DELAY 5000 // ms

// From RFC5227
#define PROBE_WAIT 1000            // initial random delay
#define PROBE_NUM 3                // number of probe packets
#define PROBE_MIN 1000             // minimum delay until repeated probe
#define PROBE_MAX 2000             // maximum delay until repeated probe
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

static long long arp_wake_ts[AS_MAX] = { -1, -1, -1, -1, -1 };

typedef enum {
    ASEND_COLLISION_CHECK,
    ASEND_GW_PING,
    ASEND_ANNOUNCE,
    ASEND_MAX,
} arp_send_t;

static arp_state_t arpState;
struct arp_stats {
    long long ts;
    int count;
};
static struct arp_stats arp_send_stats[ASEND_MAX];
static int using_arp_bpf; // Is a BPF installed on the ARP socket?

int arp_relentless_def; // Don't give up defense no matter what.
static long long last_conflict_ts; // TS of the last conflicting ARP seen.

static int gw_check_init_pingcount; // Initial count of ASEND_GW_PING when
                                    // AS_GW_CHECK was entered.

static uint16_t probe_wait_time; // Time to wait for a COLLISION_CHECK reply.
static long long arp_check_start_ts; // TS of when we started the
                                     // AS_COLLISION_CHECK state.

static unsigned int total_conflicts; // Total number of address conflicts on
                                     // the interface.  Never decreases.

static struct dhcpmsg arp_dhcp_packet; // Used only for AS_COLLISION_CHECK

static char arp_router_has_replied;
static char arp_server_has_replied;

static struct arpMsg arpreply;
static int arpreply_offset;
static void arpreply_clear(void)
{
    memset(&arpreply, 0, sizeof arpreply);
    arpreply_offset = 0;
}

void arp_reset_send_stats(void)
{
    for (int i = 0; i < ASEND_MAX; ++i) {
        arp_send_stats[i].ts = 0;
        arp_send_stats[i].count = 0;
    }
}

static void arp_set_bpf_basic(int fd)
{
    static const struct sock_filter sf_arp[] = {
        // Verify that the frame has ethernet protocol type of ARP
        // and that the ARP hardware type field indicates Ethernet.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 12),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_ARP << 16) | ARPHRD_ETHER,
                 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Verify that the ARP protocol type field indicates IP, the ARP
        // hardware address length field is 6, and the ARP protocol address
        // length field is 4.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 16),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_IP << 16) | 0x0604, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Sanity tests passed, so send all possible data.
        BPF_STMT(BPF_RET + BPF_K, 0x7fffffff),
    };
    static const struct sock_fprog sfp_arp = {
        .len = sizeof sf_arp / sizeof sf_arp[0],
        .filter = (struct sock_filter *)sf_arp,
    };
    using_arp_bpf = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sfp_arp,
                               sizeof sfp_arp) != -1;
}

static void arp_set_bpf_defense(struct client_state_t *cs, int fd)
{
    uint32_t mac4b;
    uint16_t mac2b;
    memcpy(&mac4b, client_config.arp, 4);
    memcpy(&mac2b, client_config.arp+4, 2);

    struct sock_filter sf_arp[] = {
        // Verify that the frame has ethernet protocol type of ARP
        // and that the ARP hardware type field indicates Ethernet.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 12),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_ARP << 16) | ARPHRD_ETHER,
                 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Verify that the ARP protocol type field indicates IP, the ARP
        // hardware address length field is 6, and the ARP protocol address
        // length field is 4.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 16),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_IP << 16) | 0x0604, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),

        // If the ARP packet source IP does not match our IP address, then
        // it can be ignored.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 28),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, cs->clientAddr, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // If the first four bytes of the ARP packet source hardware address
        // does not equal our hardware address, then it's a conflict and should
        // be passed along.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 22),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac4b, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0x7fffffff),
        // If the last two bytes of the ARP packet source hardware address
        // do not equal our hardware address, then it's a conflict and should
        // be passed along.
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 26),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac2b, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0x7fffffff),
        // Packet announces our IP address and hardware address, so it requires
        // no action.
        BPF_STMT(BPF_RET + BPF_K, 0),
    };
    struct sock_fprog sfp_arp = {
        .len = sizeof sf_arp / sizeof sf_arp[0],
        .filter = (struct sock_filter *)sf_arp,
    };
    using_arp_bpf = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sfp_arp,
                               sizeof sfp_arp) != -1;
}

static int arp_open_fd(struct client_state_t *cs)
{
    if (cs->arpFd != -1)
        return 0;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd == -1) {
        log_error("arp: Failed to create socket: %s", strerror(errno));
        goto out;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) == -1) {
        log_error("arp: Failed to set broadcast: %s", strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("arp: Failed to set non-blocking: %s", strerror(errno));
        goto out_fd;
    }
    struct sockaddr_ll saddr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ARP),
        .sll_ifindex = client_config.ifindex,
    };
    if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll)) < 0) {
        log_error("arp: bind failed: %s", strerror(errno));
        goto out_fd;
    }

    cs->arpFd = fd;
    epoll_add(cs, fd);
    arpreply_clear();
    return 0;
out_fd:
    close(fd);
out:
    return -1;
}

static void arp_switch_state(struct client_state_t *cs, arp_state_t state)
{
    arp_state_t prev_state = arpState;
    if (arpState == state || arpState >= AS_MAX)
        return;
    arpState = state;
    if (arpState == AS_NONE) {
        arp_close_fd(cs);
        return;
    }
    if (cs->arpFd == -1) {
        if (arp_open_fd(cs) == -1)
            suicide("arp: Failed to open arpFd when changing state to %u",
                    arpState);
        if (arpState != AS_DEFENSE)
            arp_set_bpf_basic(cs->arpFd);
    }
    if (arpState == AS_DEFENSE) {
        arp_set_bpf_defense(cs, cs->arpFd);
        return;
    }
    if (prev_state == AS_DEFENSE) {
        arp_set_bpf_basic(cs->arpFd);
        return;
    }
}

static int arp_min_close_fd(struct client_state_t *cs)
{
    if (cs->arpFd == -1)
        return 0;
    epoll_del(cs, cs->arpFd);
    close(cs->arpFd);
    cs->arpFd = -1;
    arpState = AS_NONE;
    return 1;
}

int arp_close_fd(struct client_state_t *cs)
{
    arp_min_close_fd(cs);
    for (int i = 0; i < AS_MAX; ++i)
        arp_wake_ts[i] = -1;
    return 1;
}

static int arp_reopen_fd(struct client_state_t *cs)
{
    arp_state_t prev_state = arpState;
    arp_min_close_fd(cs);
    if (arp_open_fd(cs) == -1) {
        log_warning("arp: Failed to re-open fd.  Something is very wrong.");
        log_warning("arp: Client will still run, but functionality will be degraded.");
        return -1;
    }
    arp_switch_state(cs, prev_state);
    return 0;
}

static int arp_send(struct client_state_t *cs, struct arpMsg *arp)
{
    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(addr.sll_addr, client_config.arp, 6);

    if (cs->arpFd == -1) {
        log_warning("arp: Send attempted when no ARP fd is open.");
        return -1;
    }

    if (safe_sendto(cs->arpFd, (const char *)arp, sizeof *arp,
                    0, (struct sockaddr *)&addr, sizeof addr) < 0) {
        log_error("arp: sendto failed: %s", strerror(errno));
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
        .operation = htons(ARPOP_REQUEST), };                           \
    memcpy(arp.h_source, client_config.arp, 6);                         \
    memset(arp.h_dest, 0xff, 6);                                        \
    memcpy(arp.smac, client_config.arp, 6)

// Returns 0 on success, -1 on failure.
static int arp_ping(struct client_state_t *cs, uint32_t test_ip)
{
    BASE_ARPMSG();
    memcpy(arp.sip4, &cs->clientAddr, sizeof cs->clientAddr);
    memcpy(arp.dip4, &test_ip, sizeof test_ip);
    if (arp_send(cs, &arp) == -1)
        return -1;
    arp_send_stats[ASEND_GW_PING].count++;
    arp_send_stats[ASEND_GW_PING].ts = curms();
    return 0;
}

// Returns 0 on success, -1 on failure.
static int arp_ip_anon_ping(struct client_state_t *cs, uint32_t test_ip)
{
    BASE_ARPMSG();
    memcpy(arp.dip4, &test_ip, sizeof test_ip);
    log_line("arp: Probing for hosts that may conflict with our lease...");
    if (arp_send(cs, &arp) == -1)
        return -1;
    arp_send_stats[ASEND_COLLISION_CHECK].count++;
    arp_send_stats[ASEND_COLLISION_CHECK].ts = curms();
    return 0;
}

static int arp_announcement(struct client_state_t *cs)
{
    BASE_ARPMSG();
    memcpy(arp.sip4, &cs->clientAddr, 4);
    memcpy(arp.dip4, &cs->clientAddr, 4);
    if (arp_send(cs, &arp) == -1)
        return -1;
    arp_send_stats[ASEND_ANNOUNCE].count++;
    arp_send_stats[ASEND_ANNOUNCE].ts = curms();
    return 0;
}
#undef BASE_ARPMSG

// Callable from DS_REQUESTING, DS_RENEWING, or DS_REBINDING via an_packet()
int arp_check(struct client_state_t *cs, struct dhcpmsg *packet)
{
    memcpy(&arp_dhcp_packet, packet, sizeof (struct dhcpmsg));
    arp_switch_state(cs, AS_COLLISION_CHECK);
    if (arp_ip_anon_ping(cs, arp_dhcp_packet.yiaddr) == -1)
        return -1;
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_COLLISION_CHECK;
    arp_check_start_ts = arp_send_stats[ASEND_COLLISION_CHECK].ts;
    probe_wait_time = PROBE_WAIT;
    arp_wake_ts[AS_COLLISION_CHECK] = arp_check_start_ts + probe_wait_time;
    return 0;
}

// Callable only from DS_BOUND via state.c:ifup_action().
int arp_gw_check(struct client_state_t *cs)
{
    if (arpState == AS_GW_CHECK)  // Guard against state bounce.
        return 0;
    gw_check_init_pingcount = arp_send_stats[ASEND_GW_PING].count;
    arp_server_has_replied = 0;
    if (arp_ping(cs, cs->serverAddr) == -1)
        return -1;
    if (cs->routerAddr) {
        arp_router_has_replied = 0;
        if (arp_ping(cs, cs->routerAddr) == -1)
            return -1;
    } else
        arp_router_has_replied = 1;
    arp_switch_state(cs, AS_GW_CHECK);
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_BOUND_GW_CHECK;
    arp_wake_ts[AS_GW_CHECK] =
        arp_send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY + 250;
    return 0;
}

// Should only be called from DS_BOUND state.
static int arp_get_gw_hwaddr(struct client_state_t *cs)
{
    if (cs->dhcpState != DS_BOUND)
        log_error("arp_get_gw_hwaddr: called when state != DS_BOUND");
    arp_switch_state(cs, AS_GW_QUERY);
    if (cs->routerAddr)
        log_line("arp: Searching for dhcp server and gw addresses...");
    else
        log_line("arp: Searching for dhcp server address...");
    cs->got_server_arp = 0;
    if (arp_ping(cs, cs->serverAddr) == -1)
        return -1;
    if (cs->routerAddr) {
        cs->got_router_arp = 0;
        if (arp_ping(cs, cs->routerAddr) == -1)
            return -1;
    } else
        cs->got_router_arp = 1;
    arp_wake_ts[AS_GW_QUERY] =
        arp_send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY + 250;
    return 0;
}

static void arp_failed(struct client_state_t *cs)
{
    log_line("arp: Offered address is in use.  Declining.");
    send_decline(cs, arp_dhcp_packet.yiaddr);
    arp_wake_ts[AS_COLLISION_CHECK] = -1;
    reinit_selecting(cs, total_conflicts < MAX_CONFLICTS ?
                     0 : RATE_LIMIT_INTERVAL);
}

static void arp_gw_failed(struct client_state_t *cs)
{
    arp_wake_ts[AS_GW_CHECK] = -1;
    reinit_selecting(cs, 0);
}

static int act_if_arp_gw_failed(struct client_state_t *cs)
{
    if (arp_send_stats[ASEND_GW_PING].count >= gw_check_init_pingcount + 6) {
        if (arp_router_has_replied && !arp_server_has_replied)
            log_line("arp: DHCP server didn't reply.  Getting new lease.");
        else if (!arp_router_has_replied && arp_server_has_replied)
            log_line("arp: Gateway didn't reply.  Getting new lease.");
        else
            log_line("arp: DHCP server and gateway didn't reply.  Getting new lease.");
        arp_gw_failed(cs);
        return 1;
    }
    return 0;
}

void arp_set_defense_mode(struct client_state_t *cs)
{
    arp_switch_state(cs, AS_DEFENSE);
}

void arp_success(struct client_state_t *cs)
{
    char clibuf[INET_ADDRSTRLEN];
    struct in_addr temp_addr = {.s_addr = arp_dhcp_packet.yiaddr};
    inet_ntop(AF_INET, &temp_addr, clibuf, sizeof clibuf);
    log_line("Lease of %s obtained.  Lease time is %ld seconds.",
             clibuf, cs->lease);
    cs->clientAddr = arp_dhcp_packet.yiaddr;
    cs->dhcpState = DS_BOUND;
    cs->init = 0;
    last_conflict_ts = 0;
    arp_wake_ts[AS_COLLISION_CHECK] = -1;
    ifchange_bind(&arp_dhcp_packet);
    if (cs->arpPrevState == DS_RENEWING || cs->arpPrevState == DS_REBINDING) {
        arp_switch_state(cs, AS_DEFENSE);
    } else {
        ssize_t ol;
        uint8_t *od = get_option_data(&arp_dhcp_packet, DHCP_ROUTER, &ol);
        if (ol == 4) {
            memcpy(&cs->routerAddr, od, 4);
        } else
            cs->routerAddr = 0;
        arp_get_gw_hwaddr(cs);
    }
    set_listen_none(cs);
    write_leasefile(temp_addr);
    arp_announcement(cs);
    if (client_config.quit_after_lease)
        exit(EXIT_SUCCESS);
    if (!client_config.foreground)
        background(cs);
}

static void arp_gw_success(struct client_state_t *cs)
{
    log_line("arp: Network seems unchanged.  Resuming normal operation.");
    arp_switch_state(cs, AS_DEFENSE);
    arp_announcement(cs);

    arp_wake_ts[AS_GW_CHECK] = -1;
    cs->dhcpState = cs->arpPrevState;
}

// ARP validation functions that will be performed by the BPF if it is
// installed.
static int arp_validate_bpf(struct arpMsg *am)
{
    if (am->h_proto != htons(ETH_P_ARP)) {
        log_warning("arp: IP header does not indicate ARP protocol");
        return 0;
    }
    if (am->htype != htons(ARPHRD_ETHER)) {
        log_warning("arp: ARP hardware type field invalid");
        return 0;
    }
    if (am->ptype != htons(ETH_P_IP)) {
        log_warning("arp: ARP protocol type field invalid");
        return 0;
    }
    if (am->hlen != 6) {
        log_warning("arp: ARP hardware address length invalid");
        return 0;
    }
    if (am->plen != 4) {
        log_warning("arp: ARP protocol address length invalid");
        return 0;
    }
    return 1;
}

// ARP validation functions that will be performed by the BPF if it is
// installed.
static int arp_validate_bpf_defense(struct client_state_t *cs,
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

static int arp_gen_probe_wait(void)
{
    // This is not a uniform distribution but it doesn't matter here.
    return PROBE_MIN + rand() % (PROBE_MAX - PROBE_MIN);
}

static void arp_defense_timeout(struct client_state_t *cs, long long nowts)
{
    if (arp_wake_ts[AS_DEFENSE] != -1) {
        log_line("arp: Defending our lease IP.");
        arp_announcement(cs);
        arp_wake_ts[AS_DEFENSE] = -1;
    }
}

static void arp_gw_check_timeout(struct client_state_t *cs, long long nowts)
{
    arp_defense_timeout(cs, nowts);

    if (act_if_arp_gw_failed(cs))
        return;
    long long rtts = arp_send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    if (nowts < rtts) {
        arp_wake_ts[AS_GW_CHECK] = rtts;
        return;
    }
    if (!arp_router_has_replied) {
        log_line("arp: Still waiting for gateway to reply to arp ping...");
        if (arp_ping(cs, cs->routerAddr) == -1)
            log_warning("arp: Failed to send ARP ping in retransmission.");
    }
    if (!arp_server_has_replied) {
        log_line("arp: Still waiting for DHCP server to reply to arp ping...");
        if (arp_ping(cs, cs->serverAddr) == -1)
            log_warning("arp: Failed to send ARP ping in retransmission.");
    }
    arp_wake_ts[AS_GW_CHECK] =
        arp_send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
}

static void arp_gw_query_timeout(struct client_state_t *cs, long long nowts)
{
    arp_defense_timeout(cs, nowts);

    long long rtts = arp_send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
    if (nowts < rtts) {
        arp_wake_ts[AS_GW_QUERY] = rtts;
        return;
    }
    if (!cs->got_router_arp) {
        log_line("arp: Still looking for gateway hardware address...");
        if (arp_ping(cs, cs->routerAddr) == -1)
            log_warning("arp: Failed to send ARP ping in retransmission.");
    }
    if (!cs->got_server_arp) {
        log_line("arp: Still looking for DHCP server hardware address...");
        if (arp_ping(cs, cs->serverAddr) == -1)
            log_warning("arp: Failed to send ARP ping in retransmission.");
    }
    arp_wake_ts[AS_GW_QUERY] =
        arp_send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
}

static void arp_collision_timeout(struct client_state_t *cs, long long nowts)
{
    arp_defense_timeout(cs, nowts);

    if (nowts >= arp_check_start_ts + ANNOUNCE_WAIT ||
        arp_send_stats[ASEND_COLLISION_CHECK].count >= PROBE_NUM) {
        arp_success(cs);
        return;
    }
    long long rtts = arp_send_stats[ASEND_COLLISION_CHECK].ts +
        probe_wait_time;
    if (nowts < rtts) {
        arp_wake_ts[AS_COLLISION_CHECK] = rtts;
        return;
    }
    if (arp_ip_anon_ping(cs, arp_dhcp_packet.yiaddr) == -1)
        log_warning("arp: Failed to send ARP ping in retransmission.");
    probe_wait_time = arp_gen_probe_wait();
    arp_wake_ts[AS_COLLISION_CHECK] =
        arp_send_stats[ASEND_COLLISION_CHECK].ts + probe_wait_time;
}

static void arp_do_defense(struct client_state_t *cs)
{
    // Even though the BPF will usually catch this case, sometimes there are
    // packets still in the socket buffer that arrived before the defense
    // BPF was installed, so it's necessary to check here.
    if (!arp_validate_bpf_defense(cs, &arpreply))
        return;

    log_line("arp: Detected a peer attempting to use our IP!");
    long long nowts = curms();
    arp_wake_ts[AS_DEFENSE] = -1;
    if (!last_conflict_ts ||
        nowts - last_conflict_ts < DEFEND_INTERVAL) {
        log_line("arp: Defending our lease IP.");
        arp_announcement(cs);
    } else if (!arp_relentless_def) {
        log_line("arp: Conflicting peer is persistent.  Requesting new lease.");
        send_release(cs);
        reinit_selecting(cs, 0);
    } else {
        arp_wake_ts[AS_DEFENSE] =
            arp_send_stats[ASEND_ANNOUNCE].ts + DEFEND_INTERVAL;
    }
    total_conflicts++;
    last_conflict_ts = nowts;
}

static void arp_do_gw_query_done(struct client_state_t *cs)
{
    arp_wake_ts[AS_GW_QUERY] = -1;
    arp_switch_state(cs, AS_DEFENSE);
    arp_announcement(cs);  // Do a second announcement.
}

static void arp_do_gw_query(struct client_state_t *cs)
{
    if (!arp_is_query_reply(&arpreply)) {
        arp_do_defense(cs);
        return;
    }
    if (!memcmp(arpreply.sip4, &cs->routerAddr, 4)) {
        memcpy(cs->routerArp, arpreply.smac, 6);
        log_line("arp: Gateway hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                 cs->routerArp[0], cs->routerArp[1],
                 cs->routerArp[2], cs->routerArp[3],
                 cs->routerArp[4], cs->routerArp[5]);
        cs->got_router_arp = 1;
        if (cs->routerAddr == cs->serverAddr)
            goto server_is_router;
        if (cs->got_server_arp)
            arp_do_gw_query_done(cs);
        return;
    }
    if (!memcmp(arpreply.sip4, &cs->serverAddr, 4)) {
server_is_router:
        memcpy(cs->serverArp, arpreply.smac, 6);
        log_line("arp: DHCP Server hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                 cs->serverArp[0], cs->serverArp[1],
                 cs->serverArp[2], cs->serverArp[3],
                 cs->serverArp[4], cs->serverArp[5]);
        cs->got_server_arp = 1;
        if (cs->got_router_arp)
            arp_do_gw_query_done(cs);
        return;
    }
    arp_do_defense(cs);
}

static void arp_do_collision_check(struct client_state_t *cs)
{
    if (!arp_is_query_reply(&arpreply))
        return;
    // If this packet was sent from our lease IP, and does not have a
    // MAC address matching our own (the latter check guards against stupid
    // hubs or repeaters), then it's a conflict and thus a failure.
    if (!memcmp(arpreply.sip4, &arp_dhcp_packet.yiaddr, 4) &&
        !memcmp(client_config.arp, arpreply.smac, 6)) {
        total_conflicts++;
        arp_failed(cs);
    }
}

static void arp_do_gw_check(struct client_state_t *cs)
{
    if (!arp_is_query_reply(&arpreply))
        return;
    if (!memcmp(arpreply.sip4, &cs->routerAddr, 4)) {
        // Success only if the router/gw MAC matches stored value
        if (!memcmp(cs->routerArp, arpreply.smac, 6)) {
            arp_router_has_replied = 1;
            if (cs->routerAddr == cs->serverAddr)
                goto server_is_router;
            if (arp_server_has_replied)
                arp_gw_success(cs);
        } else {
            log_line("arp: Gateway is different.  Getting a new lease.");
            arp_gw_failed(cs);
        }
        return;
    }
    if (!memcmp(arpreply.sip4, &cs->serverAddr, 4)) {
server_is_router:
        // Success only if the server MAC matches stored value
        if (!memcmp(cs->serverArp, arpreply.smac, 6)) {
            arp_server_has_replied = 1;
            if (arp_router_has_replied)
                arp_gw_success(cs);
        } else {
            log_line("arp: DHCP server is different.  Getting a new lease.");
            arp_gw_failed(cs);
        }
    }
}

static void arp_do_invalid(struct client_state_t *cs)
{
    log_error("handle_arp_response: called in invalid state %u", arpState);
    arp_close_fd(cs);
}

typedef struct {
    void (*packet_fn)(struct client_state_t *cs);
    void (*timeout_fn)(struct client_state_t *cs, long long nowts);
} arp_state_fn_t;

static const arp_state_fn_t arp_states[] = {
    { arp_do_invalid, 0 }, // AS_NONE
    { arp_do_collision_check, arp_collision_timeout }, // AS_COLLISION_CHECK
    { arp_do_gw_check, arp_gw_check_timeout }, // AS_GW_CHECK
    { arp_do_gw_query, arp_gw_query_timeout }, // AS_GW_QUERY
    { arp_do_defense, arp_defense_timeout }, // AS_DEFENSE
    { arp_do_invalid, 0 }, // AS_MAX
};

void handle_arp_response(struct client_state_t *cs)
{
    int r = 0;
    if (arpreply_offset < sizeof arpreply) {
        r = safe_read(cs->arpFd, (char *)&arpreply + arpreply_offset,
                          sizeof arpreply - arpreply_offset);
        if (r < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
            log_error("arp: ARP response read failed: %s", strerror(errno));
            switch (arpState) {
                case AS_COLLISION_CHECK: arp_failed(cs); break;
                case AS_GW_CHECK: arp_gw_failed(cs); break;
                default:
                    arp_reopen_fd(cs);
                    break;
            }
        } else
            arpreply_offset += r;
    }

    if (r <= 0) {
        handle_arp_timeout(cs, curms());
        return;
    }

    if (arpreply_offset < ARP_MSG_SIZE)
        return;

    // Emulate the BPF filters if they are not in use.
    if (!using_arp_bpf && (!arp_validate_bpf(&arpreply) ||
                           (arpState == AS_DEFENSE &&
                            !arp_validate_bpf_defense(cs, &arpreply)))) {
        arpreply_clear();
        return;
    }

    if (arp_states[arpState].packet_fn)
        arp_states[arpState].packet_fn(cs);
    arpreply_clear();
}

// Perform retransmission if necessary.
void handle_arp_timeout(struct client_state_t *cs, long long nowts)
{
    if (arp_states[arpState].timeout_fn)
        arp_states[arpState].timeout_fn(cs, nowts);
}

long long arp_get_wake_ts(void)
{
    long long mt = -1;
    for (int i = 0; i < AS_MAX; ++i) {
        if (arp_wake_ts[i] == -1)
            continue;
        if (mt == -1 || mt > arp_wake_ts[i])
            mt = arp_wake_ts[i];
    }
    return mt;
}

