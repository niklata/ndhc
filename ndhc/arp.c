/* arp.c - arp ping checking
 * Time-stamp: <2011-07-06 09:18:58 njk>
 *
 * Copyright 2010-2011 Nicholas J. Kain <njkain@gmail.com>
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
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
static long long pending_def_ts; // TS of the upcoming defense ARP send.
static int def_old_oldTimeout; // Old value of cs->oldTimeout.

static int gw_check_init_pingcount; // Initial count of ASEND_GW_PING when
                                    // AS_GW_CHECK was entered.

static long long collision_check_init_ts; // Initial ts when COLLISION_CHECK
                                          // was entered.
static uint16_t probe_wait_time; // Time to wait for a COLLISION_CHECK reply.
static unsigned int total_conflicts; // Total number of address conflicts on
                                     // the interface.  Never decreases.

static struct dhcpmsg arp_dhcp_packet; // Used only for AS_COLLISION_CHECK

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
        log_error("arp: failed to create socket: %s", strerror(errno));
        goto out;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) == -1) {
        log_error("arp: failed to set broadcast: %s", strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("arp: failed to set non-blocking: %s", strerror(errno));
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
            suicide("arp: failed to open arpFd when changing state to %u",
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

int arp_close_fd(struct client_state_t *cs)
{
    if (cs->arpFd == -1)
        return 0;
    epoll_del(cs, cs->arpFd);
    close(cs->arpFd);
    cs->arpFd = -1;
    arpState = AS_NONE;
    return 1;
}

static int arp_reopen_fd(struct client_state_t *cs)
{
    arp_state_t prev_state = arpState;
    arp_close_fd(cs);
    if (arp_open_fd(cs) == -1) {
        log_warning("arp_reopen_fd: Failed to open.  Something is very wrong.");
        log_warning("arp_reopen_fd: Client will still run, but functionality will be degraded.");
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
        log_warning("arp_send: Send attempted when no ARP fd is open.");
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
    log_line("arp: Probing for hosts that may conflict with our lease...");
    if (arp_ip_anon_ping(cs, arp_dhcp_packet.yiaddr) == -1)
        return -1;
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_COLLISION_CHECK;
    collision_check_init_ts = arp_send_stats[ASEND_COLLISION_CHECK].ts;
    cs->timeout = probe_wait_time = PROBE_WAIT;
    return 0;
}

// Callable only from DS_BOUND via state.c:ifup_action().
int arp_gw_check(struct client_state_t *cs)
{
    if (arpState == AS_GW_CHECK)  // Guard against state bounce.
        return 0;
    gw_check_init_pingcount = arp_send_stats[ASEND_GW_PING].count;
    if (arp_ping(cs, cs->routerAddr) == -1)
        return -1;
    arp_switch_state(cs, AS_GW_CHECK);
    cs->arpPrevState = cs->dhcpState;
    cs->dhcpState = DS_BOUND_GW_CHECK;
    cs->oldTimeout = cs->timeout;
    cs->timeout = ARP_RETRANS_DELAY + 250;
    return 0;
}

static int arp_get_gw_hwaddr(struct client_state_t *cs)
{
    if (cs->dhcpState != DS_BOUND)
        log_error("arp_get_gw_hwaddr: called when state != DS_BOUND");
    arp_switch_state(cs, AS_GW_QUERY);
    log_line("arp: Searching for gw address...");
    if (arp_ping(cs, cs->routerAddr) == -1)
        return -1;
    cs->oldTimeout = cs->timeout;
    cs->timeout = ARP_RETRANS_DELAY + 250;
    return 0;
}

static void arp_failed(struct client_state_t *cs)
{
    log_line("arp: Offered address is in use -- declining");
    send_decline(cs, arp_dhcp_packet.yiaddr);
    reinit_selecting(cs, total_conflicts < MAX_CONFLICTS ?
                     0 : RATE_LIMIT_INTERVAL);
}

static void arp_gw_failed(struct client_state_t *cs)
{
    log_line("arp: Gateway appears to have changed, getting new lease.");
    cs->oldTimeout = 0;
    reinit_selecting(cs, 0);
}

static int act_if_arp_gw_failed(struct client_state_t *cs)
{
    if (arp_send_stats[ASEND_GW_PING].count >= gw_check_init_pingcount + 3) {
        arp_gw_failed(cs);
        return 1;
    }
    return 0;
}

void arp_success(struct client_state_t *cs)
{
    cs->timeout = (cs->renewTime * 1000) - (curms() - cs->leaseStartTime);

    struct in_addr temp_addr = {.s_addr = arp_dhcp_packet.yiaddr};
    log_line("arp: Lease of %s obtained, lease time %ld",
             inet_ntoa(temp_addr), cs->lease);
    cs->clientAddr = arp_dhcp_packet.yiaddr;
    cs->dhcpState = DS_BOUND;
    cs->init = 0;
    last_conflict_ts = 0;
    pending_def_ts = 0;
    def_old_oldTimeout = 0;
    ifchange_bind(&arp_dhcp_packet);
    if (cs->arpPrevState == DS_RENEWING || cs->arpPrevState == DS_REBINDING) {
        arp_switch_state(cs, AS_DEFENSE);
    } else {
        ssize_t ol;
        uint8_t *od = get_option_data(&arp_dhcp_packet, DHCP_ROUTER, &ol);
        if (ol == 4) {
            memcpy(&cs->routerAddr, od, 4);
            arp_get_gw_hwaddr(cs);
        } else
            arp_switch_state(cs, AS_DEFENSE);
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
    log_line("arp: Gateway seems unchanged");
    arp_switch_state(cs, AS_DEFENSE);
    arp_announcement(cs);

    cs->timeout = cs->oldTimeout;
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

// Perform retransmission if necessary.
void arp_retransmit(struct client_state_t *cs)
{
    if (pending_def_ts) {
        log_line("arp: Defending our lease IP.");
        pending_def_ts = 0;
        arp_announcement(cs);
        if (def_old_oldTimeout) {
            cs->timeout = cs->oldTimeout;
            cs->oldTimeout = def_old_oldTimeout;
            def_old_oldTimeout = 0;
        }
    }
    if (arpState == AS_GW_CHECK || arpState == AS_GW_QUERY) {
        if (arpState == AS_GW_CHECK && act_if_arp_gw_failed(cs))
            return;
        long long cms = curms();
        long long rtts = arp_send_stats[ASEND_GW_PING].ts + ARP_RETRANS_DELAY;
        if (cms < rtts) {
            cs->timeout = rtts - cms;
            return;
        }
        log_line(arpState == AS_GW_CHECK ?
                 "arp: Still waiting for gateway to reply to arp ping..." :
                 "arp: Still looking for gateway hardware address...");
        if (arp_ping(cs, cs->routerAddr) == -1)
            log_warning("arp: Failed to send ARP ping in retransmission.");
        cs->timeout = ARP_RETRANS_DELAY;
        return;
    }
    if (arpState == AS_COLLISION_CHECK) {
        long long cms = curms();
        if (cms >= collision_check_init_ts + ANNOUNCE_WAIT ||
            arp_send_stats[ASEND_COLLISION_CHECK].count >= PROBE_NUM) {
            arp_success(cs);
            return;
        }
        long long rtts = arp_send_stats[ASEND_COLLISION_CHECK].ts +
            probe_wait_time;
        if (cms < rtts) {
            cs->timeout = rtts - cms;
            return;
        }
        log_line("arp: Probing for hosts that may conflict with our lease...");
        if (arp_ip_anon_ping(cs, arp_dhcp_packet.yiaddr) == -1)
            log_warning("arp: Failed to send ARP ping in retransmission.");
        cs->timeout = probe_wait_time = arp_gen_probe_wait();
        return;
    }
}

static void arp_do_defense(struct client_state_t *cs)
{
    log_line("arp: detected a peer attempting to use our IP!");
    long long cur_conflict_ts = curms();
    if (!last_conflict_ts ||
        cur_conflict_ts - last_conflict_ts < DEFEND_INTERVAL) {
        log_line("arp: Defending our lease IP.");
        arp_announcement(cs);
    } else if (!arp_relentless_def) {
        log_line("arp: Conflicting peer is persistent.  Requesting new lease.");
        send_release(cs);
        reinit_selecting(cs, 0);
    } else {
        pending_def_ts = arp_send_stats[ASEND_ANNOUNCE].ts + DEFEND_INTERVAL;
        long long def_xmit_ts = pending_def_ts - cur_conflict_ts;
        if (!cs->timeout || cs->timeout > def_xmit_ts) {
            def_old_oldTimeout = cs->oldTimeout;
            cs->oldTimeout = cs->timeout;
            cs->timeout = def_xmit_ts;
        }
    }
    total_conflicts++;
    last_conflict_ts = cur_conflict_ts;
}

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
        arp_retransmit(cs);
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

    switch (arpState) {
    case AS_COLLISION_CHECK:
        if (!arp_is_query_reply(&arpreply))
            break;
        // If this packet was sent from our lease IP, and does not have a
        // MAC address matching our own (the latter check guards against stupid
        // hubs or repeaters), then it's a conflict and thus a failure.
        if (!memcmp(arpreply.sip4, &arp_dhcp_packet.yiaddr, 4) &&
            !memcmp(client_config.arp, arpreply.smac, 6)) {
            total_conflicts++;
            arp_failed(cs);
        }
        break;
    case AS_GW_CHECK:
        if (!arp_is_query_reply(&arpreply))
            break;
        if (!memcmp(arpreply.sip4, &cs->routerAddr, 4)) {
            // Success only if the router/gw MAC matches stored value
            if (!memcmp(cs->routerArp, arpreply.smac, 6))
                arp_gw_success(cs);
            else
                arp_gw_failed(cs);
        }
        break;
    case AS_GW_QUERY:
        if (arp_is_query_reply(&arpreply) &&
            !memcmp(arpreply.sip4, &cs->routerAddr, 4)) {
            cs->timeout = cs->oldTimeout;
            memcpy(cs->routerArp, arpreply.smac, 6);
            log_line("arp: Gateway hardware address %02x:%02x:%02x:%02x:%02x:%02x",
                     cs->routerArp[0], cs->routerArp[1],
                     cs->routerArp[2], cs->routerArp[3],
                     cs->routerArp[4], cs->routerArp[5]);
            arp_switch_state(cs, AS_DEFENSE);
            arp_announcement(cs);  // Do a second announcement.
            break;
        }
        if (!arp_validate_bpf_defense(cs, &arpreply))
            break;
    case AS_DEFENSE:
        arp_do_defense(cs);
        break;
    default:
        log_error("handle_arp_response: called in invalid state %u", arpState);
        arp_close_fd(cs);
    }
    arpreply_clear();
}
