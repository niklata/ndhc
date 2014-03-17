/* state.c - high level DHCP state machine
 *
 * Copyright (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "state.h"
#include "ifchange.h"
#include "arp.h"
#include "options.h"
#include "log.h"
#include "ndhc.h"
#include "sys.h"
#include "random.h"

static void selecting_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                             uint8_t msgtype);
static void an_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                      uint8_t msgtype);
static void selecting_timeout(struct client_state_t *cs, long long nowts);
static void requesting_timeout(struct client_state_t *cs, long long nowts);
static void bound_timeout(struct client_state_t *cs, long long nowts);
static void renewing_timeout(struct client_state_t *cs, long long nowts);
static void rebinding_timeout(struct client_state_t *cs, long long nowts);
static void released_timeout(struct client_state_t *cs, long long nowts);
static void xmit_release(struct client_state_t *cs);
static void print_release(struct client_state_t *cs);
static void frenew(struct client_state_t *cs);

typedef struct {
    void (*packet_fn)(struct client_state_t *cs, struct dhcpmsg *packet,
                      uint8_t msgtype);
    void (*timeout_fn)(struct client_state_t *cs, long long nowts);
    void (*force_renew_fn)(struct client_state_t *cs);
    void (*force_release_fn)(struct client_state_t *cs);
} dhcp_state_t;

static const dhcp_state_t dhcp_states[] = {
    { selecting_packet, selecting_timeout, 0, print_release}, // SELECTING
    { an_packet, requesting_timeout, 0, print_release},       // REQUESTING
    { 0, bound_timeout, frenew, xmit_release},                // BOUND
    { an_packet, renewing_timeout, 0, xmit_release},          // RENEWING
    { an_packet, rebinding_timeout, 0, xmit_release},         // REBINDING
    { 0, 0, 0, xmit_release},                                 // BOUND_GW_CHECK
    { 0, 0, 0, xmit_release},                                // COLLISION_CHECK
    { 0, released_timeout, frenew, 0},                       // RELEASED
    { 0, 0, 0, 0},                                           // NUM_STATES
};

static unsigned int num_dhcp_requests;
static long long dhcp_wake_ts = -1;

static int delay_timeout(size_t numpackets)
{
    int to = 64;
    char tot[] = { 4, 8, 16, 32, 64 };
    if (numpackets < sizeof tot)
        to = tot[numpackets];
    return to * 1000 + rand() % 1000;
}

static void reinit_shared_deconfig(struct client_state_t *cs)
{
    ifchange_deconfig(cs);
    arp_close_fd(cs);
    cs->clientAddr = 0;
    num_dhcp_requests = 0;
    cs->got_router_arp = 0;
    cs->got_server_arp = 0;
    memset(&cs->routerArp, 0, sizeof cs->routerArp);
    memset(&cs->serverArp, 0, sizeof cs->serverArp);
    arp_reset_send_stats();
}

void reinit_selecting(struct client_state_t *cs, int timeout)
{
    reinit_shared_deconfig(cs);
    cs->dhcpState = DS_SELECTING;
    dhcp_wake_ts = curms() + timeout;
    set_listen_raw(cs);
}

static void set_released(struct client_state_t *cs)
{
    reinit_shared_deconfig(cs);
    cs->dhcpState = DS_RELEASED;
    dhcp_wake_ts = -1;
    set_listen_none(cs);
}

// Triggered after a DHCP lease request packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of request retransmits, then send another packet and wait
// again.  Otherwise, return to the DHCP initialization state.
static void requesting_timeout(struct client_state_t *cs, long long nowts)
{
    if (num_dhcp_requests < 5) {
        send_selecting(cs);
        dhcp_wake_ts = nowts + delay_timeout(num_dhcp_requests);
        num_dhcp_requests++;
    } else
        reinit_selecting(cs, 0);
}

// Triggered when the lease has been held for a significant fraction of its
// total time, and it is time to renew the lease so that it is not lost.
static void bound_timeout(struct client_state_t *cs, long long nowts)
{
    long long rnt = cs->leaseStartTime + cs->renewTime * 1000;
    if (nowts < rnt) {
        dhcp_wake_ts = rnt;
        return;
    }
    cs->dhcpState = DS_RENEWING;
    set_listen_cooked(cs);
    renewing_timeout(cs, nowts);
}

// Triggered when a DHCP renew request has been sent and no reply has been
// received within the response wait time.  This function is also directly
// called by bound_timeout() when it is time to renew a lease before it
// expires.  Check to see if the lease is still valid, and if it is, send
// a unicast DHCP renew packet.  If it is not, then change to the REBINDING
// state to send broadcast queries.
static void renewing_timeout(struct client_state_t *cs, long long nowts)
{
    long long rbt = cs->leaseStartTime + cs->rebindTime * 1000;
    if (nowts < rbt) {
        if (rbt - nowts < 30000) {
            dhcp_wake_ts = rbt;
            return;
        }
        send_renew(cs);
        dhcp_wake_ts = nowts + ((rbt - nowts) / 2);
    } else {
        cs->dhcpState = DS_REBINDING;
        rebinding_timeout(cs, nowts);
    }
}

// Triggered when a DHCP rebind request has been sent and no reply has been
// received within the response wait time.  Check to see if the lease is still
// valid, and if it is, send a broadcast DHCP renew packet.  If it is not, then
// change to the SELECTING state to get a new lease.
static void rebinding_timeout(struct client_state_t *cs, long long nowts)
{
    long long elt = cs->leaseStartTime + cs->lease * 1000;
    if (nowts < elt) {
        if (elt - nowts < 30000) {
            dhcp_wake_ts = elt;
            return;
        }
        send_rebind(cs);
        dhcp_wake_ts = nowts + ((elt - nowts) / 2);
    } else {
        log_line("Lease expired.  Searching for a new lease...");
        reinit_selecting(cs, 0);
    }
}

static void released_timeout(struct client_state_t *cs, long long nowts)
{
    (void)cs;
    (void)nowts;
    dhcp_wake_ts = -1;
}

static int validate_serverid(struct client_state_t *cs, struct dhcpmsg *packet,
                             char *typemsg)
{
    int found;
    uint32_t sid = get_option_serverid(packet, &found);
    if (!found) {
        log_line("Received %s with no server id.  Ignoring it.");
        return 0;
    }
    if (cs->serverAddr != sid) {
        char svrbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(struct in_addr){.s_addr=sid},
                  svrbuf, sizeof svrbuf);
        log_line("Received %s with an unexpected server id: %s.  Ignoring it.",
                 typemsg, svrbuf);
        return 0;
    }
    return 1;
}

// Can transition to DS_BOUND or DS_SELECTING.
static void an_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                      uint8_t msgtype)
{
    if (msgtype == DHCPACK) {
        if (!validate_serverid(cs, packet, "a DHCP ACK"))
            return;
        cs->lease = get_option_leasetime(packet);
        cs->leaseStartTime = curms();
        if (!cs->lease) {
            log_line("No lease time received, assuming 1h.");
            cs->lease = 60 * 60;
        } else {
            if (cs->lease < 60) {
                log_warning("Server sent lease of <1m.  Forcing lease to 1m.");
                cs->lease = 60;
            }
        }
        // Always use RFC2131 'default' values.  It's not worth validating
        // the remote server values, if they even exist, for sanity.
        cs->renewTime = cs->lease >> 1;
        cs->rebindTime = (cs->lease >> 3) * 0x7; // * 0.875
        dhcp_wake_ts = cs->leaseStartTime + cs->renewTime * 1000;

        // Only check if we are either in the REQUESTING state, or if we
        // have received a lease with a different IP than what we had before.
        if (cs->dhcpState == DS_REQUESTING ||
            memcmp(&packet->yiaddr, &cs->clientAddr, 4)) {
            char clibuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->clientAddr},
                      clibuf, sizeof clibuf);
            log_line("Accepted a firm offer for %s.  Validating...", clibuf);
            if (arp_check(cs, packet) == -1) {
                log_warning("Failed to make arp socket.  Searching for new lease...");
                reinit_selecting(cs, 3000);
            }
        } else {
            log_line("Lease refreshed to %u seconds.", cs->lease);
            cs->dhcpState = DS_BOUND;
            arp_set_defense_mode(cs);
            set_listen_none(cs);
        }

    } else if (msgtype == DHCPNAK) {
        if (!validate_serverid(cs, packet, "a DHCP NAK"))
            return;
        log_line("Our request was rejected.  Searching for a new lease...");
        reinit_selecting(cs, 3000);
    }
}

static void selecting_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                             uint8_t msgtype)
{
    if (msgtype == DHCPOFFER) {
        int found;
        uint32_t sid = get_option_serverid(packet, &found);
        if (found) {
            char clibuf[INET_ADDRSTRLEN];
            char svrbuf[INET_ADDRSTRLEN];
            cs->serverAddr = sid;
            cs->xid = packet->xid;
            cs->clientAddr = packet->yiaddr;
            cs->dhcpState = DS_REQUESTING;
            dhcp_wake_ts = curms();
            num_dhcp_requests = 0;
            inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->clientAddr},
                      clibuf, sizeof clibuf);
            inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->serverAddr},
                      svrbuf, sizeof svrbuf);
            log_line("Received an offer of %s from server %s.",
                     clibuf, svrbuf);
        } else {
            log_line("Invalid offer received: it didn't have a server id.");
        }
    }
}

// Triggered after a DHCP discover packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of discover retransmits, then send another packet and wait
// again.  Otherwise, background or fail.
static void selecting_timeout(struct client_state_t *cs, long long nowts)
{
    if (cs->init && num_dhcp_requests >= 2) {
        if (client_config.background_if_no_lease) {
            log_line("No lease, going to background.");
            cs->init = 0;
            background();
        } else if (client_config.abort_if_no_lease) {
            log_line("No lease, failing.");
            exit(EXIT_FAILURE);
        }
    }
    if (num_dhcp_requests == 0)
        cs->xid = nk_random_u32(&cs->rnd32_state);
    send_discover(cs);
    dhcp_wake_ts = nowts + delay_timeout(num_dhcp_requests);
    num_dhcp_requests++;
}

static void xmit_release(struct client_state_t *cs)
{
    char clibuf[INET_ADDRSTRLEN];
    char svrbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->clientAddr},
              clibuf, sizeof clibuf);
    inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->serverAddr},
              svrbuf, sizeof svrbuf);
    log_line("Unicasting a release of %s to %s.", clibuf, svrbuf);
    send_release(cs);
    print_release(cs);
}

static void print_release(struct client_state_t *cs)
{
    log_line("ndhc going to sleep.  Wake it by sending a SIGUSR1.");
    set_released(cs);
}

static void frenew(struct client_state_t *cs)
{
    if (cs->dhcpState == DS_BOUND) {
        log_line("Forcing a DHCP renew...");
        cs->dhcpState = DS_RENEWING;
        set_listen_cooked(cs);
        send_renew(cs);
    } else if (cs->dhcpState == DS_RELEASED)
        reinit_selecting(cs, 0);
}

void ifup_action(struct client_state_t *cs)
{
    // If we have a lease, check to see if our gateway is still valid via ARP.
    // If it fails, state -> SELECTING.
    if (cs->routerAddr && (cs->dhcpState == DS_BOUND ||
                           cs->dhcpState == DS_RENEWING ||
                           cs->dhcpState == DS_REBINDING)) {
        if (arp_gw_check(cs) != -1) {
            log_line("nl: %s is back.  Revalidating lease...",
                     client_config.interface);
            return;
        } else
            log_warning("nl: arp_gw_check could not make arp socket.");
    }
    if (cs->dhcpState == DS_SELECTING)
        return;
    log_line("nl: %s is back.  Searching for new lease...",
             client_config.interface);
    reinit_selecting(cs, 0);
}

void ifdown_action(struct client_state_t *cs)
{
    log_line("nl: %s shut down.  Going to sleep.", client_config.interface);
    set_released(cs);
}

void ifnocarrier_action(struct client_state_t *cs)
{
    (void)cs;
    log_line("nl: %s carrier down.", client_config.interface);
}

void packet_action(struct client_state_t *cs, struct dhcpmsg *packet,
                   uint8_t msgtype)
{
    if (dhcp_states[cs->dhcpState].packet_fn)
        dhcp_states[cs->dhcpState].packet_fn(cs, packet, msgtype);
}

void timeout_action(struct client_state_t *cs, long long nowts)
{
    handle_arp_timeout(cs, nowts);
    if (dhcp_states[cs->dhcpState].timeout_fn)
        dhcp_states[cs->dhcpState].timeout_fn(cs, nowts);
}

void force_renew_action(struct client_state_t *cs)
{
    if (dhcp_states[cs->dhcpState].force_renew_fn)
        dhcp_states[cs->dhcpState].force_renew_fn(cs);
}

void force_release_action(struct client_state_t *cs)
{
    if (dhcp_states[cs->dhcpState].force_release_fn)
        dhcp_states[cs->dhcpState].force_release_fn(cs);
}

long long dhcp_get_wake_ts(void)
{
    return dhcp_wake_ts;
}

