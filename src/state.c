/* state.c - high level DHCP state machine
 *
 * Copyright 2011-2018 Nicholas J. Kain <njkain at gmail dot com>
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
#include "nk/log.h"
#include "nk/random.h"

#include "state.h"
#include "ifchange.h"
#include "arp.h"
#include "options.h"
#include "ndhc.h"
#include "sys.h"
#include "netlink.h"
#include "coroutine.h"

#define SEL_SUCCESS 0
#define SEL_FAIL -1

#define REQ_SUCCESS 0
#define REQ_TIMEOUT -1
#define REQ_FAIL -2

#define ANP_SUCCESS 0
#define ANP_IGNORE -1
#define ANP_REJECTED -2
#define ANP_CHECK_IP -3

#define BTO_WAIT 0
#define BTO_EXPIRED -1
#define BTO_HARDFAIL -2

#define IFUP_REVALIDATE 0
#define IFUP_NEWLEASE 1
#define IFUP_FAIL -1

static int delay_timeout(struct client_state_t cs[static 1], size_t numpackets)
{
    int to = 64;
    char tot[] = { 4, 8, 16, 32, 64 };
    if (numpackets < sizeof tot)
        to = tot[numpackets];
    // Distribution is a bit biased but it doesn't really matter.
    return to * 1000 + (int)(nk_random_u32(&cs->rnd_state) % 1000);
}

static void reinit_shared_deconfig(struct client_state_t cs[static 1])
{
    cs->clientAddr = 0;
    cs->num_dhcp_requests = 0;
    cs->server_arp_sent = 0;
    cs->server_arp_state = ARP_QUERY;
    cs->got_router_arp = false;
    cs->check_fingerprint = false;
    cs->sent_gw_query = false;
    cs->sent_first_announce = false;
    cs->sent_second_announce = false;
    cs->init_fingerprint_inprogress = false;
    memset(&cs->routerArp, 0, sizeof cs->routerArp);
    memset(&cs->serverArp, 0, sizeof cs->serverArp);
    arp_reset_state(cs);
}

static void reinit_selecting(struct client_state_t cs[static 1], int timeout)
{
    reinit_shared_deconfig(cs);
    cs->dhcp_wake_ts = curms() + timeout;
    start_dhcp_listen(cs);
}

// Triggered after a DHCP lease request packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of request retransmits, then send another packet and wait
// again.  Otherwise, return to the DHCP initialization state.
static int requesting_timeout(struct client_state_t cs[static 1],
                               long long nowts)
{
    if (cs->num_dhcp_requests >= 5) {
        reinit_selecting(cs, 0);
        return REQ_TIMEOUT;
    }
    if (send_selecting(cs) < 0) {
        log_warning("%s: Failed to send a selecting request packet.",
                    client_config.interface);
        return REQ_FAIL;
    }
    cs->dhcp_wake_ts = nowts + delay_timeout(cs, cs->num_dhcp_requests);
    cs->num_dhcp_requests++;
    return REQ_SUCCESS;
}

static bool is_renewing(struct client_state_t cs[static 1], long long nowts)
{
    long long rnt = cs->leaseStartTime + cs->renewTime * 1000;
    return nowts >= rnt;
}

static bool is_rebinding(struct client_state_t cs[static 1], long long nowts)
{
    long long rbt = cs->leaseStartTime + cs->rebindTime * 1000;
    return nowts >= rbt;
}

// Triggered when a DHCP rebind request has been sent and no reply has been
// received within the response wait time.  Check to see if the lease is still
// valid, and if it is, send a broadcast DHCP renew packet.  If it is not, then
// change to the SELECTING state to get a new lease.
static int rebinding_timeout(struct client_state_t cs[static 1],
                              long long nowts)
{
    long long elt = cs->leaseStartTime + cs->lease * 1000;
    if (nowts >= elt) {
        log_line("%s: Lease expired.  Searching for a new lease...",
                 client_config.interface);
        reinit_selecting(cs, 0);
        return BTO_EXPIRED;
    }
    start_dhcp_listen(cs);
    if (send_rebind(cs) < 0) {
        log_warning("%s: Failed to send a rebind request packet.",
                    client_config.interface);
        return BTO_HARDFAIL;
    }
    long long ts0 = nowts + (50 + nk_random_u32(&cs->rnd_state) % 20) * 1000;
    cs->dhcp_wake_ts = ts0 < elt ? ts0 : elt;
    return BTO_WAIT;
}

// Triggered when a DHCP renew request has been sent and no reply has been
// received within the response wait time.  This function is also directly
// called by bound_timeout() when it is time to renew a lease before it
// expires.  Check to see if the lease is still valid, and if it is, send
// a unicast DHCP renew packet.  If it is not, then change to the REBINDING
// state to send broadcast queries.
static int renewing_timeout(struct client_state_t cs[static 1],
                             long long nowts)
{
    long long rbt = cs->leaseStartTime + cs->rebindTime * 1000;
    if (nowts >= rbt)
        return rebinding_timeout(cs, nowts);
    start_dhcp_listen(cs);
    if (send_renew(cs) < 0) {
        log_warning("%s: Failed to send a renew request packet.",
                    client_config.interface);
        return BTO_HARDFAIL;
    }
    long long ts0 = nowts + (50 + nk_random_u32(&cs->rnd_state) % 20) * 1000;
    cs->dhcp_wake_ts = ts0 < rbt ? ts0 : rbt;
    return BTO_WAIT;
}

// Triggered when the lease has been held for a significant fraction of its
// total time, and it is time to renew the lease so that it is not lost.
static int bound_timeout(struct client_state_t cs[static 1], long long nowts)
{
    long long rnt = cs->leaseStartTime + cs->renewTime * 1000;
    if (nowts < rnt) {
        cs->dhcp_wake_ts = rnt;
        return BTO_WAIT;
    }
    return renewing_timeout(cs, nowts);
}

static int validate_serverid(struct client_state_t cs[static 1],
                             struct dhcpmsg packet[static 1],
                             const char typemsg[static 1])
{
    int found;
    uint32_t sid = get_option_serverid(packet, &found);
    if (!found) {
        log_line("%s: Received %s with no server id.  Ignoring it.",
                 client_config.interface, typemsg);
        return 0;
    }
    if (cs->serverAddr != sid) {
        char svrbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(struct in_addr){.s_addr=sid},
                  svrbuf, sizeof svrbuf);
        log_line("%s: Received %s with an unexpected server id: %s.  Ignoring it.",
                 client_config.interface, typemsg, svrbuf);
        return 0;
    }
    return 1;
}

static void get_leasetime(struct client_state_t cs[static 1],
                          struct dhcpmsg packet[static 1])
{
    cs->lease = get_option_leasetime(packet);
    cs->leaseStartTime = curms();
    if (!cs->lease) {
        log_line("%s: No lease time received; assuming 1h.",
                 client_config.interface);
        cs->lease = 60 * 60;
    } else {
        if (cs->lease < 60) {
            log_warning("Server sent lease of <1m.  Forcing lease to 1m.",
                        client_config.interface);
            cs->lease = 60;
        }
    }
    // Always use RFC2131 'default' values.  It's not worth validating
    // the remote server values, if they even exist, for sanity.
    cs->renewTime = cs->lease >> 1;
    cs->rebindTime = (cs->lease >> 3) * 0x7; // * 0.875
    cs->dhcp_wake_ts = cs->leaseStartTime + cs->renewTime * 1000;
}

static int extend_packet(struct client_state_t cs[static 1],
                         struct dhcpmsg packet[static 1], uint8_t msgtype,
                         uint32_t srcaddr)
{
    (void)srcaddr;
    if (msgtype == DHCPACK) {
        if (!validate_serverid(cs, packet, "a DHCP ACK"))
            return ANP_IGNORE;
        get_leasetime(cs, packet);

        // Did we receive a lease with a different IP than we had before?
        if (memcmp(&packet->yiaddr, &cs->clientAddr, 4)) {
            char clibuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->clientAddr},
                      clibuf, sizeof clibuf);
            log_line("%s: Server is now offering IP %s.  Validating...",
                     client_config.interface, clibuf);
            return ANP_CHECK_IP;
        } else {
            log_line("%s: Lease refreshed to %u seconds.",
                     client_config.interface, cs->lease);
            if (arp_set_defense_mode(cs) < 0)
                log_warning("%s: Failed to create ARP defense socket.",
                            client_config.interface);
            stop_dhcp_listen(cs);
            return ANP_SUCCESS;
        }
    } else if (msgtype == DHCPNAK) {
        if (!validate_serverid(cs, packet, "a DHCP NAK"))
            return ANP_IGNORE;
        log_line("%s: Our request was rejected.  Searching for a new lease...",
                 client_config.interface);
        reinit_selecting(cs, 3000);
        return ANP_REJECTED;
    }
    return ANP_IGNORE;
}

static int selecting_packet(struct client_state_t cs[static 1],
                            struct dhcpmsg packet[static 1], uint8_t msgtype,
                            uint32_t srcaddr, bool is_requesting)
{
    char clibuf[INET_ADDRSTRLEN];
    char svrbuf[INET_ADDRSTRLEN];
    char srcbuf[INET_ADDRSTRLEN];
    int found;
    if (!is_requesting && msgtype == DHCPOFFER) {
        uint32_t sid = get_option_serverid(packet, &found);
        if (!found) {
            log_line("%s: Invalid offer received: it didn't have a server id.",
                     client_config.interface);
            return ANP_IGNORE;
        }
        cs->clientAddr = packet->yiaddr;
        cs->serverAddr = sid;
        cs->srcAddr = srcaddr;
        cs->dhcp_wake_ts = curms();
        cs->num_dhcp_requests = 0;
        inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->clientAddr},
                  clibuf, sizeof clibuf);
        inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->serverAddr},
                  svrbuf, sizeof svrbuf);
        inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->srcAddr},
                  srcbuf, sizeof srcbuf);
        log_line("%s: Received IP offer: %s from server %s via %s.",
                 client_config.interface, clibuf, svrbuf, srcbuf);
        return ANP_SUCCESS;
    } else if (is_requesting && msgtype == DHCPACK) {
        // Don't validate the server id.  Instead validate that the
        // yiaddr matches.  Some networks have multiple servers
        // that don't respect the serverid that was specified in
        // our DHCPREQUEST.
        if (!memcmp(&packet->yiaddr, &cs->clientAddr, 4)) {
            uint32_t sid = get_option_serverid(packet, &found);
            if (!found) {
                log_line("%s: Invalid offer received: it didn't have a server id.",
                         client_config.interface);
                return ANP_IGNORE;
            }
            if (cs->serverAddr != sid) {
                cs->serverAddr = sid;
                cs->srcAddr = srcaddr;
            }
            get_leasetime(cs, packet);

            inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->clientAddr},
                      clibuf, sizeof clibuf);
            inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->serverAddr},
                      svrbuf, sizeof svrbuf);
            inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->srcAddr},
                      srcbuf, sizeof srcbuf);
            log_line("%s: Received ACK: %s from server %s via %s.  Validating...",
                     client_config.interface, clibuf, svrbuf, srcbuf);
            return ANP_CHECK_IP;
        }
    }
    return ANP_IGNORE;
}

// Triggered after a DHCP discover packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of discover retransmits, then send another packet and wait
// again.  Otherwise, background or fail.
static int selecting_timeout(struct client_state_t cs[static 1],
                              long long nowts)
{
    if (cs->program_init && cs->num_dhcp_requests >= 2) {
        if (client_config.background_if_no_lease) {
            log_line("%s: No lease; going to background.",
                     client_config.interface);
            cs->program_init = false;
            background();
        } else if (client_config.abort_if_no_lease)
            suicide("%s: No lease; failing.", client_config.interface);
    }
    if (cs->num_dhcp_requests == 0)
        cs->xid = nk_random_u32(&cs->rnd_state);
    if (send_discover(cs) < 0) {
        log_warning("%s: Failed to send a discover request packet.",
                    client_config.interface);
        return SEL_FAIL;
    }
    cs->dhcp_wake_ts = nowts + delay_timeout(cs, cs->num_dhcp_requests);
    cs->num_dhcp_requests++;
    return SEL_SUCCESS;
}

// Called for a release signal during SELECTING or REQUESTING.
static void print_release(struct client_state_t cs[static 1])
{
    log_line("%s: ndhc going to sleep.  Wake it by sending a SIGUSR1.",
             client_config.interface);
    reinit_shared_deconfig(cs);
    cs->dhcp_wake_ts = -1;
    stop_dhcp_listen(cs);
}

// Called for a release signal during BOUND, RENEWING, or REBINDING.
static int xmit_release(struct client_state_t cs[static 1])
{
    char clibuf[INET_ADDRSTRLEN];
    char svrbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->clientAddr},
              clibuf, sizeof clibuf);
    inet_ntop(AF_INET, &(struct in_addr){.s_addr=cs->serverAddr},
              svrbuf, sizeof svrbuf);
    log_line("%s: Unicasting a release of %s to %s.", client_config.interface,
             clibuf, svrbuf);
    if (send_release(cs) < 0) {
        log_warning("%s: Failed to send a release request packet.",
                    client_config.interface);
        return -1;
    }
    print_release(cs);
    return 0;
}

// Called for a renewing signal during BOUND or RELEASED
static int frenew(struct client_state_t cs[static 1], bool is_bound)
{
    if (is_bound) {
        log_line("%s: Forcing a DHCP renew...", client_config.interface);
        start_dhcp_listen(cs);
        if (send_renew(cs) < 0) {
            log_warning("%s: Failed to send a renew request packet.",
                        client_config.interface);
            return -1;
        }
    } else { // RELEASED
        reinit_selecting(cs, 0);
    }
    return 0;
}

// If we have a lease, check to see if our gateway is still valid via ARP.
// If it fails, state -> SELECTING.
static int ifup_action(struct client_state_t cs[static 1])
{
    if (cs->routerAddr && cs->serverAddr) {
        if ((cs->routerAddr == cs->serverAddr) && cs->server_arp_state != ARP_FOUND)
            goto no_fingerprint;
        if (cs->init_fingerprint_inprogress) {
            suicide("%s: Carrier lost during initial fingerprint.  Forcing restart.",
                    client_config.interface);
        }
        if (arp_gw_check(cs) >= 0) {
            log_line("%s: Interface is back.  Revalidating lease...",
                     client_config.interface);
            return IFUP_REVALIDATE;
        } else {
            log_warning("%s: arp_gw_check could not make arp socket.",
                        client_config.interface);
            return IFUP_FAIL;
        }
    }
no_fingerprint:
    log_line("%s: Interface is back.  Searching for new lease...",
             client_config.interface);
    return IFUP_NEWLEASE;
}

#define BAD_STATE() suicide("%s(%d): bad state", __func__, __LINE__)

// XXX: Should be re-entrant so as to handle multiple servers.
int dhcp_handle(struct client_state_t cs[static 1], long long nowts,
                bool sev_dhcp, struct dhcpmsg dhcp_packet[static 1],
                uint8_t dhcp_msgtype, uint32_t dhcp_srcaddr, bool sev_arp,
                bool force_fingerprint, bool dhcp_timeout, bool arp_timeout,
                int sev_signal)
{
    scrBegin;
reinit:
    cs->xid = nk_random_u32(&cs->rnd_state);
    // We're in the SELECTING state here.
    for (;;) {
        int ret = COR_SUCCESS;
        if (sev_signal == SIGNAL_RELEASE) {
            print_release(cs);
            goto skip_to_released;
        }
        if (sev_dhcp) {
            int r = selecting_packet(cs, dhcp_packet, dhcp_msgtype,
                                     dhcp_srcaddr, false);
            if (r == ANP_SUCCESS) {
                // Send a request packet to the answering DHCP server.
                sev_dhcp = false;
                goto skip_to_requesting;
            }
        }
        if (dhcp_timeout) {
            int r = selecting_timeout(cs, nowts);
            if (r == SEL_SUCCESS) {
            } else if (r == SEL_FAIL) {
                ret = COR_ERROR;
            } else BAD_STATE();
        }
        scrReturn(ret);
    }
    scrReturn(COR_SUCCESS);
    // We're in the REQUESTING state here.
    for (;;) {
        int ret;
skip_to_requesting:
        ret = COR_SUCCESS;
        if (sev_signal == SIGNAL_RELEASE) {
            print_release(cs);
            goto skip_to_released;
        }
        if (sev_dhcp) {
            int r = selecting_packet(cs, dhcp_packet, dhcp_msgtype,
                                     dhcp_srcaddr, true);
            if (r == ANP_IGNORE) {
            } else if (r == ANP_CHECK_IP) {
                if (arp_check(cs, dhcp_packet) < 0) {
                    log_warning("%s: Failed to make arp socket.  Searching for new lease...",
                                client_config.interface);
                    reinit_selecting(cs, 3000);
                    sev_dhcp = false;
                    goto reinit;
                }
                break;
            } else BAD_STATE();
        }
        if (dhcp_timeout) {
            // Send a request packet to the answering DHCP server.
            int r = requesting_timeout(cs, nowts);
            if (r == REQ_SUCCESS) {
            } else if (r == REQ_TIMEOUT) {
                // We timed out.  Send another packet.
                sev_dhcp = false;
                goto reinit;
            } else if (r == REQ_FAIL) {
                // Failed to send packet.  Sleep and retry.
                ret = COR_ERROR;
            } else BAD_STATE();
        }
        scrReturn(ret);
    }
    scrReturn(COR_SUCCESS);
    // We're checking to see if there's a conflict for our IP.  Technically,
    // this is still in REQUESTING.
    for (;;) {
        int ret;
        ret = COR_SUCCESS;
        if (sev_signal == SIGNAL_RELEASE) {
            print_release(cs);
            goto skip_to_released;
        }
        if (sev_dhcp) {
            // XXX: Maybe I can think of something to do here.  Would
            //      be more relevant if we tracked multiple dhcp servers.
        }
        if (sev_arp) {
            int r = arp_do_collision_check(cs);
            if (r == ARPR_OK) {
            } else if (r == ARPR_CONFLICT) {
                // XXX: If we tracked multiple DHCP servers, then we
                //      could fall back on another one.
                reinit_selecting(cs, 0);
                sev_dhcp = false;
                goto reinit;
            } else if (r == ARPR_FAIL) {
                ret = COR_ERROR;
                scrReturn(ret);
                continue;
            } else BAD_STATE();
        }
        if (arp_timeout) {
            int r = arp_collision_timeout(cs, nowts);
            if (r == ARPR_FREE) {
                arp_query_gateway(cs);
                arp_announce(cs);
                break;
            } else if (r == ARPR_OK) {
            } else if (r == ARPR_FAIL) {
                ret = COR_ERROR;
                scrReturn(ret);
                continue;
            } else BAD_STATE();
        }
        if (dhcp_timeout) {
            // Send a request packet to the answering DHCP server.
            int r = requesting_timeout(cs, nowts);
            if (r == REQ_SUCCESS) {
            } else if (r == REQ_TIMEOUT) {
                // We timed out.  Send another packet.
                sev_dhcp = false;
                goto reinit;
            } else if (r == REQ_FAIL) {
                // Failed to send packet.  Sleep and retry.
                ret = COR_ERROR;
            } else BAD_STATE();
        }
        scrReturn(ret);
    }
    scrReturn(COR_SUCCESS);
    // We're in the BOUND, RENEWING, or REBINDING states here.
    for (;;) {
        int ret = COR_SUCCESS;
        if (sev_signal) {
            if (sev_signal == SIGNAL_RELEASE) {
                int r = xmit_release(cs);
                if (r) {
                    ret = COR_ERROR;
                    scrReturn(ret);
                    continue;
                }
                goto skip_to_released;
            }
            if (sev_signal == SIGNAL_RENEW) {
                int r = frenew(cs, true);
                if (r) {
                    ret = COR_ERROR;
                    scrReturn(ret);
                    continue;
                }
            }
        }
        if (sev_dhcp && is_renewing(cs, nowts)) {
            int r = extend_packet(cs, dhcp_packet, dhcp_msgtype, dhcp_srcaddr);
            if (r == ANP_SUCCESS || r == ANP_IGNORE) {
            } else if (r == ANP_REJECTED) {
                sev_dhcp = false;
                goto reinit;
            } else if (r == ANP_CHECK_IP) {
                if (arp_check(cs, dhcp_packet) < 0) {
                    log_warning("%s: Failed to make arp socket.  Searching for new lease...",
                                client_config.interface);
                    reinit_selecting(cs, 3000);
                    sev_dhcp = false;
                    goto reinit;
                }
            } else BAD_STATE();
        }
        if (sev_arp) {
            int r;
            r = arp_do_defense(cs);
            if (r == ARPR_OK) {
            } else if (r == ARPR_CONFLICT) {
                reinit_selecting(cs, 0);
                sev_dhcp = false;
                goto reinit;
            } else if (r == ARPR_FAIL) {
                ret = COR_ERROR;
                scrReturn(ret);
                continue;
            } else BAD_STATE();
            if (!cs->got_router_arp || cs->server_arp_state == ARP_QUERY) {
                r = arp_do_gw_query(cs);
                if (r == ARPR_OK) {
                } else if (r == ARPR_FREE) {
                    log_line("%s: Network fingerprinting complete.", client_config.interface);
                    cs->init_fingerprint_inprogress = false;
                } else if (r == ARPR_FAIL) {
                    ret = COR_ERROR;
                    scrReturn(ret);
                    continue;
                } else BAD_STATE();
            } else if (cs->check_fingerprint) {
                r = arp_do_gw_check(cs);
                if (r == ARPR_OK) {
                } else if (r == ARPR_FREE) {
                    cs->check_fingerprint = false;
                } else if (r == ARPR_CONFLICT) {
                    cs->check_fingerprint = false;
                    reinit_selecting(cs, 0);
                    sev_dhcp = false;
                    goto reinit;
                } else if (r == ARPR_FAIL) {
                    ret = COR_ERROR;
                    scrReturn(ret);
                    continue;
                } else BAD_STATE();
            }
        }
        if (arp_timeout) {
            if (cs->sent_first_announce && cs->sent_second_announce)
                arp_defense_timeout(cs, nowts);
            else
                arp_announce_timeout(cs, nowts);
            if (!cs->sent_gw_query)
                arp_query_gateway_timeout(cs, nowts);
            else if (!cs->got_router_arp || cs->server_arp_state == ARP_QUERY) {
                int r = arp_gw_query_timeout(cs, nowts);
                if (r == ARPR_OK) {
                } else if (r == ARPR_FAIL) {
                    ret = COR_ERROR;
                    scrReturn(ret);
                    continue;
                } else BAD_STATE();
            } else if (cs->check_fingerprint) {
                int r = arp_gw_check_timeout(cs, nowts);
                if (r == ARPR_OK) {
                } else if (r == ARPR_CONFLICT) {
                    cs->check_fingerprint = false;
                    reinit_selecting(cs, 0);
                    sev_dhcp = false;
                    goto reinit;
                } else if (r == ARPR_FAIL) {
                    ret = COR_ERROR;
                    scrReturn(ret);
                    continue;
                } else BAD_STATE();
            }
        }
        if (force_fingerprint) {
            int r = ifup_action(cs);
            if (r == IFUP_REVALIDATE) {
            } else if (r == IFUP_NEWLEASE) {
                if (ifchange_deconfig(cs) < 0) {
                    // Likely only to fail because of rfkill.
                    ret = COR_ERROR;
                    scrReturn(ret);
                }
                reinit_selecting(cs, 0);
                sev_dhcp = false;
                goto reinit;
            } else if (r == IFUP_FAIL) {
                ret = COR_ERROR;
                scrReturn(ret);
                continue;
            } else BAD_STATE();
        }
        if (dhcp_timeout) {
            int r;
            if (is_rebinding(cs, nowts)) {
                r = rebinding_timeout(cs, nowts);
            } else if (is_renewing(cs, nowts)) {
                r = renewing_timeout(cs, nowts);
            } else {
                r = bound_timeout(cs, nowts);
            }
            if (r == BTO_WAIT) {
            } else if (r == BTO_EXPIRED) {
                sev_dhcp = false;
                goto reinit;
            } else if (r == BTO_HARDFAIL) {
                ret = COR_ERROR;
            } else
                BAD_STATE();
        }
        scrReturn(ret);
    }
    sev_dhcp = false;
    goto reinit;
    // We're in the RELEASED state here.
    for (;;) {
        int ret;
skip_to_released:
        ret = COR_SUCCESS;
        if (sev_signal == SIGNAL_RENEW) {
            int r = frenew(cs, false);
            if (r) {
                ret = COR_ERROR;
                scrReturn(ret);
                continue;
            }
            break;
        }
        scrReturn(ret);
    }
    sev_dhcp = false;
    goto reinit;
    scrFinish(COR_SUCCESS);
}


