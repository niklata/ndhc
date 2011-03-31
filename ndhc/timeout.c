/* timeout.c - callbacks to react to event timeouts
 * Time-stamp: <2011-03-30 23:42:13 nk>
 *
 * (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
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

#include "timeout.h"
#include "config.h"
#include "ifchange.h"
#include "packet.h"
#include "dhcpmsg.h"
#include "arp.h"
#include "log.h"

#define DELAY_SEC (((RETRY_DELAY - (RETRY_DELAY / NUMPACKETS)) / NUMPACKETS) + 1)
static void init_selecting_timeout(struct client_state_t *cs)
{
    if (cs->packetNum < NUMPACKETS) {
        if (cs->packetNum == 0)
            cs->xid = random_xid();
        /* broadcast */
        send_discover(cs->xid, cs->requestedIP);

        cs->timeout = DELAY_SEC * (cs->packetNum + 1) * 1000;
        cs->packetNum++;
    } else {
        if (client_config.background_if_no_lease) {
            log_line("No lease, going to background.");
            background(cs);
        } else if (client_config.abort_if_no_lease) {
            log_line("No lease, failing.");
            exit(EXIT_FAILURE);
        }
        /* wait to try again */
        cs->packetNum = 0;
        cs->timeout = RETRY_DELAY * 1000;
    }
}
#undef DELAY_SEC

static void renew_requested_timeout(struct client_state_t *cs)
{
    if (cs->packetNum < NUMPACKETS) {
        /* send unicast request packet */
        send_renew(cs->xid, cs->serverAddr, cs->requestedIP);
        cs->timeout = ((cs->packetNum == NUMPACKETS - 1) ? 10 : 2) * 1000;
        cs->packetNum++;
    } else {
        /* timed out, go back to init state */
        ifchange(NULL, IFCHANGE_DECONFIG);
        cs->dhcpState = DS_INIT_SELECTING;
        cs->timeout = 0;
        cs->packetNum = 0;
        change_listen_mode(cs, LM_RAW);
    }
}

static void requesting_timeout(struct client_state_t *cs)
{
    if (cs->packetNum < NUMPACKETS) {
        /* send broadcast request packet */
        send_selecting(cs->xid, cs->serverAddr, cs->requestedIP);
        cs->timeout = ((cs->packetNum == NUMPACKETS - 1) ? 10 : 2) * 1000;
        cs->packetNum++;
    } else {
        /* timed out, go back to init state */
        cs->dhcpState = DS_INIT_SELECTING;
        cs->timeout = 0;
        cs->packetNum = 0;
        change_listen_mode(cs, LM_RAW);
    }
}

static void renewing_timeout(struct client_state_t *cs)
{
    /* Either set a new T1, or enter DS_REBINDING state */
    if ((cs->t2 - cs->t1) <= (cs->lease / 14400 + 1)) {
        /* timed out, enter rebinding state */
        cs->dhcpState = DS_REBINDING;
        cs->timeout = (cs->t2 - cs->t1) * 1000;
        log_line("Entering rebinding state.");
    } else {
        /* send a request packet */
        send_renew(cs->xid, cs->serverAddr, cs->requestedIP); /* unicast */

        cs->t1 = ((cs->t2 - cs->t1) >> 1) + cs->t1;
        cs->timeout = (cs->t1 * 1000) - (curms() - cs->leaseStartTime);
    }
}

static void bound_timeout(struct client_state_t *cs)
{
    /* Lease is starting to run out, time to enter renewing state */
    cs->dhcpState = DS_RENEWING;
    change_listen_mode(cs, LM_KERNEL);
    log_line("Entering renew state.");
    renewing_timeout(cs);
}

static void rebinding_timeout(struct client_state_t *cs)
{
    /* Either set a new T2, or enter INIT state */
    if ((cs->lease - cs->t2) <= (cs->lease / 14400 + 1)) {
        /* timed out, enter init state */
        cs->dhcpState = DS_INIT_SELECTING;
        log_line("Lease lost, entering init state.");
        ifchange(NULL, IFCHANGE_DECONFIG);
        cs->timeout = 0;
        cs->packetNum = 0;
        change_listen_mode(cs, LM_RAW);
    } else {
        /* send a request packet */
        send_renew(cs->xid, 0, cs->requestedIP); /* broadcast */

        cs->t2 = ((cs->lease - cs->t2) >> 1) + cs->t2;
        cs->timeout = (cs->t2 * 1000) - (curms() - cs->leaseStartTime);
    }
}

/* Handle epoll timeout expiring */
void handle_timeout(struct client_state_t *cs)
{
    switch (cs->dhcpState) {
        case DS_INIT_SELECTING: init_selecting_timeout(cs); break;
        case DS_RENEW_REQUESTED: renew_requested_timeout(cs); break;
        case DS_REQUESTING: requesting_timeout(cs); break;
        case DS_RENEWING: renewing_timeout(cs); break;
        case DS_BOUND: bound_timeout(cs); break;
        case DS_REBINDING: rebinding_timeout(cs); break;
        case DS_RELEASED: cs->timeout = -1; break;
        case DS_ARP_CHECK: arp_success(cs); break;
        case DS_ARP_GW_CHECK: arp_gw_failed(cs); break;
        default: break;
    }
}
