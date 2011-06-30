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
#include "sys.h"
#include "random.h"

static void selecting_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                             uint8_t *message);
static void an_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                      uint8_t *message);
static void selecting_timeout(struct client_state_t *cs);
static void requesting_timeout(struct client_state_t *cs);
static void bound_timeout(struct client_state_t *cs);
static void renewing_timeout(struct client_state_t *cs);
static void rebinding_timeout(struct client_state_t *cs);
static void released_timeout(struct client_state_t *cs);
static void anfrelease(struct client_state_t *cs);
static void nfrelease(struct client_state_t *cs);
static void frelease(struct client_state_t *cs);
static void frenew(struct client_state_t *cs);

typedef struct {
    void (*packet_fn)(struct client_state_t *cs, struct dhcpmsg *packet,
                      uint8_t *message);
    void (*timeout_fn)(struct client_state_t *cs);
    void (*force_renew_fn)(struct client_state_t *cs);
    void (*force_release_fn)(struct client_state_t *cs);
} dhcp_state_t;

dhcp_state_t dhcp_states[] = {
    { selecting_packet, selecting_timeout, 0, frelease},     // SELECTING
    { an_packet, requesting_timeout, frenew, frelease},      // REQUESTING
    { 0, bound_timeout, frenew, nfrelease},                  // BOUND
    { an_packet, renewing_timeout, frenew, nfrelease},       // RENEWING
    { an_packet, rebinding_timeout, frenew, nfrelease},      // REBINDING
    { 0, arp_gw_failed, frenew, frelease},                   // ARP_GW_CHECK XXX
    { 0, arp_success, frenew, anfrelease},                   // ARP_CHECK
    { 0, released_timeout, frenew, frelease},                // RELEASED
    { 0, 0, 0, 0},                                           // NUM_STATES
};

// Triggered after a DHCP lease request packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of request retransmits, then send another packet and wait
// again.  Otherwise, return to the DHCP initialization state.
static void requesting_timeout(struct client_state_t *cs)
{
    if (cs->packetNum < NUMPACKETS) {
        send_selecting(cs->xid, cs->serverAddr, cs->requestedIP);
        cs->timeout = ((cs->packetNum == NUMPACKETS - 1) ? 10 : 2) * 1000;
        cs->packetNum++;
    } else {
        cs->dhcpState = DS_SELECTING;
        cs->timeout = 0;
        cs->packetNum = 0;
        change_listen_mode(cs, LM_RAW);
    }
}

// Triggered when the lease has been held for a significant fraction of its
// total time, and it is time to renew the lease so that it is not lost.
static void bound_timeout(struct client_state_t *cs)
{
    cs->dhcpState = DS_RENEWING;
    change_listen_mode(cs, LM_KERNEL);
    log_line("Entering renew state.");
    renewing_timeout(cs);
}

// Triggered when a DHCP renew request has been sent and no reply has been
// received within the response wait time.  This function is also directly
// called by bound_timeout() when it is time to renew a lease before it
// expires.  Check to see if the lease is still valid, and if it is, send
// a unicast DHCP renew packet.  If it is not, then change to the REBINDING
// state to get a new lease.
static void renewing_timeout(struct client_state_t *cs)
{
    if ((cs->t2 - cs->t1) <= (cs->lease / 14400 + 1)) {
        cs->dhcpState = DS_REBINDING;
        cs->timeout = (cs->t2 - cs->t1) * 1000;
        log_line("Entering rebinding state.");
    } else {
        send_renew(cs->xid, cs->serverAddr, cs->requestedIP);
        cs->t1 = ((cs->t2 - cs->t1) >> 1) + cs->t1;
        cs->timeout = (cs->t1 * 1000) - (curms() - cs->leaseStartTime);
    }
}

static void rebinding_timeout(struct client_state_t *cs)
{
    /* Either set a new T2, or enter INIT state */
    if ((cs->lease - cs->t2) <= (cs->lease / 14400 + 1)) {
        /* timed out, enter init state */
        cs->dhcpState = DS_SELECTING;
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

static void released_timeout(struct client_state_t *cs)
{
    cs->timeout = -1;
}

static void an_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                      uint8_t *message)
{
    uint8_t *temp = NULL;
    ssize_t optlen;
    if (*message == DHCPACK) {
        if (!(temp = get_option_data(packet, DHCP_LEASE_TIME, &optlen))) {
            log_line("No lease time received, assuming 1h.");
            cs->lease = 60 * 60;
        } else {
            memcpy(&cs->lease, temp, 4);
            cs->lease = ntohl(cs->lease);
            // Enforce upper and lower bounds on lease.
            cs->lease &= 0x0fffffff;
            if (cs->lease < RETRY_DELAY)
                cs->lease = RETRY_DELAY;
        }

        // Can transition from DS_ARP_CHECK to DS_BOUND or DS_SELECTING.
        if (arp_check(cs, packet) == -1) {
            log_warning("arp_check failed to make arp socket, retrying lease");
            ifchange(NULL, IFCHANGE_DECONFIG);
            cs->dhcpState = DS_SELECTING;
            cs->timeout = 30000;
            cs->requestedIP = 0;
            cs->packetNum = 0;
            change_listen_mode(cs, LM_RAW);
        }

    } else if (*message == DHCPNAK) {
        log_line("Received DHCP NAK.");
        ifchange(packet, IFCHANGE_NAK);
        if (cs->dhcpState != DS_REQUESTING)
            ifchange(NULL, IFCHANGE_DECONFIG);
        cs->dhcpState = DS_SELECTING;
        cs->timeout = 3000;
        cs->requestedIP = 0;
        cs->packetNum = 0;
        change_listen_mode(cs, LM_RAW);
    }
}

static void selecting_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                             uint8_t *message)
{
    uint8_t *temp = NULL;
    ssize_t optlen;
    if (*message == DHCPOFFER) {
        if ((temp = get_option_data(packet, DHCP_SERVER_ID, &optlen))) {
            memcpy(&cs->serverAddr, temp, 4);
            cs->xid = packet->xid;
            cs->requestedIP = packet->yiaddr;
            cs->dhcpState = DS_REQUESTING;
            cs->timeout = 0;
            cs->packetNum = 0;
        } else {
            log_line("No server ID in message");
        }
    }
}

#define DELAY_SEC (((RETRY_DELAY - (RETRY_DELAY / NUMPACKETS)) / NUMPACKETS) + 1)
// Triggered after a DHCP discover packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of discover retransmits, then send another packet and wait
// again.  Otherwise, background or fail.
static void selecting_timeout(struct client_state_t *cs)
{
    if (cs->packetNum < NUMPACKETS) {
        if (cs->packetNum == 0)
            cs->xid = libc_random_u32();
        send_discover(cs->xid, cs->requestedIP);
        cs->timeout = DELAY_SEC * (cs->packetNum + 1) * 1000;
        cs->packetNum++;
    } else {
        if (cs->init) {
            if (client_config.background_if_no_lease) {
                log_line("No lease, going to background.");
                cs->init = 0;
                background(cs);
            } else if (client_config.abort_if_no_lease) {
                log_line("No lease, failing.");
                exit(EXIT_FAILURE);
            }
        }
        cs->packetNum = 0;
        cs->timeout = RETRY_DELAY * 1000;
    }
}
#undef DELAY_SEC

static void anfrelease(struct client_state_t *cs)
{
    arp_close_fd(cs);
    nfrelease(cs);
}

static void nfrelease(struct client_state_t *cs)
{
    log_line("Unicasting a release of %s to %s.",
             inet_ntoa((struct in_addr){.s_addr=cs->requestedIP}),
             inet_ntoa((struct in_addr){.s_addr=cs->serverAddr}));
    send_release(cs->serverAddr, cs->requestedIP);
    ifchange(NULL, IFCHANGE_DECONFIG);
    frelease(cs);
}

static void frelease(struct client_state_t *cs)
{
    log_line("Entering released state.");
    change_listen_mode(cs, LM_NONE);
    cs->dhcpState = DS_RELEASED;
    cs->timeout = -1;
}

// XXX: DS_ARP_CHECK_GW? Also split this up?
static void frenew(struct client_state_t *cs)
{
    log_line("Forcing a DHCP renew...");
  retry:
    switch (cs->dhcpState) {
        case DS_BOUND:
            change_listen_mode(cs, LM_KERNEL);
        case DS_ARP_CHECK:
            // Cancel arp ping in progress and treat as previous state.
            epoll_del(cs, cs->arpFd);
            close(cs->arpFd);
            cs->arpFd = -1;
            cs->dhcpState = cs->arpPrevState;
            goto retry;
        case DS_REQUESTING:
        case DS_RELEASED:
            change_listen_mode(cs, LM_RAW);
            cs->dhcpState = DS_SELECTING;
            break;
        case DS_RENEWING:
        case DS_REBINDING:
        case DS_SELECTING:
        default:
            break;
    }
    cs->packetNum = 0;
    cs->timeout = 0;
}

void packet_action(struct client_state_t *cs, struct dhcpmsg *packet,
                   uint8_t *message)
{
    if (dhcp_states[cs->dhcpState].packet_fn)
        dhcp_states[cs->dhcpState].packet_fn(cs, packet, message);
}

void timeout_action(struct client_state_t *cs)
{
    if (dhcp_states[cs->dhcpState].timeout_fn)
        dhcp_states[cs->dhcpState].timeout_fn(cs);
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

