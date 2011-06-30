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
    { 0, arp_gw_failed, frenew, anfrelease},                 // BOUND_GW_CHECK
    { 0, arp_success, frenew, anfrelease},                   // ARP_CHECK
    { 0, released_timeout, frenew, frelease},                // RELEASED
    { 0, 0, 0, 0},                                           // NUM_STATES
};

static int delay_timeout(int numpackets)
{
    int to = 64;
    char tot[] = { 4, 8, 16, 32, 64 };
    if (numpackets < sizeof tot)
        to = tot[numpackets];
    return to;
}

// Triggered after a DHCP lease request packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of request retransmits, then send another packet and wait
// again.  Otherwise, return to the DHCP initialization state.
static void requesting_timeout(struct client_state_t *cs)
{
    if (cs->packetNum < 5) {
        send_selecting(cs->xid, cs->serverAddr, cs->requestedIP);
        cs->timeout = delay_timeout(cs->packetNum);
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

static void lease_timedout(struct client_state_t *cs)
{
    cs->dhcpState = DS_SELECTING;
    log_line("Lease lost, entering init state.");
    ifchange(NULL, IFCHANGE_DECONFIG);
    cs->timeout = 0;
    cs->packetNum = 0;
    change_listen_mode(cs, LM_RAW);
}

// Triggered when a DHCP renew request has been sent and no reply has been
// received within the response wait time.  This function is also directly
// called by bound_timeout() when it is time to renew a lease before it
// expires.  Check to see if the lease is still valid, and if it is, send
// a unicast DHCP renew packet.  If it is not, then change to the REBINDING
// state to send broadcast queries.
static void renewing_timeout(struct client_state_t *cs)
{
    long long ct = curms();
    long long rbt = cs->leaseStartTime + cs->rebindTime * 1000;
    if (ct < rbt) {
        long long wt = (rbt - ct) / 2;
        if (wt >= 30000)
            send_renew(cs->xid, cs->serverAddr, cs->requestedIP);
        else
            wt = rbt - ct;
        cs->timeout = wt;
        return;
    }
    long long elt = cs->leaseStartTime + cs->lease * 1000;
    if (ct < elt) {
        cs->dhcpState = DS_REBINDING;
        cs->timeout = elt - ct / 2;
        log_line("Entering rebinding state.");
    } else
        lease_timedout(cs);
}

// Triggered when a DHCP rebind request has been sent and no reply has been
// received within the response wait time.  Check to see if the lease is still
// valid, and if it is, send a broadcast DHCP renew packet.  If it is not, then
// change to the SELECTING state to get a new lease.
static void rebinding_timeout(struct client_state_t *cs)
{
    long long ct = curms();
    long long elt = cs->leaseStartTime + cs->lease * 1000;
    if (ct < elt) {
        long long wt = (elt - ct) / 2;
        if (wt >= 30000)
            send_renew(cs->xid, 0, cs->requestedIP);
        else
            wt = elt - ct;
        cs->timeout = wt;
    } else
        lease_timedout(cs);
}

static void released_timeout(struct client_state_t *cs)
{
    cs->timeout = -1;
}

static void an_packet(struct client_state_t *cs, struct dhcpmsg *packet,
                      uint8_t *message)
{
    if (*message == DHCPACK) {
        uint8_t *temp = NULL;
        ssize_t optlen;
        cs->leaseStartTime = curms();
        if (!(temp = get_option_data(packet, DHCP_LEASE_TIME, &optlen))) {
            log_line("No lease time received, assuming 1h.");
            cs->lease = 60 * 60;
        } else {
            memcpy(&cs->lease, temp, 4);
            cs->lease = ntohl(cs->lease);
            cs->lease &= 0x0fffffff;
            if (cs->lease < 60) {
                log_warning("Server sent lease of <1m.  Forcing lease to 1m.");
                cs->lease = 60;
            }
        }
        // Always use RFC2131 'default' values.  It's not worth validating
        // the remote server values, if they even exist, for sanity.
        cs->renewTime = cs->lease >> 1;
        cs->rebindTime = (cs->lease * 0x7) >> 3; // * 0.875

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
    if (*message == DHCPOFFER) {
        uint8_t *temp = NULL;
        ssize_t optlen;
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

// Triggered after a DHCP discover packet has been sent and no reply has
// been received within the response wait time.  If we've not exceeded the
// maximum number of discover retransmits, then send another packet and wait
// again.  Otherwise, background or fail.
static void selecting_timeout(struct client_state_t *cs)
{
    if (cs->packetNum == 0)
        cs->xid = libc_random_u32();
    send_discover(cs->xid, cs->requestedIP);
    cs->timeout = delay_timeout(cs->packetNum);
    cs->packetNum++;
    if (cs->init && cs->packetNum >= 2) {
        if (client_config.background_if_no_lease) {
            log_line("No lease, going to background.");
            cs->init = 0;
            background(cs);
        } else if (client_config.abort_if_no_lease) {
            log_line("No lease, failing.");
            exit(EXIT_FAILURE);
        }
    }
}

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

static void frenew(struct client_state_t *cs)
{
    log_line("Forcing a DHCP renew...");
  retry:
    switch (cs->dhcpState) {
        case DS_BOUND:
        case DS_BOUND_GW_CHECK:
            arp_close_fd(cs);
            cs->dhcpState = DS_RENEWING;
            change_listen_mode(cs, LM_KERNEL);
            send_renew(cs->xid, cs->serverAddr, cs->requestedIP);
            break;
        case DS_ARP_CHECK:
            // Cancel arp ping in progress and treat as previous state.
            if (arp_close_fd(cs))
                cs->dhcpState = cs->arpPrevState;
            goto retry;
        case DS_RELEASED:
            change_listen_mode(cs, LM_RAW);
            cs->dhcpState = DS_SELECTING;
            break;
        case DS_RENEWING:
        case DS_REBINDING:
            break;
        default:
            return;
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

