/* packet.c - send and react to DHCP message packets
 * Time-stamp: <2011-06-11 11:15:09 njk>
 *
 * (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
 * (c) 2001 Russ Dill <Russ.Dill@asu.edu>
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <time.h>
#include <errno.h>

#include "packet.h"
#include "socket.h"
#include "arp.h"
#include "ifchange.h"
#include "sys.h"
#include "log.h"
#include "io.h"
#include "options.h"

// Read a packet from a cooked socket.  Returns -1 on fatal error, -2 on
// transient error.
static int get_packet(struct dhcpMessage *packet, int fd)
{
    int bytes;

    memset(packet, 0, DHCP_SIZE);
    bytes = safe_read(fd, (char *)packet, DHCP_SIZE);
    if (bytes == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_line("Read on listen socket failed: %s", strerror(errno));
        return -1;
    }

    log_line("Received a packet via cooked socket.");

    return bytes;
}

// Read a packet from a raw socket.  Returns -1 on fatal error, -2 on
// transient error.
static int get_raw_packet(struct dhcpMessage *payload, int fd)
{
    struct ip_udp_dhcp_packet packet;
    uint16_t check;

    memset(&packet, 0, IP_UPD_DHCP_SIZE);
    int len = safe_read(fd, (char *)&packet, IP_UPD_DHCP_SIZE);
    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_line("get_raw_packet: read error %s", strerror(errno));
        return -1;
    }

    /* ignore any extra garbage bytes */
    len = ntohs(packet.ip.tot_len);

    // Validate the IP and UDP headers.
    if (packet.ip.protocol != IPPROTO_UDP) {
        log_line("IP header is not UDP: %d", packet.ip.protocol);
        return -2;
    }
    if (packet.ip.version != IPVERSION) {
        log_line("IP version is not IPv4");
        return -2;
    }
    if (packet.ip.ihl != sizeof packet.ip >> 2) {
        log_line("IP header length incorrect");
        return -2;
    }
    check = packet.ip.check;
    packet.ip.check = 0;
    if (check != checksum(&packet.ip, sizeof packet.ip)) {
        log_line("IP header checksum incorrect");
        return -2;
    }
    if (packet.udp.dest != htons(DHCP_CLIENT_PORT)) {
        log_line("UDP destination port incorrect: %d", ntohs(packet.udp.dest));
        return -2;
    }
    if (len > IP_UPD_DHCP_SIZE) {
        log_line("Data longer than that of a IP+UDP+DHCP message: %d", len);
        return -2;
    }
    if (ntohs(packet.udp.len) != (short)(len - sizeof packet.ip)) {
        log_line("UDP header length incorrect");
        return -2;
    }

    /* verify the UDP checksum by replacing the header with a psuedo header */
    memset(&packet.ip, 0, offsetof(struct iphdr, protocol));
    /* preserved fields: protocol, check, saddr, daddr */
    packet.ip.tot_len = packet.udp.len; /* cheat on the psuedo-header */
    check = packet.udp.check;
    packet.udp.check = 0;
    if (check && check != checksum(&packet, len)) {
        log_error("Packet with bad UDP checksum received, ignoring");
        return -2;
    }

    memcpy(payload, &packet.data,
           len - sizeof packet.ip - sizeof packet.udp);

    log_line("Received a packet via raw socket.");
    return len - sizeof packet.ip - sizeof packet.udp;
}

/* Compute Internet Checksum for @count bytes beginning at location @addr. */
uint16_t checksum(void *addr, int count)
{
    register int32_t sum = 0;
    uint16_t *source = (uint16_t *)addr;

    while (count > 1)  {
        sum += *source++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0) {
        /* Make sure that the left-over byte is added correctly both
         * with little and big endian hosts */
        uint16_t tmp = 0;
        *(uint8_t *)&tmp = *(uint8_t *)source;
        sum += tmp;
    }
    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

/* Constuct a ip/udp header for a packet, and specify the source and dest
 * hardware address */
int raw_packet(struct dhcpMessage *payload, uint32_t source_ip,
               int source_port, uint32_t dest_ip, int dest_port,
               uint8_t *dest_arp, int ifindex)
{
    struct sockaddr_ll dest;
    struct ip_udp_dhcp_packet packet;
    int fd, r = -1;
    unsigned int padding;

    if ((fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        log_error("raw_packet: socket failed: %s", strerror(errno));
        goto out;
    }

    memset(&dest, 0, sizeof dest);
    memset(&packet, 0, offsetof(struct ip_udp_dhcp_packet, data));
    packet.data = *payload; /* struct copy */

    set_sock_nonblock(fd);

    dest.sll_family = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_IP);
    dest.sll_ifindex = ifindex;
    dest.sll_halen = 6;
    memcpy(dest.sll_addr, dest_arp, 6);
    if (bind(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll)) < 0) {
        log_error("raw_packet: bind failed: %s", strerror(errno));
        goto out_fd;
    }

    /* We were sending full-sized DHCP packets (zero padded),
     * but some badly configured servers were seen dropping them.
     * Apparently they drop all DHCP packets >576 *ethernet* octets big,
     * whereas they may only drop packets >576 *IP* octets big
     * (which for typical Ethernet II means 590 octets: 6+6+2 + 576).
     *
     * In order to work with those buggy servers,
     * we truncate packets after end option byte.
     */
    ssize_t endloc = get_end_option_idx(packet.data.options,
                                        DHCP_OPTIONS_BUFSIZE);
    if (endloc == -1) {
        log_error("raw_packet: attempt to send packet with no DHCP_END");
        goto out_fd;
    }
    padding = DHCP_OPTIONS_BUFSIZE - 1 - endloc;

    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.saddr = source_ip;
    packet.ip.daddr = dest_ip;
    packet.udp.source = htons(source_port);
    packet.udp.dest = htons(dest_port);
    /* size, excluding IP header: */
    packet.udp.len = htons(UPD_DHCP_SIZE - padding);
    /* for UDP checksumming, ip.len is set to UDP packet len */
    packet.ip.tot_len = packet.udp.len;
    packet.udp.check = checksum(&packet, IP_UPD_DHCP_SIZE - padding);
    /* but for sending, it is set to IP packet len */
    packet.ip.tot_len = htons(IP_UPD_DHCP_SIZE - padding);
    packet.ip.ihl = sizeof packet.ip >> 2;
    packet.ip.version = IPVERSION;
    packet.ip.ttl = IPDEFTTL;
    packet.ip.check = checksum(&packet.ip, sizeof packet.ip);

    r = safe_sendto(fd, (const char *)&packet, IP_UPD_DHCP_SIZE - padding,
                    0, (struct sockaddr *)&dest, sizeof dest);
    if (r == -1)
        log_error("raw_packet: sendto failed: %s", strerror(errno));
  out_fd:
    close(fd);
  out:
    return r;
}

/* Let the kernel do all the work for packet generation */
int kernel_packet(struct dhcpMessage *payload, uint32_t source_ip,
                  int source_port, uint32_t dest_ip, int dest_port)
{
    struct sockaddr_in client;
    int opt = 1, fd, result = -1;
    unsigned int padding;

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        goto out;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1)
        goto out_fd;

    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(source_port);
    client.sin_addr.s_addr = source_ip;

    if (bind(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
        goto out_fd;

    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(dest_port);
    client.sin_addr.s_addr = dest_ip;

    if (connect(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
        goto out_fd;

    ssize_t endloc = get_end_option_idx(payload->options,
                                        DHCP_OPTIONS_BUFSIZE);
    if (endloc == -1) {
        log_error("kernel_packet: attempt to send packet with no DHCP_END");
        goto out_fd;
    }
    padding = DHCP_OPTIONS_BUFSIZE - 1 - endloc;
    result = safe_write(fd, (const char *)payload, DHCP_SIZE - padding);
    if (result == -1)
        log_error("kernel_packet: write failed: %s", strerror(errno));
  out_fd:
    close(fd);
  out:
    return result;
}

// Switch listen socket between raw (if-bound), kernel (ip-bound), and none
void change_listen_mode(struct client_state_t *cs, int new_mode)
{
    cs->listenMode = new_mode;
    if (cs->listenFd >= 0) {
        epoll_del(cs, cs->listenFd);
        close(cs->listenFd);
        cs->listenFd = -1;
    }
    switch (new_mode) {
        case LM_NONE:
            log_line("Stopped listening for DHCP packets.");
            return;
        case LM_RAW:
            cs->listenFd = raw_socket(client_config.ifindex);
            break;
        case LM_KERNEL:
            cs->listenFd = listen_socket(INADDR_ANY, DHCP_CLIENT_PORT,
                                         client_config.interface);
            break;
    }
    if (cs->listenFd < 0) {
        log_error("FATAL: couldn't listen on socket: %s.", strerror(errno));
        exit(EXIT_FAILURE);
    }
    epoll_add(cs, cs->listenFd);
    log_line("Listening for DHCP packets using a %s socket.",
             new_mode == LM_RAW ? "raw" : "cooked");
}

static void init_selecting_packet(struct client_state_t *cs,
                                  struct dhcpMessage *packet,
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

static void dhcp_ack_or_nak_packet(struct client_state_t *cs,
                                   struct dhcpMessage *packet,
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
            /* Enforce upper and lower bounds on lease. */
            cs->lease &= 0x0fffffff;
            if (cs->lease < RETRY_DELAY)
                cs->lease = RETRY_DELAY;
        }

        // Can transition from DS_ARP_CHECK to DS_BOUND or DS_INIT_SELECTING.
        if (arp_check(cs, packet) == -1) {
            log_warning("arp_check failed to make arp socket, retrying lease");
            ifchange(NULL, IFCHANGE_DECONFIG);
            cs->dhcpState = DS_INIT_SELECTING;
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
        cs->dhcpState = DS_INIT_SELECTING;
        cs->timeout = 3000;
        cs->requestedIP = 0;
        cs->packetNum = 0;
        change_listen_mode(cs, LM_RAW);
    }
}

void handle_packet(struct client_state_t *cs)
{
    uint8_t *message = NULL;
    int len;
    struct dhcpMessage packet;
    ssize_t optlen;

    if (cs->listenMode == LM_KERNEL)
        len = get_packet(&packet, cs->listenFd);
    else if (cs->listenMode == LM_RAW)
        len = get_raw_packet(&packet, cs->listenFd);
    else /* LM_NONE */
        return;

    if (len < 0) {
        // Transient issue handled by packet collection functions.
        if (len == -2 || (len == -1 && errno == EINTR))
            return;

        log_error("Error when reading from listening socket: %s.  Reopening listening socket.",
                  strerror(errno));
        change_listen_mode(cs, cs->listenMode);
    }

    if (len < DHCP_SIZE - 308) {
        log_line("Packet is too short to contain magic cookie. Ignoring.");
        return;
    }

    if (ntohl(packet.cookie) != DHCP_MAGIC) {
        log_line("Packet with bad magic number. Ignoring.");
        return;
    }

    if (packet.xid != cs->xid) {
        log_line("Packet XID %lx does not equal our XID %lx.  Ignoring.",
                 packet.xid, cs->xid);
        return;
    }

    if (!(message = get_option_data(&packet, DHCP_MESSAGE_TYPE, &optlen))) {
        log_line("Packet does not specify a DHCP message type. Ignoring.");
        return;
    }

    switch (cs->dhcpState) {
        case DS_INIT_SELECTING:
            init_selecting_packet(cs, &packet, message);
            break;
        case DS_ARP_CHECK:
            // We ignore dhcp packets for now.  This state will
            // be changed by the callback for arp ping.
            break;
        case DS_RENEW_REQUESTED:
        case DS_REQUESTING:
        case DS_RENEWING:
        case DS_REBINDING:
            dhcp_ack_or_nak_packet(cs, &packet, message);
            break;
        case DS_BOUND:
        case DS_RELEASED:
        default:
            break;
    }
}

/* Create a random xid */
uint32_t random_xid(void)
{
    static int initialized;
    if (initialized)
        return rand();

    uint32_t seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        int r = safe_read(fd, (char *)&seed, sizeof seed);
        if (r == -1) {
            log_warning("Could not read /dev/urandom: %s", strerror(errno));
            close(fd);
            seed = time(0);
        }
    } else {
        log_warning("Could not open /dev/urandom: %s",
                    strerror(errno));
        seed = time(0);
    }
    srand(seed);
    initialized = 1;
    return rand();
}

/* Initializes dhcp packet header for a -client- packet. */
static void init_header(struct dhcpMessage *packet, char type)
{
    memset(packet, 0, DHCP_SIZE);
    packet->op = 1; // BOOTREQUEST (client)
    packet->htype = 1; // ETH_10MB
    packet->hlen = 6; // ETH_10MB_LEN
    packet->cookie = htonl(DHCP_MAGIC);
    packet->options[0] = DHCP_END;
    add_u32_option(packet->options, DHCP_OPTIONS_BUFSIZE, DHCP_MESSAGE_TYPE,
                   type);
}

/* initialize a packet with the proper defaults */
static void init_packet(struct dhcpMessage *packet, char type)
{
    struct vendor  {
        char vendor;
        char length;
        char str[sizeof "ndhc"];
    } vendor_id = { DHCP_VENDOR,  sizeof "ndhc" - 1, "ndhc"};

    init_header(packet, type);
    memcpy(packet->chaddr, client_config.arp, 6);
    add_option_string(packet->options, DHCP_OPTIONS_BUFSIZE,
                      client_config.clientid);
    if (client_config.hostname)
        add_option_string(packet->options, DHCP_OPTIONS_BUFSIZE,
                          client_config.hostname);
    add_option_string(packet->options, DHCP_OPTIONS_BUFSIZE,
                      (uint8_t *)&vendor_id);
}

#define MAC_BCAST_ADDR (uint8_t *)"\xff\xff\xff\xff\xff\xff"
/* Wrapper that broadcasts a raw dhcp packet on the bound interface. */
static int bcast_raw_packet(struct dhcpMessage *packet)
{
    return raw_packet(packet, INADDR_ANY, DHCP_CLIENT_PORT, INADDR_BROADCAST,
                      DHCP_SERVER_PORT, MAC_BCAST_ADDR, client_config.ifindex);
}
#undef MAC_BCAST_ADDR

/* Broadcast a DHCP discover packet to the network, with an optionally
 * requested IP */
int send_discover(uint32_t xid, uint32_t requested)
{
    struct dhcpMessage packet;

    init_packet(&packet, DHCPDISCOVER);
    packet.xid = xid;
    if (requested)
        add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_REQUESTED_IP,
                       requested);

    /* Request a RFC-specified max size to work around buggy servers. */
    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE,
                   DHCP_MAX_SIZE, htons(576));
    add_option_request_list(packet.options, DHCP_OPTIONS_BUFSIZE);
    log_line("Sending discover...");
    return bcast_raw_packet(&packet);
}

/* Broadcasts a DHCP request message */
int send_selecting(uint32_t xid, uint32_t server, uint32_t requested)
{
    struct dhcpMessage packet;
    struct in_addr addr;

    init_packet(&packet, DHCPREQUEST);
    packet.xid = xid;

    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_REQUESTED_IP,
                   requested);
    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_SERVER_ID, server);

    add_option_request_list(packet.options, DHCP_OPTIONS_BUFSIZE);
    addr.s_addr = requested;
    log_line("Sending select for %s...", inet_ntoa(addr));
    return bcast_raw_packet(&packet);
}

/* Unicasts or broadcasts a DHCP renew message */
int send_renew(uint32_t xid, uint32_t server, uint32_t ciaddr)
{
    struct dhcpMessage packet;

    init_packet(&packet, DHCPREQUEST);
    packet.xid = xid;
    packet.ciaddr = ciaddr;

    add_option_request_list(packet.options, DHCP_OPTIONS_BUFSIZE);
    log_line("Sending renew...");
    if (server)
        return kernel_packet(&packet, ciaddr, DHCP_CLIENT_PORT, server,
                             DHCP_SERVER_PORT);
    else
        return bcast_raw_packet(&packet);
}

/* Broadcast a DHCP decline message */
int send_decline(uint32_t xid, uint32_t server, uint32_t requested)
{
    struct dhcpMessage packet;

    /* Fill in: op, htype, hlen, cookie, chaddr, random xid fields,
     * client-id option (unless -C), message type option:
     */
    init_packet(&packet, DHCPDECLINE);

    /* RFC 2131 says DHCPDECLINE's xid is randomly selected by client,
     * but in case the server is buggy and wants DHCPDECLINE's xid
     * to match the xid which started entire handshake,
     * we use the same xid we used in initial DHCPDISCOVER:
     */
    packet.xid = xid;
    /* DHCPDECLINE uses "requested ip", not ciaddr, to store offered IP */
    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_REQUESTED_IP,
                   requested);
    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_SERVER_ID, server);

    log_line("Sending decline...");
    return bcast_raw_packet(&packet);
}

/* Unicasts a DHCP release message */
int send_release(uint32_t server, uint32_t ciaddr)
{
    struct dhcpMessage packet;

    init_packet(&packet, DHCPRELEASE);
    packet.xid = random_xid();
    packet.ciaddr = ciaddr;

    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_REQUESTED_IP,
                   ciaddr);
    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_SERVER_ID, server);

    log_line("Sending release...");
    return kernel_packet(&packet, ciaddr, DHCP_CLIENT_PORT, server,
                         DHCP_SERVER_PORT);
}
