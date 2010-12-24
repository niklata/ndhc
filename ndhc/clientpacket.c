/* clientpacket.c
 *
 * Packet generation and dispatching functions for the DHCP client.
 *
 * Nicholas J. Kain <njkain at gmail dot com> 2004-2010
 * Russ Dill <Russ.Dill@asu.edu> July 2001
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dhcpd.h"
#include "packet.h"
#include "options.h"
#include "config.h"
#include "log.h"
#include "io.h"

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
    packet->op = BOOTREQUEST; /* client */
    packet->htype = ETH_10MB;
    packet->hlen = ETH_10MB_LEN;
    packet->cookie = htonl(DHCP_MAGIC);
    packet->options[0] = DHCP_END;
    add_simple_option(packet->options, DHCP_MESSAGE_TYPE, type);
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
    add_option_string(packet->options, client_config.clientid);
    if (client_config.hostname)
        add_option_string(packet->options, client_config.hostname);
    add_option_string(packet->options, (unsigned char *)&vendor_id);
}

/* Add a paramater request list for stubborn DHCP servers. Pull the data
 * from the struct in options.c. Don't do bounds checking here because it
 * goes towards the head of the packet. */
static void add_requests(struct dhcpMessage *packet)
{
    int end = end_option(packet->options);
    int i, len = 0;

    packet->options[end + OPT_CODE] = DHCP_PARAM_REQ;
    for (i = 0; options[i].code; i++)
        if (options[i].flags & OPTION_REQ)
            packet->options[end + OPT_DATA + len++] = options[i].code;
    packet->options[end + OPT_LEN] = len;
    packet->options[end + OPT_DATA + len] = DHCP_END;
}

/* Wrapper that broadcasts a raw dhcp packet on the bound interface. */
static int bcast_raw_packet(struct dhcpMessage *packet)
{
    return raw_packet(packet, INADDR_ANY, CLIENT_PORT, INADDR_BROADCAST,
                      SERVER_PORT, MAC_BCAST_ADDR, client_config.ifindex);
}

/* Broadcast a DHCP discover packet to the network, with an optionally
 * requested IP */
int send_discover(uint32_t xid, uint32_t requested)
{
    struct dhcpMessage packet;

    init_packet(&packet, DHCPDISCOVER);
    packet.xid = xid;
    if (requested)
        add_simple_option(packet.options, DHCP_REQUESTED_IP, requested);

    /* Request a RFC-specified max size to work around buggy servers. */
    add_simple_option(packet.options, DHCP_MAX_SIZE, htons(576));
    add_requests(&packet);
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

    add_simple_option(packet.options, DHCP_REQUESTED_IP, requested);
    add_simple_option(packet.options, DHCP_SERVER_ID, server);

    add_requests(&packet);
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

    add_requests(&packet);
    log_line("Sending renew...");
    if (server)
        return kernel_packet(&packet, ciaddr, CLIENT_PORT,
                             server, SERVER_PORT);
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
    add_simple_option(packet.options, DHCP_REQUESTED_IP, requested);
    add_simple_option(packet.options, DHCP_SERVER_ID, server);

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

    add_simple_option(packet.options, DHCP_REQUESTED_IP, ciaddr);
    add_simple_option(packet.options, DHCP_SERVER_ID, server);

    log_line("Sending release...");
    return kernel_packet(&packet, ciaddr, CLIENT_PORT, server, SERVER_PORT);
}

/* return -1 on errors that are fatal for the socket,
 * -2 for those that aren't */
int get_raw_packet(struct dhcpMessage *payload, int fd)
{
    struct ip_udp_dhcp_packet packet;
    uint16_t check;
    const int header_size = sizeof(struct iphdr) + sizeof(struct udphdr);
    const int packet_size = sizeof(struct ip_udp_dhcp_packet);

    memset(&packet, 0, packet_size);
    int len = safe_read(fd, (char *)&packet, packet_size);
    if (len == -1) {
        log_line("get_raw_packet: read error %s", strerror(errno));
        usleep(500000); /* possible down interface, looping condition */
        return -1;
    }

    if (len < header_size) {
        log_line("Message too short to contain IP + UDP headers, ignoring");
        sleep(1);
        return -2;
    }

    if (len < ntohs(packet.ip.tot_len)) {
        log_line("Truncated packet");
        return -2;
    }

    /* ignore any extra garbage bytes */
    len = ntohs(packet.ip.tot_len);

    /* Make sure its the right packet for us, and that it passes
     * sanity checks */
    if (packet.ip.protocol != IPPROTO_UDP) {
        log_line("IP header is not UDP: %d", packet.ip.protocol);
        sleep(1);
        return -2;
    }
    if (packet.ip.version != IPVERSION) {
        log_line("IP version is not IPv4");
        sleep(1);
        return -2;
    }
    if (packet.ip.ihl != sizeof packet.ip >> 2) {
        log_line("IP header length incorrect");
        sleep(1);
        return -2;
    }
    if (packet.udp.dest != htons(CLIENT_PORT)) {
        log_line("UDP destination port incorrect: %d", ntohs(packet.udp.dest));
        sleep(1);
        return -2;
    }
    if (len > packet_size) {
        log_line("Data longer than that of a IP+UDP+DHCP message: %d", len);
        sleep(1);
        return -2;
    }
    if (ntohs(packet.udp.len) != (short)(len - sizeof packet.ip)) {
        log_line("UDP header length incorrect");
        sleep(1);
        return -2;
    }

    /* check IP checksum */
    check = packet.ip.check;
    packet.ip.check = 0;
    if (check != checksum(&packet.ip, sizeof packet.ip)) {
        log_line("Bad IP header checksum, ignoring");
        return -1;
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

    if (ntohl(payload->cookie) != DHCP_MAGIC) {
        log_error("Packet with bad magic number, ignoring");
        return -2;
    }
    log_line("Received valid DHCP message.");
    return len - sizeof packet.ip - sizeof packet.udp;
}
