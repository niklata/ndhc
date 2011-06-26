/* packet.c - send and react to DHCP message packets
 * Time-stamp: <2011-06-11 11:15:09 njk>
 *
 * (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
 * (c) 2001 Russ Dill <Russ.Dill@asu.edu>
 * Kernel BPF filter is (c) 2006, 2007 Stefan Rompf <sux@loplof.de>.
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
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <time.h>
#include <errno.h>

#include "packet.h"
#include "arp.h"
#include "ifchange.h"
#include "sys.h"
#include "log.h"
#include "io.h"
#include "options.h"
#include "strl.h"

/* Returns fd of new listen socket bound to @ip:@port on interface @inf
 * on success, or -1 on failure. */
static int create_udp_listen_socket(unsigned int ip, int port, char *inf)
{
    log_line("Opening listen socket on 0x%08x:%d %s", ip, port, inf);

    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_error("create_udp_listen_socket: socket failed: %s",
                  strerror(errno));
        goto out;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1) {
        log_error("create_udp_listen_socket: set reuse addr failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) == -1) {
        log_error("create_udp_listen_socket: set broadcast failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) == -1) {
        log_error("create_udp_listen_socket: set don't route failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    strlcpy(ifr.ifr_name, inf, IFNAMSIZ);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_error("create_udp_listen_socket: set bind to device failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("create_udp_listen_socket: set non-blocking failed: %s",
                  strerror(errno));
        goto out_fd;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = ip,
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1)
        goto out_fd;

    return fd;
  out_fd:
    close(fd);
  out:
    return -1;
}

static int create_raw_listen_socket(int ifindex)
{
    /*
     * Comment:
     *   I've selected not to see LL header, so BPF doesn't see it, too.
     *   The filter may also pass non-IP and non-ARP packets, but we do
     *   a more complete check when receiving the message in userspace.
     * and filter shamelessly stolen from:
     *   http://www.flamewarmaster.de/software/dhcpclient/
     *
     *  Copyright: 2006, 2007 Stefan Rompf <sux@loplof.de>.
     *  License: GPL v2.
     */
#define SERVER_AND_CLIENT_PORTS  ((67 << 16) + 68)
    static const struct sock_filter filter_instr[] = {
        /* check for udp */
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 9),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 2, 0),     /* L5, L1, is UDP? */
        /* ugly check for arp on ethernet-like and IPv4 */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 2),                      /* L1: */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x08000604, 3, 4),      /* L3, L4 */
        /* skip IP header */
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0),                     /* L5: */
        /* check udp source and destination ports */
        BPF_STMT(BPF_LD|BPF_W|BPF_IND, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SERVER_AND_CLIENT_PORTS, 0, 1),/* L3, L4 */
        /* returns */
        BPF_STMT(BPF_RET|BPF_K, 0x0fffffff ),                   /* L3: pass */
        BPF_STMT(BPF_RET|BPF_K, 0),                             /* L4: reject */
    };
    static const struct sock_fprog filter_prog = {
        .len = sizeof(filter_instr) / sizeof(filter_instr[0]),
        /* casting const away: */
        .filter = (struct sock_filter *) filter_instr,
    };

    log_line("Opening raw socket on ifindex %d", ifindex);

    int fd;
    if ((fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        log_error("create_raw_listen_socket: socket failed: %s",
                  strerror(errno));
        goto out;
    }

    // Ignoring error since kernel may lack support for BPF.
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog,
                   sizeof filter_prog) >= 0)
        log_line("Attached filter to raw socket fd %d", fd);

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) == -1) {
        log_error("create_raw_listen_socket: failed to set don't route: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("create_raw_listen_socket: set non-blocking failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    struct sockaddr_ll sock = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = ifindex,
    };
    if (bind(fd, (struct sockaddr *)&sock, sizeof(sock)) < 0) {
        log_error("create_raw_listen_socket: bind failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    return fd;
out_fd:
    close(fd);
out:
    return -1;
}

// Read a packet from a cooked socket.  Returns -1 on fatal error, -2 on
// transient error.
static int get_packet(struct dhcpmsg *packet, int fd)
{
    int bytes;

    memset(packet, 0, sizeof *packet);
    bytes = safe_read(fd, (char *)packet, sizeof *packet);
    if (bytes == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_line("Read on listen socket failed: %s", strerror(errno));
        return -1;
    }

    log_line("Received a packet via cooked socket.");

    return bytes;
}

// When summing ones-complement 16-bit values using a 32-bit unsigned
// representation, fold the carry bits that have spilled into the upper
// 16-bits of the 32-bit unsigned value back into the 16-bit ones-complement
// binary value.
static inline uint16_t foldcarry(uint32_t v)
{
    v = (v >> 16) + (v & 0xffff);
    v += v >> 16;
    return v;
}

// This function is not suitable for summing buffers that are greater than
// 128k bytes in length: failure case will be incorrect checksums via
// unsigned overflow, which is a defined operation and is safe.  This limit
// should not be an issue for IPv4 or IPv6 packet, which are limited to
// at most 64k bytes.
static uint16_t net_checksum(void *buf, size_t size)
{
    uint32_t sum = 0;
    int odd = size & 0x01;
    size_t i;
    size &= ~((size_t)0x01);
    size >>= 1;
    uint8_t *b = buf;
    for (i = 0; i < size; ++i) {
        uint16_t hi = b[i*2];
        uint16_t lo = b[i*2+1];
        sum += ntohs((lo + (hi << 8)));
    }
    if (odd) {
        uint16_t hi = b[i*2];
        uint16_t lo = 0;
        sum += ntohs((lo + (hi << 8)));
    }
    return ~foldcarry(sum);
}

// For two sequences of bytes A and B that return checksums CS(A) and CS(B),
// this function will calculate the checksum CS(AB) of the concatenated value
// AB given the checksums of the individual parts CS(A) and CS(B).
static inline uint16_t net_checksum_add(uint16_t a, uint16_t b)
{
    return ~foldcarry((~a & 0xffff) + (~b & 0xffff));
}

// Returns 1 if IP checksum is correct, otherwise 0.
static int ip_checksum(struct ip_udp_dhcp_packet *packet)
{
    return net_checksum(&packet->ip, sizeof packet->ip) == 0;
}

// Returns 1 if UDP checksum is correct, otherwise 0.
static int udp_checksum(struct ip_udp_dhcp_packet *packet)
{
    struct iphdr ph = {
        .saddr = packet->ip.saddr,
        .daddr = packet->ip.daddr,
        .protocol = packet->ip.protocol,
        .tot_len = packet->udp.len,
    };
    uint16_t udpcs = net_checksum(&packet->udp, ntohs(packet->udp.len));
    uint16_t hdrcs = net_checksum(&ph, sizeof ph);
    uint16_t cs = net_checksum_add(udpcs, hdrcs);
    return cs == 0;
}

// Read a packet from a raw socket.  Returns -1 on fatal error, -2 on
// transient error.
static int get_raw_packet(struct dhcpmsg *payload, int fd)
{
    struct ip_udp_dhcp_packet packet;
    memset(&packet, 0, sizeof packet);

    ssize_t inc = safe_read(fd, (char *)&packet, sizeof packet);
    if (inc == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_line("get_raw_packet: read error %s", strerror(errno));
        return -1;
    }

    if (inc > ntohs(packet.ip.tot_len))
        log_line("Discarded extra bytes after reading a single UDP datagram.");

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
    if (!ip_checksum(&packet)) {
        log_line("IP header checksum incorrect");
        return -2;
    }
    if (ntohs(packet.udp.dest) != DHCP_CLIENT_PORT) {
        log_line("UDP destination port incorrect: %d", ntohs(packet.udp.dest));
        return -2;
    }
    if (ntohs(packet.udp.len) != ntohs(packet.ip.tot_len) - sizeof packet.ip) {
        log_line("UDP header length incorrect");
        return -2;
    }

    if (packet.udp.check && !udp_checksum(&packet)) {
        log_error("Packet with bad UDP checksum received, ignoring");
        return -2;
    }

    size_t l = ntohs(packet.ip.tot_len) - sizeof packet.ip - sizeof packet.udp; 
    memcpy(payload, &packet.data, l);

    log_line("Received a packet via raw socket.");
    return l;
}

// Broadcast a DHCP message using a raw socket.
static int send_dhcp_raw(struct dhcpmsg *payload)
{
    int fd, r = -1;

    if ((fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        log_error("send_dhcp_raw: socket failed: %s", strerror(errno));
        goto out;
    }
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) == -1) {
        log_error("send_dhcp_raw: failed to set don't route: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("send_dhcp_raw: set non-blocking failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    struct sockaddr_ll dest = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(dest.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);
    if (bind(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll)) < 0) {
        log_error("send_dhcp_raw: bind failed: %s", strerror(errno));
        goto out_fd;
    }

    // Send packets that are as short as possible, since some servers are buggy
    // and drop packets that are longer than 562 bytes.
    ssize_t endloc = get_end_option_idx(payload->options, DHCP_OPTIONS_BUFSIZE);
    if (endloc < 0) {
        log_error("send_dhcp_raw: attempt to send packet with no DHCP_END");
        goto out_fd;
    }
    size_t padding = DHCP_OPTIONS_BUFSIZE - 1 - endloc;
    size_t iud_len = sizeof(struct ip_udp_dhcp_packet) - padding;
    size_t ud_len = sizeof(struct udp_dhcp_packet) - padding;
    // UDP checksumming needs a temporary pseudoheader with a fake length.
    struct ip_udp_dhcp_packet iudmsg = {
        .ip = {
            .protocol = IPPROTO_UDP,
            .saddr = INADDR_ANY,
            .daddr = INADDR_BROADCAST,
            .tot_len = htons(ud_len),
        },
        .udp = {
            .source = htons(DHCP_CLIENT_PORT),
            .dest = htons(DHCP_SERVER_PORT),
            .len = htons(ud_len),
        },
        .data = *payload,
    };
    iudmsg.udp.check = net_checksum(&iudmsg, iud_len);
    // Set the true IP packet length for the final packet.
    iudmsg.ip.tot_len = htons(iud_len);
    iudmsg.ip.ihl = sizeof iudmsg.ip >> 2;
    iudmsg.ip.version = IPVERSION;
    iudmsg.ip.ttl = IPDEFTTL;
    iudmsg.ip.check = net_checksum(&iudmsg.ip, sizeof iudmsg.ip);

    r = safe_sendto(fd, (const char *)&iudmsg, iud_len, 0,
                    (struct sockaddr *)&dest, sizeof dest);
    if (r == -1)
        log_error("send_dhcp_raw: sendto failed: %s", strerror(errno));
  out_fd:
    close(fd);
  out:
    return r;
}

// Broadcast a DHCP message using a UDP socket.
static int send_dhcp_cooked(struct dhcpmsg *payload, uint32_t source_ip,
                            uint32_t dest_ip)
{
    int fd, result = -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_error("send_dhcp_cooked: socket failed: %s", strerror(errno));
        goto out;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1) {
        log_error("send_dhcp_cooked: set reuse addr failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) == -1) {
        log_error("send_dhcp_cooked: failed to set don't route: %s",
                  strerror(errno));
        goto out_fd;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    strlcpy(ifr.ifr_name, client_config.interface, IFNAMSIZ);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_error("send_dhcp_cooked: set bind to device failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("send_dhcp_cooked: set non-blocking failed: %s",
                  strerror(errno));
        goto out_fd;
    }

    struct sockaddr_in laddr = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_CLIENT_PORT),
        .sin_addr.s_addr = source_ip,
    };
    if (bind(fd, (struct sockaddr *)&laddr, sizeof(struct sockaddr)) == -1) {
        log_error("send_dhcp_cooked: bind failed: %s", strerror(errno));
        goto out_fd;
    }

    struct sockaddr_in raddr = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr.s_addr = dest_ip,
    };
    if (connect(fd, (struct sockaddr *)&raddr, sizeof(struct sockaddr)) == -1) {
        log_error("send_dhcp_cooked: connect failed: %s", strerror(errno));
        goto out_fd;
    }

    ssize_t endloc = get_end_option_idx(payload->options,
                                        DHCP_OPTIONS_BUFSIZE);
    if (endloc < 0) {
        log_error("send_dhcp_cooked: attempt to send packet with no DHCP_END");
        goto out_fd;
    }
    size_t payload_len = sizeof *payload - DHCP_OPTIONS_BUFSIZE - 1 - endloc;
    result = safe_write(fd, (const char *)payload, payload_len);
    if (result == -1)
        log_error("send_dhcp_cooked: write failed: %s", strerror(errno));
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
            cs->listenFd = create_raw_listen_socket(client_config.ifindex);
            break;
        case LM_KERNEL:
            cs->listenFd =
                create_udp_listen_socket(INADDR_ANY, DHCP_CLIENT_PORT,
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
                                  struct dhcpmsg *packet,
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
                                   struct dhcpmsg *packet,
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
    struct dhcpmsg packet;
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

    if (len < sizeof packet - sizeof packet.options) {
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
static void init_header(struct dhcpmsg *packet, char type)
{
    memset(packet, 0, sizeof *packet);
    packet->op = 1; // BOOTREQUEST (client)
    packet->htype = 1; // ETH_10MB
    packet->hlen = 6; // ETH_10MB_LEN
    packet->cookie = htonl(DHCP_MAGIC);
    packet->options[0] = DHCP_END;
    add_u32_option(packet->options, DHCP_OPTIONS_BUFSIZE, DHCP_MESSAGE_TYPE,
                   type);
}

/* initialize a packet with the proper defaults */
static void init_packet(struct dhcpmsg *packet, char type)
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

/* Broadcast a DHCP discover packet to the network, with an optionally
 * requested IP */
int send_discover(uint32_t xid, uint32_t requested)
{
    struct dhcpmsg packet;

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
    return send_dhcp_raw(&packet);
}

/* Broadcasts a DHCP request message */
int send_selecting(uint32_t xid, uint32_t server, uint32_t requested)
{
    struct dhcpmsg packet;
    struct in_addr addr;

    init_packet(&packet, DHCPREQUEST);
    packet.xid = xid;

    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_REQUESTED_IP,
                   requested);
    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_SERVER_ID, server);

    add_option_request_list(packet.options, DHCP_OPTIONS_BUFSIZE);
    addr.s_addr = requested;
    log_line("Sending select for %s...", inet_ntoa(addr));
    return send_dhcp_raw(&packet);
}

/* Unicasts or broadcasts a DHCP renew message */
int send_renew(uint32_t xid, uint32_t server, uint32_t ciaddr)
{
    struct dhcpmsg packet;

    init_packet(&packet, DHCPREQUEST);
    packet.xid = xid;
    packet.ciaddr = ciaddr;

    add_option_request_list(packet.options, DHCP_OPTIONS_BUFSIZE);
    log_line("Sending renew...");
    if (server)
        return send_dhcp_cooked(&packet, ciaddr, server);
    else
        return send_dhcp_raw(&packet);
}

/* Broadcast a DHCP decline message */
int send_decline(uint32_t xid, uint32_t server, uint32_t requested)
{
    struct dhcpmsg packet;

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
    return send_dhcp_raw(&packet);
}

/* Unicasts a DHCP release message */
int send_release(uint32_t server, uint32_t ciaddr)
{
    struct dhcpmsg packet;

    init_packet(&packet, DHCPRELEASE);
    packet.xid = random_xid();
    packet.ciaddr = ciaddr;

    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_REQUESTED_IP,
                   ciaddr);
    add_u32_option(packet.options, DHCP_OPTIONS_BUFSIZE, DHCP_SERVER_ID, server);

    log_line("Sending release...");
    return send_dhcp_cooked(&packet, ciaddr, server);
}

