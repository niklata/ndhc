/* packet.c - send and react to DHCP message packets
 * Time-stamp: <2011-07-03 18:53:28 njk>
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
#include <linux/filter.h>
#include <time.h>
#include <errno.h>

#include "dhcp.h"
#include "state.h"
#include "arp.h"
#include "ifchange.h"
#include "sys.h"
#include "log.h"
#include "io.h"
#include "options.h"
#include "strl.h"
#include "random.h"

typedef enum {
    LM_NONE = 0,
    LM_COOKED,
    LM_RAW
} listen_mode_t;

// Returns fd of new udp socket bound on success, or -1 on failure.
static int create_udp_socket(uint32_t ip, uint16_t port, char *iface)
{
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_error("create_udp_socket: socket failed: %s", strerror(errno));
        goto out;
    }
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1) {
        log_error("create_udp_socket: Set reuse addr failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) == -1) {
        log_error("create_udp_socket: Set don't route failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    strlcpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_error("create_udp_socket: Set bind to device failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("create_udp_socket: Set non-blocking failed: %s",
                  strerror(errno));
        goto out_fd;
    }

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = ip,
    };
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == -1)
        goto out_fd;

    return fd;
  out_fd:
    close(fd);
  out:
    return -1;
}

// Returns fd of new listen socket bound to 0.0.0.0:@68 on interface @inf
// on success, or -1 on failure.
static int create_udp_listen_socket(struct client_state_t *cs, char *inf)
{
    int fd = create_udp_socket(INADDR_ANY, DHCP_CLIENT_PORT, inf);
    if (fd == -1)
        return -1;
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) == -1) {
        log_error("create_udp_listen_socket: Set broadcast failed: %s",
                  strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

// Broadcast a DHCP message using a UDP socket.
static int send_dhcp_cooked(struct client_state_t *cs, struct dhcpmsg *payload)
{
    int ret = -1;
    int fd = create_udp_socket(cs->clientAddr, DHCP_CLIENT_PORT,
                               client_config.interface);
    if (fd == -1)
        goto out;

    struct sockaddr_in raddr = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr.s_addr = cs->serverAddr,
    };
    if (connect(fd, (struct sockaddr *)&raddr, sizeof(struct sockaddr)) == -1) {
        log_error("send_dhcp_cooked: connect failed: %s", strerror(errno));
        goto out_fd;
    }

    ssize_t endloc = get_end_option_idx(payload);
    if (endloc < 0) {
        log_error("send_dhcp_cooked: Attempt to send packet with no DHCP_END.");
        goto out_fd;
    }
    size_t payload_len =
        sizeof *payload - (sizeof payload->options - 1 - endloc);
    ret = safe_write(fd, (const char *)payload, payload_len);
    if (ret == -1)
        log_error("send_dhcp_cooked: write failed: %s", strerror(errno));
  out_fd:
    close(fd);
  out:
    return ret;
}

// Read a packet from a cooked socket.  Returns -1 on fatal error, -2 on
// transient error.
static int get_cooked_packet(struct dhcpmsg *packet, int fd)
{
    memset(packet, 0, sizeof *packet);
    int bytes = safe_read(fd, (char *)packet, sizeof *packet);
    if (bytes == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_line("Read on listen socket failed: %s", strerror(errno));
        return -1;
    }
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

static int get_raw_packet_validate_bpf(struct ip_udp_dhcp_packet *packet)
{
    if (packet->ip.version != IPVERSION) {
        log_line("IP version is not IPv4.");
        return 0;
    }
    if (packet->ip.ihl != sizeof packet->ip >> 2) {
        log_line("IP header length incorrect.");
        return 0;
    }
    if (packet->ip.protocol != IPPROTO_UDP) {
        log_line("IP header is not UDP: %d", packet->ip.protocol);
        return 0;
    }
    if (ntohs(packet->udp.dest) != DHCP_CLIENT_PORT) {
        log_line("UDP destination port incorrect: %d", ntohs(packet->udp.dest));
        return 0;
    }
    if (ntohs(packet->udp.len) !=
        ntohs(packet->ip.tot_len) - sizeof packet->ip) {
        log_line("UDP header length incorrect.");
        return 0;
    }
    return 1;
}

// Read a packet from a raw socket.  Returns -1 on fatal error, -2 on
// transient error.
static int get_raw_packet(struct client_state_t *cs, struct dhcpmsg *payload)
{
    struct ip_udp_dhcp_packet packet;
    memset(&packet, 0, sizeof packet);

    ssize_t inc = safe_read(cs->listenFd, (char *)&packet, sizeof packet);
    if (inc == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_line("get_raw_packet: read error %s", strerror(errno));
        return -1;
    }

    if (inc > ntohs(packet.ip.tot_len))
        log_line("Discarded extra bytes after reading a single UDP datagram.");

    if (!cs->using_dhcp_bpf && !get_raw_packet_validate_bpf(&packet))
        return -2;

    if (!ip_checksum(&packet)) {
        log_line("IP header checksum incorrect.");
        return -2;
    }
    if (packet.udp.check && !udp_checksum(&packet)) {
        log_error("Packet with bad UDP checksum received.  Ignoring.");
        return -2;
    }

    size_t l = ntohs(packet.ip.tot_len) - sizeof packet.ip - sizeof packet.udp; 
    memcpy(payload, &packet.data, l);
    return l;
}

static int create_raw_socket(struct client_state_t *cs, struct sockaddr_ll *sa,
                             const struct sock_fprog *filter_prog)
{
    int fd;
    if ((fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        log_error("create_raw_socket: socket failed: %s", strerror(errno));
        goto out;
    }

    if (cs) {
        if (filter_prog && (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
                            filter_prog, sizeof *filter_prog) != -1))
            cs->using_dhcp_bpf = 1;
        else
            cs->using_dhcp_bpf = 0;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) == -1) {
        log_error("create_raw_socket: Failed to set don't route: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("create_raw_socket: Set non-blocking failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (bind(fd, (struct sockaddr *)sa, sizeof *sa) < 0) {
        log_error("create_raw_socket: bind failed: %s", strerror(errno));
        goto out_fd;
    }
    return fd;
out_fd:
    close(fd);
out:
    return -1;
}

static int create_raw_listen_socket(struct client_state_t *cs, int ifindex)
{
    static const struct sock_filter sf_dhcp[] = {
        // Verify that the packet has a valid IPv4 version nibble and
        // that no IP options are defined.
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x45, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Verify that the IP header has a protocol number indicating UDP.
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 9),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Packet is UDP.  Advance X past the IP header.
        BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),
        // Verify that the UDP client and server ports match that of the
        // IANA-assigned DHCP ports.
        BPF_STMT(BPF_LD + BPF_W + BPF_IND, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                 (DHCP_SERVER_PORT << 16) + DHCP_CLIENT_PORT, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Get the UDP length field and store it in X.
        BPF_STMT(BPF_LD + BPF_H + BPF_IND, 4),
        BPF_STMT(BPF_MISC + BPF_TAX, 0),
        // Get the IPv4 length field and store it in A and M[0].
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 2),
        BPF_STMT(BPF_ST, 0),
        // Verify that UDP length = IP length - IP header size
        BPF_STMT(BPF_ALU + BPF_SUB + BPF_K, 20),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Pass the number of octets that are specified in the IPv4 header.
        BPF_STMT(BPF_LD + BPF_MEM, 0),
        BPF_STMT(BPF_RET + BPF_A, 0),
    };
    static const struct sock_fprog sfp_dhcp = {
        .len = sizeof sf_dhcp / sizeof sf_dhcp[0],
        .filter = (struct sock_filter *)sf_dhcp,
    };
    struct sockaddr_ll sa = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = ifindex,
    };
    return create_raw_socket(cs, &sa, &sfp_dhcp);
}

// Broadcast a DHCP message using a raw socket.
static int send_dhcp_raw(struct dhcpmsg *payload)
{
    int ret = -1;
    struct sockaddr_ll da = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_pkttype = PACKET_BROADCAST,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(da.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);
    int fd = create_raw_socket(NULL, &da, NULL);
    if (fd == -1)
        return ret;

    // Send packets that are as short as possible, since some servers are buggy
    // and drop packets that are longer than 562 bytes.
    ssize_t endloc = get_end_option_idx(payload);
    if (endloc < 0) {
        log_error("send_dhcp_raw: Attempt to send packet with no DHCP_END.");
        close(fd);
        return ret;
    }
    size_t padding = sizeof payload->options - 1 - endloc;
    size_t iud_len = sizeof(struct ip_udp_dhcp_packet) - padding;
    size_t ud_len = sizeof(struct udp_dhcp_packet) - padding;

    struct iphdr ph = {
        .saddr = INADDR_ANY,
        .daddr = INADDR_BROADCAST,
        .protocol = IPPROTO_UDP,
        .tot_len = htons(ud_len),
    };
    struct ip_udp_dhcp_packet iudmsg = {
        .ip = {
            .saddr = INADDR_ANY,
            .daddr = INADDR_BROADCAST,
            .protocol = IPPROTO_UDP,
            .tot_len = htons(iud_len),
            .ihl = sizeof iudmsg.ip >> 2,
            .version = IPVERSION,
            .ttl = IPDEFTTL,
        },
        .udp = {
            .source = htons(DHCP_CLIENT_PORT),
            .dest = htons(DHCP_SERVER_PORT),
            .len = htons(ud_len),
        },
        .data = *payload,
    };
    uint16_t udpcs = net_checksum(&iudmsg.udp, ud_len);
    uint16_t phcs = net_checksum(&ph, sizeof ph);
    iudmsg.udp.check = net_checksum_add(udpcs, phcs);
    iudmsg.ip.check = net_checksum(&iudmsg.ip, sizeof iudmsg.ip);

    ret = safe_sendto(fd, (const char *)&iudmsg, iud_len, 0,
                      (struct sockaddr *)&da, sizeof da);
    if (ret == -1)
        log_error("send_dhcp_raw: sendto failed: %s", strerror(errno));
    close(fd);
    return ret;
}

// Switch listen socket between raw (if-bound), kernel (ip-bound), and none
static void change_listen_mode(struct client_state_t *cs, int new_mode)
{
    cs->listenMode = new_mode;
    if (cs->listenFd >= 0) {
        epoll_del(cs, cs->listenFd);
        close(cs->listenFd);
        cs->listenFd = -1;
    }
    if (new_mode == LM_NONE)
        return;
    cs->listenFd = new_mode == LM_RAW ?
        create_raw_listen_socket(cs, client_config.ifindex) :
        create_udp_listen_socket(cs, client_config.interface);
    if (cs->listenFd < 0) {
        log_error("FATAL: Couldn't listen on socket: %s.", strerror(errno));
        exit(EXIT_FAILURE);
    }
    epoll_add(cs, cs->listenFd);
}

void set_listen_raw(struct client_state_t *cs)
{
    change_listen_mode(cs, LM_RAW);
}

void set_listen_cooked(struct client_state_t *cs)
{
    change_listen_mode(cs, LM_COOKED);
}

void set_listen_none(struct client_state_t *cs)
{
    change_listen_mode(cs, LM_NONE);
}

static int validate_dhcp_packet(struct client_state_t *cs, int len,
                                struct dhcpmsg *packet, uint8_t **msg)
{
    ssize_t optlen;
    if (len < sizeof *packet - sizeof packet->options) {
        log_line("Packet is too short to contain magic cookie.  Ignoring.");
        return 0;
    }
    if (ntohl(packet->cookie) != DHCP_MAGIC) {
        log_line("Packet with bad magic number. Ignoring.");
        return 0;
    }
    if (packet->xid != cs->xid) {
        log_line("Packet XID %lx does not equal our XID %lx.  Ignoring.",
                 packet->xid, cs->xid);
        return 0;
    }
    if (!(*msg = get_option_data(packet, DHCP_MESSAGE_TYPE, &optlen))) {
        log_line("Packet does not specify a DHCP message type.  Ignoring.");
        return 0;
    }
    return 1;
}

void handle_packet(struct client_state_t *cs)
{
    uint8_t *message = NULL;
    int len;
    struct dhcpmsg packet;

    if (cs->listenMode == LM_NONE)
        return;
    len = cs->listenMode == LM_RAW ?
        get_raw_packet(cs, &packet) : get_cooked_packet(&packet, cs->listenFd);

    if (len < 0) {
        // Transient issue handled by packet collection functions.
        if (len == -2 || (len == -1 && errno == EINTR))
            return;
        log_error("Error reading from listening socket: %s.  Reopening.",
                  strerror(errno));
        change_listen_mode(cs, cs->listenMode);
    }

    if (!validate_dhcp_packet(cs, len, &packet, &message))
        return;
    packet_action(cs, &packet, message);
}

static void add_option_vendor(struct dhcpmsg *packet)
{
    size_t len = strlen(client_config.vendor);
    if (len)
        add_option_string(packet, DHCP_VENDOR, client_config.vendor, len);
    else
        add_option_string(packet, DHCP_VENDOR, "ndhc", sizeof "ndhc" - 1);
}

static void add_option_clientid(struct dhcpmsg *packet)
{
    char buf[sizeof client_config.clientid + 1];
    size_t len = 6;
    buf[0] = 1; // Ethernet MAC
    if (!client_config.clientid_mac) {
        size_t slen = strlen(client_config.clientid);
        if (!slen) {
            memcpy(buf+1, client_config.arp, len);
        } else {
            buf[0] = 0; // Not a hardware address
            len = slen;
            memcpy(buf+1, client_config.clientid, slen);
        }
    } else
        memcpy(buf+1, client_config.clientid, len);
    add_option_string(packet, DHCP_CLIENT_ID, buf, len+1);
}

static void add_option_hostname(struct dhcpmsg *packet)
{
    size_t len = strlen(client_config.hostname);
    if (len)
        add_option_string(packet, DHCP_HOST_NAME, client_config.hostname, len);
}

// Initialize a DHCP client packet that will be sent to a server
static struct dhcpmsg init_packet(char type, uint32_t xid)
{
    struct dhcpmsg packet = {
        .op = 1, // BOOTREQUEST (client)
        .htype = 1, // ETH_10MB
        .hlen = 6, // ETH_10MB_LEN
        .cookie = htonl(DHCP_MAGIC),
        .options[0] = DHCP_END,
        .xid = xid,
    };
    add_u8_option(&packet, DHCP_MESSAGE_TYPE, type);
    memcpy(packet.chaddr, client_config.arp, 6);
    add_option_clientid(&packet);
    return packet;
}

int send_discover(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPDISCOVER, cs->xid);
    if (cs->clientAddr)
        add_u32_option(&packet, DHCP_REQUESTED_IP, cs->clientAddr);
    add_u16_option(&packet, DHCP_MAX_SIZE,
                   htons(sizeof(struct ip_udp_dhcp_packet)));
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    log_line("Discovering DHCP servers...");
    return send_dhcp_raw(&packet);
}

int send_selecting(struct client_state_t *cs)
{
    char clibuf[INET_ADDRSTRLEN];
    struct dhcpmsg packet = init_packet(DHCPREQUEST, cs->xid);
    add_u32_option(&packet, DHCP_REQUESTED_IP, cs->clientAddr);
    add_u32_option(&packet, DHCP_SERVER_ID, cs->serverAddr);
    add_u16_option(&packet, DHCP_MAX_SIZE,
                   htons(sizeof(struct ip_udp_dhcp_packet)));
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    inet_ntop(AF_INET, &(struct in_addr){.s_addr = cs->clientAddr},
              clibuf, sizeof clibuf);
    log_line("Sending a selection request for %s...", clibuf);
    return send_dhcp_raw(&packet);
}

int send_renew(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPREQUEST, cs->xid);
    packet.ciaddr = cs->clientAddr;
    add_u16_option(&packet, DHCP_MAX_SIZE,
                   htons(sizeof(struct ip_udp_dhcp_packet)));
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    log_line("Sending a renew request...");
    return send_dhcp_cooked(cs, &packet);
}

int send_rebind(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPREQUEST, cs->xid);
    packet.ciaddr = cs->clientAddr;
    add_u32_option(&packet, DHCP_REQUESTED_IP, cs->clientAddr);
    add_u16_option(&packet, DHCP_MAX_SIZE,
                   htons(sizeof(struct ip_udp_dhcp_packet)));
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    log_line("Sending a rebind request...");
    return send_dhcp_raw(&packet);
}

int send_decline(struct client_state_t *cs, uint32_t server)
{
    struct dhcpmsg packet = init_packet(DHCPDECLINE, cs->xid);
    add_u32_option(&packet, DHCP_REQUESTED_IP, cs->clientAddr);
    add_u32_option(&packet, DHCP_SERVER_ID, server);
    log_line("Sending a decline message...");
    return send_dhcp_raw(&packet);
}

int send_release(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPRELEASE, libc_random_u32());
    packet.ciaddr = cs->clientAddr;
    add_u32_option(&packet, DHCP_REQUESTED_IP, cs->clientAddr);
    add_u32_option(&packet, DHCP_SERVER_ID, cs->serverAddr);
    log_line("Sending a release message...");
    return send_dhcp_cooked(cs, &packet);
}

