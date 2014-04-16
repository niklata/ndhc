/* dhcp.c - general DHCP protocol handling
 *
 * Copyright (c) 2004-2014 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <errno.h>
#include "nk/log.h"
#include "nk/io.h"
#include "nk/random.h"

#include "dhcp.h"
#include "state.h"
#include "arp.h"
#include "ifchange.h"
#include "sys.h"
#include "options.h"
#include "sockd.h"

static int get_udp_unicast_socket(struct client_state_t *cs)
{
    char buf[32];
    buf[0] = 'u';
    memcpy(buf + 1, &cs->clientAddr, sizeof cs->clientAddr);
    return request_sockd_fd(buf, 1 + sizeof cs->clientAddr, NULL);
}

static int get_raw_broadcast_socket(void)
{
    return request_sockd_fd("s", 1, NULL);
}

static int get_raw_listen_socket(struct client_state_t *cs)
{
    char resp;
    int fd = request_sockd_fd("L", 1, &resp);
    switch (resp) {
    case 'L': cs->using_dhcp_bpf = 1; break;
    case 'l': cs->using_dhcp_bpf = 0; break;
    default: suicide("%s: (%s) expected l or L sockd reply but got %c",
                     client_config.interface, __func__, resp);
    }
    return fd;
}

// Unicast a DHCP message using a UDP socket.
static ssize_t send_dhcp_unicast(struct client_state_t *cs,
                                 struct dhcpmsg *payload)
{
    ssize_t ret = -1;
    int fd = get_udp_unicast_socket(cs);
    if (fd < 0) {
        log_error("%s: (%s) get_udp_unicast_socket failed",
                  client_config.interface, __func__);
        goto out;
    }

    struct sockaddr_in raddr = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr.s_addr = cs->serverAddr,
    };
    if (connect(fd, (struct sockaddr *)&raddr, sizeof(struct sockaddr)) < 0) {
        log_error("%s: (%s) connect failed: %s", client_config.interface,
                  __func__, strerror(errno));
        goto out_fd;
    }

    // Send packets that are as short as possible.
    ssize_t endloc = get_end_option_idx(payload);
    if (endloc < 0) {
        log_error("%s: (%s) No end marker.  Not sending.",
                  client_config.interface, __func__);
        goto out_fd;
    }
    size_t payload_len =
        sizeof *payload - (sizeof payload->options - 1 - endloc);
    ret = safe_write(fd, (const char *)payload, payload_len);
    if (ret < 0 || (size_t)ret != payload_len)
        log_error("%s: (%s) write failed: %d", client_config.interface,
                  __func__, ret);
  out_fd:
    close(fd);
  out:
    return ret;
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
        log_warning("%s: IP version is not IPv4.", client_config.interface);
        return 0;
    }
    if (packet->ip.ihl != sizeof packet->ip >> 2) {
        log_warning("%s: IP header length incorrect.",
                    client_config.interface);
        return 0;
    }
    if (packet->ip.protocol != IPPROTO_UDP) {
        log_warning("%s: IP header is not UDP: %d",
                    client_config.interface, packet->ip.protocol);
        return 0;
    }
    if (ntohs(packet->udp.dest) != DHCP_CLIENT_PORT) {
        log_warning("%s: UDP destination port incorrect: %d",
                    client_config.interface, ntohs(packet->udp.dest));
        return 0;
    }
    if (ntohs(packet->udp.len) !=
        ntohs(packet->ip.tot_len) - sizeof packet->ip) {
        log_warning("%s: UDP header length incorrect.",
                    client_config.interface);
        return 0;
    }
    return 1;
}

// Read a packet from a raw socket.  Returns -1 on fatal error, -2 on
// transient error.
static ssize_t get_raw_packet(struct client_state_t *cs,
                              struct dhcpmsg *payload)
{
    struct ip_udp_dhcp_packet packet;
    memset(&packet, 0, sizeof packet);

    ssize_t inc = safe_read(cs->listenFd, (char *)&packet, sizeof packet);
    if (inc < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_warning("%s: (%s) read error %s", client_config.interface,
                    __func__, strerror(errno));
        return -1;
    }
    size_t iphdrlen = ntohs(packet.ip.tot_len);
    if ((size_t)inc != iphdrlen) {
        log_warning("%s: UDP length [%zd] does not match header length field [%zu].",
                    client_config.interface, inc, iphdrlen);
        return -2;
    }
    if (!cs->using_dhcp_bpf && !get_raw_packet_validate_bpf(&packet))
        return -2;

    if (!ip_checksum(&packet)) {
        log_warning("%s: IP header checksum incorrect.",
                    client_config.interface);
        return -2;
    }
    if (packet.udp.check && !udp_checksum(&packet)) {
        log_error("%s: Packet with bad UDP checksum received.  Ignoring.",
                  client_config.interface);
        return -2;
    }
    size_t l = iphdrlen - sizeof packet.ip - sizeof packet.udp;
    memcpy(payload, &packet.data, l);
    return l;
}

// Broadcast a DHCP message using a raw socket.
static ssize_t send_dhcp_raw(struct dhcpmsg *payload)
{
    ssize_t ret = -1;
    int fd = get_raw_broadcast_socket();
    if (fd < 0) {
        log_error("%s: (%s) get_raw_broadcast_socket failed",
                  client_config.interface, __func__);
        return ret;
    }

    // Send packets that are as short as possible.
    ssize_t endloc = get_end_option_idx(payload);
    if (endloc < 0) {
        log_error("%s: (%s) No end marker.  Not sending.",
                  client_config.interface, __func__);
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
        .data = *payload,
    };
    iudmsg.udp.source = htons(DHCP_CLIENT_PORT);
    iudmsg.udp.dest = htons(DHCP_SERVER_PORT);
    iudmsg.udp.len = htons(ud_len);
    iudmsg.udp.check = 0;
    uint16_t udpcs = net_checksum(&iudmsg.udp, ud_len);
    uint16_t phcs = net_checksum(&ph, sizeof ph);
    iudmsg.udp.check = net_checksum_add(udpcs, phcs);
    iudmsg.ip.check = net_checksum(&iudmsg.ip, sizeof iudmsg.ip);

    struct sockaddr_ll da = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_pkttype = PACKET_BROADCAST,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(da.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);
    ret = safe_sendto(fd, (const char *)&iudmsg, iud_len, 0,
                      (struct sockaddr *)&da, sizeof da);
    if (ret < 0 || (size_t)ret != iud_len) {
        if (ret < 0)
            log_error("%s: (%s) sendto failed: %s", client_config.interface,
                      __func__, strerror(errno));
        else
            log_error("%s: (%s) sendto short write: %z < %zu",
                      client_config.interface, __func__, ret, iud_len);
    }
    close(fd);
    return ret;
}

void start_dhcp_listen(struct client_state_t *cs)
{
    if (cs->listenFd >= 0)
        return;
    cs->listenFd = get_raw_listen_socket(cs);
    if (cs->listenFd < 0)
        suicide("%s: FATAL: Couldn't listen on socket: %s",
                client_config.interface, strerror(errno));
    epoll_add(cs->epollFd, cs->listenFd);
}

void stop_dhcp_listen(struct client_state_t *cs)
{
    if (cs->listenFd < 0)
        return;
    epoll_del(cs->epollFd, cs->listenFd);
    close(cs->listenFd);
    cs->listenFd = -1;
}

static int validate_dhcp_packet(struct client_state_t *cs, size_t len,
                                struct dhcpmsg *packet, uint8_t *msgtype)
{
    if (len < offsetof(struct dhcpmsg, options)) {
        log_warning("%s: Packet is too short to contain magic cookie.  Ignoring.",
                    client_config.interface);
        return 0;
    }
    if (ntohl(packet->cookie) != DHCP_MAGIC) {
        log_warning("%s: Packet with bad magic number. Ignoring.",
                    client_config.interface);
        return 0;
    }
    if (packet->xid != cs->xid) {
        log_warning("%s: Packet XID %lx does not equal our XID %lx.  Ignoring.",
                    client_config.interface, packet->xid, cs->xid);
        return 0;
    }
    if (memcmp(packet->chaddr, client_config.arp, sizeof client_config.arp)) {
        log_warning("%s: Packet client MAC %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x does not equal our MAC %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x.  Ignoring it.",
                    client_config.interface,
                    packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
                    packet->chaddr[3], packet->chaddr[4], packet->chaddr[5],
                    client_config.arp[0], client_config.arp[1],
                    client_config.arp[2], client_config.arp[3],
                    client_config.arp[4], client_config.arp[5]);
        return 0;
    }
    *msgtype = get_option_msgtype(packet);
    if (!*msgtype) {
        log_warning("%s: Packet does not specify a DHCP message type.  Ignoring.",
                    client_config.interface);
        return 0;
    }
    char clientid[MAX_DOPT_SIZE];
    size_t cidlen = get_option_clientid(packet, clientid, MAX_DOPT_SIZE);
    if (cidlen == 0)
        return 1;
    if (memcmp(client_config.clientid, clientid,
               min_size_t(cidlen, client_config.clientid_len))) {
        log_warning("%s: Packet clientid does not match our clientid.  Ignoring.",
                    client_config.interface);
        return 0;
    }
    return 1;
}

void handle_packet(struct client_state_t *cs)
{
    if (cs->listenFd < 0)
        return;
    struct dhcpmsg packet;
    ssize_t r = get_raw_packet(cs, &packet);
    if (r < 0) {
        // Not a transient issue handled by packet collection functions.
        if (r != -2) {
            log_error("%s: Error reading from listening socket: %s.  Reopening.",
                      client_config.interface, strerror(errno));
            stop_dhcp_listen(cs);
            start_dhcp_listen(cs);
        }
        return;
    }
    uint8_t msgtype;
    if (!validate_dhcp_packet(cs, (size_t)r, &packet, &msgtype))
        return;
    packet_action(cs, &packet, msgtype);
}

// Initialize a DHCP client packet that will be sent to a server
static struct dhcpmsg init_packet(char type, uint32_t xid)
{
    struct dhcpmsg packet = {
        .op = 1, // BOOTREQUEST (client)
        .htype = 1, // ETH_10MB
        .hlen = 6, // ETH_10MB_LEN
        .cookie = htonl(DHCP_MAGIC),
        .options[0] = DCODE_END,
        .xid = xid,
    };
    add_option_msgtype(&packet, type);
    memcpy(packet.chaddr, client_config.arp, 6);
    add_option_clientid(&packet, client_config.clientid,
                        client_config.clientid_len);
    return packet;
}

ssize_t send_discover(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPDISCOVER, cs->xid);
    if (cs->clientAddr)
        add_option_reqip(&packet, cs->clientAddr);
    add_option_maxsize(&packet);
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    log_line("%s: Discovering DHCP servers...", client_config.interface);
    return send_dhcp_raw(&packet);
}

ssize_t send_selecting(struct client_state_t *cs)
{
    char clibuf[INET_ADDRSTRLEN];
    struct dhcpmsg packet = init_packet(DHCPREQUEST, cs->xid);
    add_option_reqip(&packet, cs->clientAddr);
    add_option_serverid(&packet, cs->serverAddr);
    add_option_maxsize(&packet);
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    inet_ntop(AF_INET, &(struct in_addr){.s_addr = cs->clientAddr},
              clibuf, sizeof clibuf);
    log_line("%s: Sending a selection request for %s...",
             client_config.interface, clibuf);
    return send_dhcp_raw(&packet);
}

ssize_t send_renew(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPREQUEST, cs->xid);
    packet.ciaddr = cs->clientAddr;
    add_option_maxsize(&packet);
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    log_line("%s: Sending a renew request...", client_config.interface);
    return send_dhcp_unicast(cs, &packet);
}

ssize_t send_rebind(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPREQUEST, cs->xid);
    packet.ciaddr = cs->clientAddr;
    add_option_reqip(&packet, cs->clientAddr);
    add_option_maxsize(&packet);
    add_option_request_list(&packet);
    add_option_vendor(&packet);
    add_option_hostname(&packet);
    log_line("%s: Sending a rebind request...", client_config.interface);
    return send_dhcp_raw(&packet);
}

ssize_t send_decline(struct client_state_t *cs, uint32_t server)
{
    struct dhcpmsg packet = init_packet(DHCPDECLINE, cs->xid);
    add_option_reqip(&packet, cs->clientAddr);
    add_option_serverid(&packet, server);
    log_line("%s: Sending a decline message...", client_config.interface);
    return send_dhcp_raw(&packet);
}

ssize_t send_release(struct client_state_t *cs)
{
    struct dhcpmsg packet = init_packet(DHCPRELEASE,
                                        nk_random_u32(&cs->rnd32_state));
    packet.ciaddr = cs->clientAddr;
    add_option_reqip(&packet, cs->clientAddr);
    add_option_serverid(&packet, cs->serverAddr);
    log_line("%s: Sending a release message...", client_config.interface);
    return send_dhcp_unicast(cs, &packet);
}

