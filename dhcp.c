// Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <errno.h>
#include "nk/log.h"
#include "nk/io.h"
#include "nk/random.h"
#include "nk/net_checksum16.h"

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
    return request_sockd_fd(buf, 1 + sizeof cs->clientAddr, (char *)0);
}

static int get_raw_broadcast_socket(void)
{
    return request_sockd_fd("s", 1, (char *)0);
}

static int get_raw_listen_socket(struct client_state_t *cs)
{
    char resp;
    int fd = request_sockd_fd("L", 1, &resp);
    switch (resp) {
    case 'L': cs->using_dhcp_bpf = true; break;
    case 'l': cs->using_dhcp_bpf = false; break;
    default: suicide("%s: (%s) expected l or L sockd reply but got %c\n",
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
        log_line("%s: (%s) get_udp_unicast_socket failed\n",
                 client_config.interface, __func__);
        goto out;
    }

    struct sockaddr_in raddr = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr.s_addr = cs->serverAddr,
    };
    if (connect(fd, (struct sockaddr *)&raddr, sizeof(struct sockaddr)) < 0) {
        log_line("%s: (%s) connect failed: %s\n", client_config.interface,
                 __func__, strerror(errno));
        goto out_fd;
    }

    // Send packets that are as short as possible.
    ssize_t endloc = get_end_option_idx(payload);
    if (endloc < 0) {
        log_line("%s: (%s) No end marker.  Not sending.\n",
                 client_config.interface, __func__);
        goto out_fd;
    }
    const size_t el = (size_t)endloc + 1;
    if (el > sizeof payload->options) {
        log_line("%s: (%s) Invalid value of endloc.  Not sending.\n",
                 client_config.interface, __func__);
        goto out_fd;
    }
    size_t payload_len =
        sizeof *payload - (sizeof payload->options - el);
    if (!carrier_isup()) {
        log_line("%s: (%s) carrier down; write would fail\n",
                 client_config.interface, __func__);
        ret = -99;
        goto out_fd;
    }
    ret = safe_write(fd, (const char *)payload, payload_len);
    if (ret < 0 || (size_t)ret != payload_len)
        log_line("%s: (%s) write failed: %zd\n", client_config.interface,
                 __func__, ret);
  out_fd:
    close(fd);
  out:
    return ret;
}

// Returns 1 if IP checksum is correct, otherwise 0.
static int ip_checksum(struct ip_udp_dhcp_packet *packet)
{
    return net_checksum16(&packet->ip, sizeof packet->ip) == 0;
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
    uint16_t udpcs =
        net_checksum16(&packet->udp,
                         min_size_t(ntohs(packet->udp.len),
                                    sizeof *packet - sizeof(struct iphdr)));
    uint16_t hdrcs = net_checksum16(&ph, sizeof ph);
    uint16_t cs = net_checksum16_add(udpcs, hdrcs);
    return cs == 0;
}

static int get_raw_packet_validate_bpf(struct ip_udp_dhcp_packet *packet)
{
    if (packet->ip.version != IPVERSION) {
        log_line("%s: IP version is not IPv4.\n", client_config.interface);
        return 0;
    }
    if (packet->ip.ihl != sizeof packet->ip >> 2) {
        log_line("%s: IP header length incorrect.\n",
                 client_config.interface);
        return 0;
    }
    if (packet->ip.protocol != IPPROTO_UDP) {
        log_line("%s: IP header is not UDP: %d\n",
                 client_config.interface, packet->ip.protocol);
        return 0;
    }
    if (ntohs(packet->udp.dest) != DHCP_CLIENT_PORT) {
        log_line("%s: UDP destination port incorrect: %d\n",
                 client_config.interface, ntohs(packet->udp.dest));
        return 0;
    }
    if (ntohs(packet->udp.len) !=
        ntohs(packet->ip.tot_len) - sizeof packet->ip) {
        log_line("%s: UDP header length incorrect.\n",
                 client_config.interface);
        return 0;
    }
    return 1;
}

// Read a packet from a raw socket.  Returns -1 on fatal error, -2 on
// transient error.
static ssize_t get_raw_packet(struct client_state_t *cs,
                              struct dhcpmsg *payload,
                              uint32_t *srcaddr)
{
    struct ip_udp_dhcp_packet packet;
    memset(&packet, 0, sizeof packet);

    ssize_t inc = safe_read(cs->listenFd, (char *)&packet, sizeof packet);
    if (inc < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -2;
        log_line("%s: (%s) read error %s\n", client_config.interface,
                 __func__, strerror(errno));
        return -1;
    }
    size_t iphdrlen = ntohs(packet.ip.tot_len);
    if ((size_t)inc < iphdrlen)
        return -2;
    if (!cs->using_dhcp_bpf && !get_raw_packet_validate_bpf(&packet))
        return -2;

    if (!ip_checksum(&packet)) {
        log_line("%s: IP header checksum incorrect.\n",
                 client_config.interface);
        return -2;
    }
    if (iphdrlen <= sizeof packet.ip + sizeof packet.udp) {
        log_line("%s: Packet received that is too small (%zu bytes).\n",
                 client_config.interface, iphdrlen);
        return -2;
    }
    size_t l = iphdrlen - sizeof packet.ip - sizeof packet.udp;
    if (l > sizeof *payload) {
        log_line("%s: Packet received that is too long (%zu bytes).\n",
                 client_config.interface, l);
        return -2;
    }
    if (packet.udp.check && !udp_checksum(&packet)) {
        log_line("%s: Packet with bad UDP checksum received.  Ignoring.\n",
                 client_config.interface);
        return -2;
    }
    if (srcaddr)
        *srcaddr = packet.ip.saddr;
    memcpy(payload, &packet.data, l);
    return (ssize_t)l;
}

// Broadcast a DHCP message using a raw socket.
static ssize_t send_dhcp_raw(struct dhcpmsg *payload)
{
    ssize_t ret = -1;
    int fd = get_raw_broadcast_socket();
    if (fd < 0) {
        log_line("%s: (%s) get_raw_broadcast_socket failed\n",
                 client_config.interface, __func__);
        return ret;
    }

    // Send packets that are as short as possible.
    ssize_t endloc = get_end_option_idx(payload);
    if (endloc < 0) {
        log_line("%s: (%s) No end marker.  Not sending.\n",
                 client_config.interface, __func__);
        close(fd);
        return ret;
    }
    const size_t el = (size_t)endloc + 1;
    if (el > sizeof payload->options) {
        log_line("%s: (%s) Invalid value of endloc.  Not sending.\n",
                 client_config.interface, __func__);
        close(fd);
        return ret;
    }
    size_t padding = sizeof payload->options - el;
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
    uint16_t udpcs = net_checksum16(&iudmsg.udp, ud_len);
    uint16_t phcs = net_checksum16(&ph, sizeof ph);
    iudmsg.udp.check = net_checksum16_add(udpcs, phcs);
    iudmsg.ip.check = net_checksum16(&iudmsg.ip, sizeof iudmsg.ip);

    struct sockaddr_ll da = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_pkttype = PACKET_BROADCAST,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(da.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);
    if (!carrier_isup()) {
        log_line("%s: (%s) carrier down; sendto would fail\n",
                 client_config.interface, __func__);
        ret = -99;
        goto carrier_down;
    }
    ret = safe_sendto(fd, (const char *)&iudmsg, iud_len, 0,
                      (struct sockaddr *)&da, sizeof da);
    if (ret < 0 || (size_t)ret != iud_len) {
        if (ret < 0)
            log_line("%s: (%s) sendto failed: %s\n", client_config.interface,
                     __func__, strerror(errno));
        else
            log_line("%s: (%s) sendto short write: %zd < %zu\n",
                     client_config.interface, __func__, ret, iud_len);
    }
carrier_down:
    close(fd);
    return ret;
}

void start_dhcp_listen(struct client_state_t *cs)
{
    if (cs->listenFd >= 0)
        return;
    cs->listenFd = get_raw_listen_socket(cs);
    if (cs->listenFd < 0)
        suicide("%s: FATAL: Couldn't listen on socket: %s\n",
                client_config.interface, strerror(errno));
}

void stop_dhcp_listen(struct client_state_t *cs)
{
    if (cs->listenFd < 0)
        return;
    close(cs->listenFd);
    cs->listenFd = -1;
}

static int validate_dhcp_packet(struct client_state_t *cs,
                                size_t len, struct dhcpmsg *packet,
                                uint8_t *msgtype)
{
    if (len < offsetof(struct dhcpmsg, options)) {
        log_line("%s: Packet is too short to contain magic cookie.  Ignoring.\n",
                 client_config.interface);
        return 0;
    }
    if (ntohl(packet->cookie) != DHCP_MAGIC) {
        log_line("%s: Packet with bad magic number. Ignoring.\n",
                 client_config.interface);
        return 0;
    }
    if (packet->xid != cs->xid) {
        log_line("%s: Packet XID %x does not equal our XID %x.  Ignoring.\n",
                 client_config.interface, packet->xid, cs->xid);
        return 0;
    }
    if (memcmp(packet->chaddr, client_config.arp, sizeof client_config.arp)) {
        log_line("%s: Packet client MAC %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x does not equal our MAC %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x.  Ignoring it.\n",
                 client_config.interface,
                 packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
                 packet->chaddr[3], packet->chaddr[4], packet->chaddr[5],
                 client_config.arp[0], client_config.arp[1],
                 client_config.arp[2], client_config.arp[3],
                 client_config.arp[4], client_config.arp[5]);
        return 0;
    }
    ssize_t endloc = get_end_option_idx(packet);
    if (endloc < 0) {
        log_line("%s: Packet does not have an end option.  Ignoring.\n", client_config.interface);
        return 0;
    }
    *msgtype = get_option_msgtype(packet);
    if (!*msgtype) {
        log_line("%s: Packet does not specify a DHCP message type.  Ignoring.\n",
                 client_config.interface);
        return 0;
    }
    char clientid[MAX_DOPT_SIZE];
    size_t cidlen = get_option_clientid(packet, clientid, MAX_DOPT_SIZE);
    if (cidlen == 0)
        return 1;
    if (memcmp(client_config.clientid, clientid,
               min_size_t(cidlen, client_config.clientid_len))) {
        log_line("%s: Packet clientid does not match our clientid.  Ignoring.\n",
                 client_config.interface);
        return 0;
    }
    return 1;
}

bool dhcp_packet_get(struct client_state_t *cs, struct dhcpmsg *packet,
                     uint8_t *msgtype, uint32_t *srcaddr)
{
    if (cs->listenFd < 0)
        return false;
    ssize_t r = get_raw_packet(cs, packet, srcaddr);
    if (r < 0) {
        // Not a transient issue handled by packet collection functions.
        if (r != -2) {
            log_line("%s: Error reading from listening socket: %s.  Reopening.\n",
                     client_config.interface, strerror(errno));
            stop_dhcp_listen(cs);
            start_dhcp_listen(cs);
        }
        return false;
    }
    if (!validate_dhcp_packet(cs, (size_t)r, packet, msgtype))
        return false;
    return true;
}

static void add_options_vendor_hostname(struct dhcpmsg *packet)
{
    size_t vlen = strlen(client_config.vendor);
    size_t hlen = strlen(client_config.hostname);
    if (vlen)
        add_option_vendor(packet, client_config.vendor, vlen);
    else
        add_option_vendor(packet, "ndhc", sizeof "ndhc" - 1);
    add_option_hostname(packet, client_config.hostname, hlen);
}

// Initialize a DHCP client packet that will be sent to a server
static void init_packet(struct dhcpmsg *packet, uint8_t type)
{
    packet->op = 1; // BOOTREQUEST (client)
    packet->htype = 1; // ETH_10MB
    packet->hlen = 6; // ETH_10MB_LEN
    packet->cookie = htonl(DHCP_MAGIC);
    packet->options[0] = DCODE_END;
    add_option_msgtype(packet, type);
    memcpy(packet->chaddr, client_config.arp, 6);
    add_option_clientid(packet, client_config.clientid,
                        client_config.clientid_len);
}

ssize_t send_discover(struct client_state_t *cs)
{
    advance_xid(cs);
    struct dhcpmsg packet = {.xid = cs->xid};
    init_packet(&packet, DHCPDISCOVER);
    if (cs->clientAddr)
        add_option_reqip(&packet, cs->clientAddr);
    add_option_maxsize(&packet);
    add_option_request_list(&packet);
    add_options_vendor_hostname(&packet);
    log_line("%s: Discovering DHCP servers...\n", client_config.interface);
    return send_dhcp_raw(&packet);
}

ssize_t send_selecting(struct client_state_t *cs)
{
    char clibuf[INET_ADDRSTRLEN];
    struct dhcpmsg packet = {.xid = cs->xid};
    init_packet(&packet, DHCPREQUEST);
    add_option_reqip(&packet, cs->clientAddr);
    add_option_serverid(&packet, cs->serverAddr);
    add_option_maxsize(&packet);
    add_option_request_list(&packet);
    add_options_vendor_hostname(&packet);
    inet_ntop(AF_INET, &(struct in_addr){.s_addr = cs->clientAddr},
              clibuf, sizeof clibuf);
    log_line("%s: Sending a selection request for %s...\n",
             client_config.interface, clibuf);
    return send_dhcp_raw(&packet);
}

ssize_t send_renew_or_rebind(struct client_state_t *cs, bool is_renew)
{
    struct dhcpmsg packet = {.xid = cs->xid};
    init_packet(&packet, DHCPREQUEST);
    packet.ciaddr = cs->clientAddr;
    add_option_maxsize(&packet);
    add_option_request_list(&packet);
    add_options_vendor_hostname(&packet);
    log_line("%s: Sending a %s request...\n", client_config.interface,
             is_renew? "renew" : "rebind");
    return is_renew? send_dhcp_unicast(cs, &packet) : send_dhcp_raw(&packet);
}

ssize_t send_decline(struct client_state_t *cs, uint32_t server)
{
    struct dhcpmsg packet = {.xid = cs->xid};
    init_packet(&packet, DHCPDECLINE);
    add_option_reqip(&packet, cs->clientAddr);
    add_option_serverid(&packet, server);
    log_line("%s: Sending a decline message...\n", client_config.interface);
    return send_dhcp_raw(&packet);
}

ssize_t send_release(struct client_state_t *cs)
{
    struct dhcpmsg packet = {.xid = nk_random_u32(&cs->rnd_state)};
    init_packet(&packet, DHCPRELEASE);
    packet.ciaddr = cs->clientAddr;
    add_option_reqip(&packet, cs->clientAddr);
    add_option_serverid(&packet, cs->serverAddr);
    log_line("%s: Sending a release message...\n", client_config.interface);
    return send_dhcp_unicast(cs, &packet);
}

