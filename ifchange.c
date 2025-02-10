// Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include "nk/log.h"
#include "nk/io.h"
#include "options.h"
#include "ndhc.h"
#include "dhcp.h"
#include "options.h"
#include "arp.h"
#include "ifchange.h"
#include "dnslabeldecomp.h"

static struct dhcpmsg cfg_packet; // Copy of the current configuration packet.

static int ifcmd_raw(char *buf, size_t buflen, const char *optname,
                     char *optdata, size_t optlen)
{
    if (!optdata) {
        log_line("%s: (%s) '%s' option has no data\n",
                 client_config.interface, __func__, optname);
        return -1;
    }
    if (optlen > INT_MAX) {
        log_line("%s: (%s) '%s' option optlen out of bounds\n",
                 client_config.interface, __func__, optname);
        return -1;
    }
    if (buflen < strlen(optname) + optlen + 3) {
        log_line("%s: (%s) '%s' option buf too short\n",
                 client_config.interface, __func__, optname);
        return -1;
    }
    int ioptlen = (int)optlen;
    ssize_t olen = snprintf(buf, buflen, "%s:%.*s;", optname, ioptlen, optdata);
    if (olen < 0 || (size_t)olen > buflen) {
        log_line("%s: (%s) '%s' option would truncate, so it was dropped.\n",
                 client_config.interface, __func__, optname);
        memset(buf, 0, buflen);
        return -1;
    }
    return olen;
}

static int ifcmd_bytes(char *buf, size_t buflen, const char *optname,
                       uint8_t *optdata, size_t optlen)
{
    return ifcmd_raw(buf, buflen, optname, (char *)optdata, optlen);
}

static int ifcmd_u8(char *buf, size_t buflen, const char *optname,
                    uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 1)
        return -1;
    char numbuf[16];
    uint8_t c = optdata[0];
    ssize_t olen = snprintf(numbuf, sizeof numbuf, "%c", c);
    if (olen < 0 || (size_t)olen > sizeof numbuf)
        return -1;
    return ifcmd_raw(buf, buflen, optname, numbuf, strlen(numbuf));
}

static int ifcmd_u16(char *buf, size_t buflen, const char *optname,
                     uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 2)
        return -1;
    char numbuf[16];
    uint16_t v;
    memcpy(&v, optdata, 2);
    v = ntohs(v);
    ssize_t olen = snprintf(numbuf, sizeof numbuf, "%hu", v);
    if (olen < 0 || (size_t)olen > sizeof numbuf)
        return -1;
    return ifcmd_raw(buf, buflen, optname, numbuf, strlen(numbuf));
}

static int ifcmd_s32(char *buf, size_t buflen, const char *optname,
                     uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 4)
        return -1;
    char numbuf[16];
    uint32_t v;
    memcpy(&v, optdata, 4);
    v = ntohl(v);
    ssize_t olen = snprintf(numbuf, sizeof numbuf, "%d", v);
    if (olen < 0 || (size_t)olen > sizeof numbuf)
        return -1;
    return ifcmd_raw(buf, buflen, optname, numbuf, strlen(numbuf));
}

static int ifcmd_ip(char *buf, size_t buflen, const char *optname,
                    uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 4)
        return -1;
    char ipbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, optdata, ipbuf, sizeof ipbuf);
    return ifcmd_raw(buf, buflen, optname, ipbuf, strlen(ipbuf));
}

static int ifcmd_iplist(char *out, size_t outlen, const char *optname,
                        uint8_t *optdata, size_t optlen)
{
    char buf[2048];
    char ipbuf[INET_ADDRSTRLEN];
    size_t bufoff = 0;
    size_t optoff = 0;

    if (!optdata || optlen < 4)
        return -1;

    inet_ntop(AF_INET, optdata + optoff, ipbuf, sizeof ipbuf);
    ssize_t wc = snprintf(buf + bufoff, sizeof buf, "%s", ipbuf);
    if (wc < 0 || (size_t)wc > sizeof buf)
        return -1;
    optoff += 4;
    bufoff += (size_t)wc;
    while (optlen >= 4 + optoff) {
        inet_ntop(AF_INET, optdata + optoff, ipbuf, sizeof ipbuf);
        wc = snprintf(buf + bufoff, sizeof buf, ",%s", ipbuf);
        if (wc < 0 || (size_t)wc > sizeof buf)
            return -1;
        optoff += 4;
        bufoff += (size_t)wc;
    }
    return ifcmd_raw(out, outlen, optname, buf, strlen(buf));
}

static int ifchd_cmd(char *b, size_t bl, uint8_t *od,
                     size_t ol, uint8_t code)
{
    switch (code) {
    case DCODE_ROUTER: return ifcmd_ip(b, bl, "routr", od, ol);
    case DCODE_DNS: return ifcmd_iplist(b, bl, "dns", od, ol);
    case DCODE_LPRSVR: return ifcmd_iplist(b, bl, "lpr", od, ol);
    case DCODE_NTPSVR: return ifcmd_iplist(b, bl, "ntp", od, ol);
    case DCODE_WINS: return ifcmd_iplist(b, bl, "wins", od, ol);
    case DCODE_HOSTNAME: return ifcmd_bytes(b, bl, "host", od, ol);
    case DCODE_DOMAIN: {
        char buf[256];
        size_t buflen = sizeof buf;
        bool ok = dnslabeldecomp(buf, &buflen, (char *)od, ol);
        if (!ok) {
            log_line("%s: Ignoring invalid domain search option\n",
                     client_config.interface);
            return -1;
        }
        return ifcmd_bytes(b, bl, "dom", (uint8_t *)buf, buflen);
    }
    case DCODE_TIMEZONE: return ifcmd_s32(b, bl, "tzone", od, ol);
    case DCODE_MTU: return ifcmd_u16(b, bl, "mtu", od, ol);
    case DCODE_IPTTL: return ifcmd_u8(b, bl, "ipttl", od, ol);
    default: break;
    }
    log_line("%s: Invalid option code (%c) for ifchd cmd.\n",
             client_config.interface, code);
    return -1;
}

static int ifchwrite(const char *buf, size_t count)
{
    ssize_t r = safe_write(ifchSock[0], buf, count);
    if (r < 0 || (size_t)r != count) {
        log_line("%s: (%s) write failed: %zd\n", client_config.interface, __func__, r);
        return -1;
    }
    char data[256], control[256];
    struct iovec iov = {
        .iov_base = data,
        .iov_len = sizeof data - 1,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof control
    };
    r = safe_recvmsg(ifchSock[0], &msg, 0);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0) {
        suicide("%s: (%s) recvmsg failed: %s\n", client_config.interface,
                __func__, strerror(errno));
    }
    data[iov.iov_len] = '\0';
    if (r == 1 && data[0] == '+')
        return 0;
    return -1;
}

bool ifchange_carrier_isup(void)
{
    const char buf[] = "carrier:;";
    return ifchwrite(buf, strlen(buf)) == 0;
}

int ifchange_deconfig(struct client_state_t *cs)
{
    const char buf[] = "ip4:0.0.0.0,255.255.255.255;";
    int ret = -1;

    if (cs->ifDeconfig)
        return 0;

    log_line("%s: Resetting IP configuration.\n", client_config.interface);
    ret = ifchwrite(buf, strlen(buf));

    if (ret >= 0) {
        cs->ifDeconfig = 1;
        memset(&cfg_packet, 0, sizeof cfg_packet);
    }
    return ret;
}

static size_t send_client_ip(char *out, size_t olen,
                             struct dhcpmsg *packet)
{
    char ip[INET_ADDRSTRLEN], sn[INET_ADDRSTRLEN], bc[INET_ADDRSTRLEN];
    bool change_ipaddr = false;
    bool have_subnet = false;
    bool change_subnet = false;
    bool have_bcast = false;
    bool change_bcast = false;

    if (memcmp(&packet->yiaddr, &cfg_packet.yiaddr, sizeof packet->yiaddr))
        change_ipaddr = true;
    inet_ntop(AF_INET, &packet->yiaddr, ip, sizeof ip);

    int found;
    uint32_t s32n = get_option_subnet_mask(packet, &found);
    if (found) {
        have_subnet = true;
        inet_ntop(AF_INET, &s32n, sn, sizeof sn);
        uint32_t s32o = get_option_subnet_mask(&cfg_packet, &found);
        if (!found || s32n != s32o)
            change_subnet = true;
    }
    uint32_t b32n = get_option_broadcast(packet, &found);
    if (found) {
        have_bcast = true;
        inet_ntop(AF_INET, &b32n, bc, sizeof bc);
        uint32_t b32o = get_option_broadcast(&cfg_packet, &found);
        if (!found || b32n != b32o)
            change_bcast = true;
    }

    // Nothing to change.
    if (!change_ipaddr && !change_subnet && !change_bcast)
        return 0;

    if (!have_subnet) {
        static char snClassC[] = "255.255.255.0";
        log_line("%s: Server did not send a subnet mask.  Assuming 255.255.255.0.\n",
                 client_config.interface);
        memcpy(sn, snClassC, sizeof snClassC);
    }

    int snlen;
    if (have_bcast) {
        snlen = snprintf(out, olen, "ip4:%s,%s,%s;", ip, sn, bc);
    } else {
        snlen = snprintf(out, olen, "ip4:%s,%s;", ip, sn);
    }
    if (snlen < 0 || (size_t)snlen > olen) {
        log_line("%s: (%s) ip4 command would truncate so it was dropped.\n",
                 client_config.interface, __func__);
        memset(out, 0, olen);
        return 0;
    }
    return (size_t)snlen;
}

static size_t send_cmd(char *out, size_t olen,
                       struct dhcpmsg *packet, uint8_t code)
{
    uint8_t optdata[MAX_DOPT_SIZE], olddata[MAX_DOPT_SIZE];
    size_t optlen, oldlen;

    optlen = get_dhcp_opt(packet, code, optdata, sizeof optdata);
    if (!optlen)
        return 0;
    oldlen = get_dhcp_opt(&cfg_packet, code, olddata, sizeof olddata);
    if (oldlen == optlen && !memcmp(optdata, olddata, optlen))
        return 0;
    int r = ifchd_cmd(out, olen, optdata, optlen, code);
    return r > 0 ? (size_t)r : 0;
}

int ifchange_bind(struct client_state_t *cs, struct dhcpmsg *packet)
{
    char buf[2048];
    size_t bo;
    int ret = -1;

    memset(buf, 0, sizeof buf);
    bo = send_client_ip(buf, sizeof buf, packet);
    bo += send_cmd(buf + bo, sizeof buf - bo, packet, DCODE_ROUTER);
    bo += send_cmd(buf + bo, sizeof buf - bo, packet, DCODE_DNS);
    bo += send_cmd(buf + bo, sizeof buf - bo, packet, DCODE_HOSTNAME);
    bo += send_cmd(buf + bo, sizeof buf - bo, packet, DCODE_DOMAIN);
    bo += send_cmd(buf + bo, sizeof buf - bo, packet, DCODE_MTU);
    bo += send_cmd(buf + bo, sizeof buf - bo, packet, DCODE_WINS);
    if (bo) {
        log_line("%s: bind command: '%s'\n", client_config.interface, buf);
        ret = ifchwrite(buf, bo);
    }

    if (ret >= 0) {
        cs->ifDeconfig = 0;
        memcpy(&cfg_packet, packet, sizeof cfg_packet);
    }
    return ret;
}

