/* ifchange.c - functions to call the interface change daemon
 *
 * Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
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

static struct dhcpmsg cfg_packet; // Copy of the current configuration packet.

static int ifcmd_raw(char buf[static 1], size_t buflen,
                     const char optname[static 1],
                     char *optdata, size_t optlen)
{
    if (!optdata) {
        log_line("%s: (%s) '%s' option has no data",
                 client_config.interface, __func__, optname);
        return -1;
    }
    if (optlen > INT_MAX) {
        log_line("%s: (%s) '%s' option optlen out of bounds",
                 client_config.interface, __func__, optname);
        return -1;
    }
    if (buflen < strlen(optname) + optlen + 3) {
        log_line("%s: (%s) '%s' option buf too short",
                 client_config.interface, __func__, optname);
        return -1;
    }
    int ioptlen = (int)optlen;
    ssize_t olen = snprintf(buf, buflen, "%s:%.*s;",
                            optname, ioptlen, optdata);
    if (olen < 0 || (size_t)olen >= buflen) {
        log_line("%s: (%s) '%s' option would truncate, so it was dropped.",
                 client_config.interface, __func__, optname);
        memset(buf, 0, buflen);
        return -1;
    }
    return olen;
}

static int ifcmd_bytes(char buf[static 1], size_t buflen,
                       const char optname[static 1],
                       uint8_t *optdata, size_t optlen)
{
    return ifcmd_raw(buf, buflen, optname, (char *)optdata, optlen);
}

static int ifcmd_u8(char buf[static 1], size_t buflen,
                    const char optname[static 1],
                    uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 1)
        return -1;
    char numbuf[16];
    uint8_t c = optdata[0];
    ssize_t olen = snprintf(numbuf, sizeof numbuf, "%c", c);
    if (olen < 0 || (size_t)olen >= sizeof numbuf)
        return -1;
    return ifcmd_raw(buf, buflen, optname, numbuf, strlen(numbuf));
}

static int ifcmd_u16(char buf[static 1], size_t buflen,
                     const char optname[static 1],
                     uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 2)
        return -1;
    char numbuf[16];
    uint16_t v;
    memcpy(&v, optdata, 2);
    v = ntohs(v);
    ssize_t olen = snprintf(numbuf, sizeof numbuf, "%hu", v);
    if (olen < 0 || (size_t)olen >= sizeof numbuf)
        return -1;
    return ifcmd_raw(buf, buflen, optname, numbuf, strlen(numbuf));
}

static int ifcmd_s32(char buf[static 1], size_t buflen,
                     const char optname[static 1],
                     uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 4)
        return -1;
    char numbuf[16];
    uint32_t v;
    memcpy(&v, optdata, 4);
    v = ntohl(v);
    ssize_t olen = snprintf(numbuf, sizeof numbuf, "%d", v);
    if (olen < 0 || (size_t)olen >= sizeof numbuf)
        return -1;
    return ifcmd_raw(buf, buflen, optname, numbuf, strlen(numbuf));
}

static int ifcmd_ip(char buf[static 1], size_t buflen,
                    const char optname[static 1],
                    uint8_t *optdata, size_t optlen)
{
    if (!optdata || optlen < 4)
        return -1;
    char ipbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, optdata, ipbuf, sizeof ipbuf);
    return ifcmd_raw(buf, buflen, optname, ipbuf, strlen(ipbuf));
}

static int ifcmd_iplist(char out[static 1], size_t outlen,
                        const char optname[static 1],
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
    if (wc < 0 || (size_t)wc >= sizeof buf)
        return -1;
    optoff += 4;
    bufoff += (size_t)wc;
    while (optlen >= 4 + optoff) {
        inet_ntop(AF_INET, optdata + optoff, ipbuf, sizeof ipbuf);
        wc = snprintf(buf + bufoff, sizeof buf, ",%s", ipbuf);
        if (wc < 0 || (size_t)wc >= sizeof buf)
            return -1;
        optoff += 4;
        bufoff += (size_t)wc;
    }
    return ifcmd_raw(out, outlen, optname, buf, strlen(buf));
}

static int ifchd_cmd(char b[static 1], size_t bl, uint8_t *od,
                     size_t ol, uint8_t code)
{
    switch (code) {
    case DCODE_ROUTER: return ifcmd_ip(b, bl, "routr", od, ol);
    case DCODE_DNS: return ifcmd_iplist(b, bl, "dns", od, ol);
    case DCODE_LPRSVR: return ifcmd_iplist(b, bl, "lpr", od, ol);
    case DCODE_NTPSVR: return ifcmd_iplist(b, bl, "ntp", od, ol);
    case DCODE_WINS: return ifcmd_iplist(b, bl, "wins", od, ol);
    case DCODE_HOSTNAME: return ifcmd_bytes(b, bl, "host", od, ol);
    case DCODE_DOMAIN: return ifcmd_bytes(b, bl, "dom", od, ol);
    case DCODE_TIMEZONE: return ifcmd_s32(b, bl, "tzone", od, ol);
    case DCODE_MTU: return ifcmd_u16(b, bl, "mtu", od, ol);
    case DCODE_IPTTL: return ifcmd_u8(b, bl, "ipttl", od, ol);
    default: break;
    }
    log_line("%s: Invalid option code (%c) for ifchd cmd.",
             client_config.interface, code);
    return -1;
}

static int ifchwrite(const char buf[static 1], size_t count)
{
    ssize_t r = safe_write(ifchSock[0], buf, count);
    if (r < 0 || (size_t)r != count) {
        log_line("%s: (%s) write failed: %zd", client_config.interface, __func__, r);
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
        suicide("%s: (%s) recvmsg failed: %s", client_config.interface,
                __func__, strerror(errno));
    }
    data[iov.iov_len] = '\0';
    if (r == 1 && data[0] == '+')
        return 0;
    return -1;
}

bool ifchange_carrier_isup(void)
{
    char buf[256];
    snprintf(buf, sizeof buf, "carrier:;");
    return ifchwrite(buf, strlen(buf)) == 0;
}

int ifchange_deconfig(struct client_state_t cs[static 1])
{
    char buf[256];
    int ret = -1;

    if (cs->ifDeconfig)
        return 0;

    snprintf(buf, sizeof buf, "ip4:0.0.0.0,255.255.255.255;");
    log_line("%s: Resetting IP configuration.", client_config.interface);
    ret = ifchwrite(buf, strlen(buf));

    if (ret >= 0) {
        cs->ifDeconfig = 1;
        memset(&cfg_packet, 0, sizeof cfg_packet);
    }
    return ret;
}

static size_t send_client_ip(char out[static 1], size_t olen,
                             struct dhcpmsg packet[static 1])
{
    uint8_t optdata[MAX_DOPT_SIZE], olddata[MAX_DOPT_SIZE];
    char ip[INET_ADDRSTRLEN], sn[INET_ADDRSTRLEN], bc[INET_ADDRSTRLEN];
    size_t optlen, oldlen;
    bool change_ipaddr = false;
    bool have_subnet = false;
    bool change_subnet = false;
    bool have_bcast = false;
    bool change_bcast = false;

    if (memcmp(&packet->yiaddr, &cfg_packet.yiaddr, sizeof packet->yiaddr))
        change_ipaddr = true;
    inet_ntop(AF_INET, &packet->yiaddr, ip, sizeof ip);

    optlen = get_dhcp_opt(packet, DCODE_SUBNET, optdata, sizeof optdata);
    if (optlen >= 4) {
        have_subnet = true;
        inet_ntop(AF_INET, optdata, sn, sizeof sn);
        oldlen = get_dhcp_opt(&cfg_packet, DCODE_SUBNET, olddata,
                              sizeof olddata);
        if (oldlen != optlen || memcmp(optdata, olddata, optlen))
            change_subnet = true;
    }

    optlen = get_dhcp_opt(packet, DCODE_BROADCAST, optdata, sizeof optdata);
    if (optlen >= 4) {
        have_bcast = true;
        inet_ntop(AF_INET, optdata, bc, sizeof bc);
        oldlen = get_dhcp_opt(&cfg_packet, DCODE_BROADCAST, olddata,
                              sizeof olddata);
        if (oldlen != optlen || memcmp(optdata, olddata, optlen))
            change_bcast = true;
    }

    // Nothing to change.
    if (!change_ipaddr && !change_subnet && !change_bcast)
        return 0;

    if (!have_subnet) {
        static char snClassC[] = "255.255.255.0";
        log_line("%s: Server did not send a subnet mask.  Assuming 255.255.255.0.",
                 client_config.interface);
        memcpy(sn, snClassC, sizeof snClassC);
    }

    int snlen;
    if (have_bcast) {
        snlen = snprintf(out, olen, "ip4:%s,%s,%s;", ip, sn, bc);
    } else {
        snlen = snprintf(out, olen, "ip4:%s,%s;", ip, sn);
    }
    if (snlen < 0 || (size_t)snlen >= olen) {
        log_line("%s: (%s) ip4 command would truncate so it was dropped.",
                 client_config.interface, __func__);
        memset(out, 0, olen);
        return 0;
    }
    return (size_t)snlen;
}

static size_t send_cmd(char out[static 1], size_t olen,
                       struct dhcpmsg packet[static 1], uint8_t code)
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

int ifchange_bind(struct client_state_t cs[static 1],
                   struct dhcpmsg packet[static 1])
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
        log_line("%s: bind command: '%s'", client_config.interface, buf);
        ret = ifchwrite(buf, bo);
    }

    if (ret >= 0) {
        cs->ifDeconfig = 0;
        memcpy(&cfg_packet, packet, sizeof cfg_packet);
    }
    return ret;
}

