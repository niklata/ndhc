/* ifchange.c - functions to call the interface change daemon
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

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>

#include "options.h"
#include "ndhc.h"
#include "dhcp.h"
#include "options.h"
#include "arp.h"
#include "log.h"
#include "io.h"
#include "strl.h"
#include "ifchange.h"
#include "ifch_proto.h"

static int cfg_deconfig; // Set if the interface has already been deconfigured.
static struct dhcpmsg cfg_packet; // Copy of the current configuration packet.

static int ifchd_cmd_u8(char *buf, size_t buflen, char *optname,
                        uint8_t *optdata, ssize_t optlen)
{
    if (!optdata || optlen < 1)
        return -1;
    return snprintf(buf, buflen, "%s:%c;", optname, *optdata);
}

static int ifchd_cmd_u16(char *buf, size_t buflen, char *optname,
                        uint8_t *optdata, ssize_t optlen)
{
    if (!optdata || optlen < 2)
        return -1;
    uint16_t v;
    memcpy(&v, optdata, 2);
    v = ntohs(v);
    return snprintf(buf, buflen, "%s:%hu;", optname, v);
}

static int ifchd_cmd_s32(char *buf, size_t buflen, char *optname,
                        uint8_t *optdata, ssize_t optlen)
{
    if (!optdata || optlen < 4)
        return -1;
    int32_t v;
    memcpy(&v, optdata, 4);
    v = ntohl(v);
    return snprintf(buf, buflen, "%s:%d;", optname, v);
}

static int ifchd_cmd_ip(char *buf, size_t buflen, char *optname,
                        uint8_t *optdata, ssize_t optlen)
{
    char ipbuf[INET_ADDRSTRLEN];
    if (!optdata || optlen < 4)
        return -1;
    inet_ntop(AF_INET, optdata, ipbuf, sizeof ipbuf);
    return snprintf(buf, buflen, "%s:%s;", optname, ipbuf);
}

static int ifchd_cmd_iplist(char *buf, size_t buflen, char *optname,
                            uint8_t *optdata, ssize_t optlen)
{
    char ipbuf[INET_ADDRSTRLEN];
    char *obuf = buf;
    if (!optdata || optlen < 4)
        return -1;
    inet_ntop(AF_INET, optdata, ipbuf, sizeof ipbuf);
    ssize_t wc = snprintf(buf, buflen, "%s:%s", optname, ipbuf);
    if (wc <= 0)
        return wc;
    optlen -= 4;
    optdata += 4;
    buf += wc;
    while (optlen >= 4) {
        inet_ntop(AF_INET, optdata, ipbuf, sizeof ipbuf);
        if (buflen < strlen(ipbuf) + (buf - obuf) + 2)
            break;
        buf += snprintf(buf, buflen - (buf - obuf), ",%s", ipbuf);
        optlen -= 4;
        optdata += 4;
    }
    buf += snprintf(buf, buflen - (buf - obuf), ";");
    return buf - obuf;
}

static int ifchd_cmd_bytes(char *buf, size_t buflen, char *optname,
                           uint8_t *optdata, ssize_t optlen)
{
    char *obuf = buf;
    if (buflen < strlen(optname) + optlen + 3)
        return -1;
    buf += snprintf(buf, buflen, "%s:", optname);
    memcpy(buf, optdata, optlen);
    buf[optlen] = ';';
    buf[optlen+1] = '\0';
    return (buf - obuf) + optlen + 1;
}

#define IFCHD_SW_CMD(x, y) case DCODE_##x: \
                           optname = CMD_##x; \
                           dofn = ifchd_cmd_##y; \
                           break
static int ifchd_cmd(char *buf, size_t buflen, uint8_t *optdata,
                     ssize_t optlen, uint8_t code)
{
    int (*dofn)(char *, size_t, char *, uint8_t *, ssize_t);
    char *optname;
    switch (code) {
        IFCHD_SW_CMD(DNS, iplist);
        IFCHD_SW_CMD(LPRSVR, iplist);
        IFCHD_SW_CMD(NTPSVR, iplist);
        IFCHD_SW_CMD(WINS, iplist);
        IFCHD_SW_CMD(ROUTER, ip);
        IFCHD_SW_CMD(TIMEZONE, s32);
        IFCHD_SW_CMD(HOSTNAME, bytes);
        IFCHD_SW_CMD(DOMAIN, bytes);
        IFCHD_SW_CMD(IPTTL, u8);
        IFCHD_SW_CMD(MTU, u16);
    default:
        log_line("Invalid option code (%c) for ifchd cmd.", code);
        return -1;
    }
    return dofn(buf, buflen, optname, optdata, optlen);
}
#undef IFCHD_SW_CMD

static void pipewrite(const char *buf, size_t count)
{
    if (safe_write(pToIfchW, buf, count) == -1)
        log_error("pipewrite: write failed: %s", strerror(errno));
}

void ifchange_deconfig(void)
{
    char buf[256];

    if (cfg_deconfig)
        return;

    snprintf(buf, sizeof buf, "ip4:0.0.0.0,255.255.255.255;");
    log_line("Resetting %s IP configuration.", client_config.interface);
    pipewrite(buf, strlen(buf));

    cfg_deconfig = 1;
    memset(&cfg_packet, 0, sizeof cfg_packet);
}

static size_t send_client_ip(char *out, size_t olen, struct dhcpmsg *packet)
{
    static char snClassC[] = "255.255.255.0";
    uint8_t optdata[MAX_DOPT_SIZE], olddata[MAX_DOPT_SIZE];
    char ipb[4*INET_ADDRSTRLEN], ip[INET_ADDRSTRLEN], sn[INET_ADDRSTRLEN],
        bc[INET_ADDRSTRLEN];
    ssize_t optlen, oldlen;
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
        log_line("Server did not send a subnet mask.  Assuming class C (255.255.255.0).");
        memcpy(sn, snClassC, sizeof snClassC);
    }

    if (have_bcast) {
        snprintf(ipb, sizeof ipb, "ip4:%s,%s,%s;", ip, sn, bc);
    } else {
        snprintf(ipb, sizeof ipb, "ip4:%s,%s;", ip, sn);
    }

    strnkcat(out, ipb, olen);
    log_line("Sent to ifchd: %s", ipb);
    return strlen(ipb);
}

static size_t send_cmd(char *out, size_t olen, struct dhcpmsg *packet,
                       uint8_t code)
{
    char buf[2048];
    uint8_t optdata[MAX_DOPT_SIZE], olddata[MAX_DOPT_SIZE];
    ssize_t optlen, oldlen;

    if (!packet)
        return 0;

    memset(buf, '\0', sizeof buf);
    optlen = get_dhcp_opt(packet, code, optdata, sizeof optdata);
    if (!optlen)
        return 0;
    oldlen = get_dhcp_opt(&cfg_packet, code, olddata, sizeof olddata);
    if (oldlen == optlen && !memcmp(optdata, olddata, optlen))
        return 0;
    if (ifchd_cmd(buf, sizeof buf, optdata, optlen, code) == -1)
        return 0;
    strnkcat(out, buf, olen);
    log_line("Sent to ifchd: %s", buf);
    return strlen(buf);
}

void ifchange_bind(struct dhcpmsg *packet)
{
    char buf[2048];
    int tbs = 0;

    if (!packet)
        return;

    tbs |= send_client_ip(buf, sizeof buf, packet);
    tbs |= send_cmd(buf, sizeof buf, packet, DCODE_ROUTER);
    tbs |= send_cmd(buf, sizeof buf, packet, DCODE_DNS);
    tbs |= send_cmd(buf, sizeof buf, packet, DCODE_HOSTNAME);
    tbs |= send_cmd(buf, sizeof buf, packet, DCODE_DOMAIN);
    tbs |= send_cmd(buf, sizeof buf, packet, DCODE_MTU);
    tbs |= send_cmd(buf, sizeof buf, packet, DCODE_WINS);
    if (tbs)
        pipewrite(buf, strlen(buf));

    cfg_deconfig = 0;
    memcpy(&cfg_packet, packet, sizeof cfg_packet);
}
