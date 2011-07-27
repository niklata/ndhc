/* options.c - DHCP options handling
 *
 * Copyright (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "options.h"
#include "log.h"
#include "ifch_proto.h"

static int do_overload_value(uint8_t *buf, ssize_t blen, int overload)
{
    ssize_t i = 0;
    while (i < blen) {
        if (buf[i] == DCODE_PADDING) {
            ++i;
            continue;
        }
        if (buf[i] == DCODE_END)
            break;
        if (i >= blen - 2)
            break;
        if (buf[i] == DCODE_OVERLOAD) {
            if (buf[i+1] == 1) {
                overload |= buf[i+2];
                i += 3;
                continue;
            }
        }
        i += buf[i+1] + 2;
    }
    return overload;
}

static int overload_value(struct dhcpmsg *packet)
{
    int ol = do_overload_value(packet->options, sizeof packet->options, 0);
    if (ol & 1 && ol & 2)
        return ol;
    if (ol & 1) {
        ol |= do_overload_value(packet->file, sizeof packet->file, ol);
        return ol;
    }
    if (ol & 2) {
        ol |= do_overload_value(packet->sname, sizeof packet->sname, ol);
        return ol;
    }
    return ol; // ol == 0
}

static ssize_t do_get_dhcp_opt(uint8_t *sbuf, ssize_t slen, uint8_t code,
                               uint8_t *dbuf, ssize_t dlen, ssize_t didx)
{
    ssize_t i = 0;
    while (i < slen) {
        if (sbuf[i] == DCODE_PADDING) {
            ++i;
            continue;
        }
        if (sbuf[i] == DCODE_END)
            break;
        if (i >= slen - 2)
            break;
        if (sbuf[i] == code) {
            if (dlen - didx < sbuf[i+1])
                return didx;
            memcpy(dbuf+didx, sbuf+i+2, sbuf[i+1]);
            didx += sbuf[i+1];
        }
        i += sbuf[i+1] + 2;
    }
    return didx;
}

ssize_t get_dhcp_opt(struct dhcpmsg *packet, uint8_t code, uint8_t *dbuf,
                     ssize_t dlen)
{
    int ol = overload_value(packet);
    ssize_t didx = do_get_dhcp_opt(packet->options, sizeof packet->options,
                                   code, dbuf, dlen, 0);
    if (ol & 1)
        didx += do_get_dhcp_opt(packet->file, sizeof packet->file, code,
                                dbuf, dlen, didx);
    if (ol & 2)
        didx += do_get_dhcp_opt(packet->sname, sizeof packet->sname, code,
                                dbuf, dlen, didx);
    return didx;
}

// return the position of the 'end' option
ssize_t get_end_option_idx(struct dhcpmsg *packet)
{
    for (size_t i = 0; i < sizeof packet->options; ++i) {
        if (packet->options[i] == DCODE_END)
            return i;
        if (packet->options[i] == DCODE_PADDING)
            continue;
        if (packet->options[i] != DCODE_PADDING)
            i += packet->options[i+1] + 1;
    }
    log_warning("get_end_option_idx: Did not find DCODE_END marker.");
    return -1;
}

static inline size_t sizeof_option_str(uint8_t code, size_t datalen)
{
    if (code == DCODE_PADDING || code == DCODE_END)
        return 1;
    return 2 + datalen;
}

// Add a raw data string to the options.  It will take a binary string suitable
// for use with eg memcpy() and will append it to the options[] field of
// a dhcp packet with the requested option code and proper length specifier.
static size_t add_option_string(struct dhcpmsg *packet, uint8_t code,
                                char *str, size_t slen)
{
    size_t len = sizeof_option_str(code, slen);
    if (slen > 255 || len != slen + 2) {
        log_warning("add_option_string: Length checks failed.");
        return 0;
    }

    ssize_t end = get_end_option_idx(packet);
    if (end == -1) {
        log_warning("add_option_string: Buffer has no DCODE_END marker.");
        return 0;
    }
    if (end + len >= sizeof packet->options) {
        log_warning("add_option_string: No space for option 0x%02x.", code);
        return 0;
    }
    packet->options[end] = code;
    packet->options[end+1] = slen;
    memcpy(packet->options + end + 2, str, slen);
    packet->options[end+len] = DCODE_END;
    return len;
}

static ssize_t add_option_check(struct dhcpmsg *packet, uint8_t code,
                                uint8_t rlen)
{
    ssize_t end = get_end_option_idx(packet);
    if (end == -1) {
        log_warning("add_u%01u_option: Buffer has no DCODE_END marker.", rlen*8);
        return -1;
    }
    if (end + 2 + rlen >= sizeof packet->options) {
        log_warning("add_u%01u_option: No space for option 0x%02x.",
                    rlen*8, code);
        return -1;
    }
    return end;
}

static size_t add_u8_option(struct dhcpmsg *packet, uint8_t code, uint8_t data)
{
    ssize_t end = add_option_check(packet, code, 1);
    if (end < 0)
        return 0;
    packet->options[end] = code;
    packet->options[end+1] = 1;
    packet->options[end+2] = data;
    packet->options[end+3] = DCODE_END;
    return 3;
}

// Data should be in network byte order.
static size_t add_u16_option(struct dhcpmsg *packet, uint8_t code,
                             uint16_t data)
{
    ssize_t end = add_option_check(packet, code, 2);
    if (end < 0)
        return 0;
    uint8_t *dp = (uint8_t *)&data;
    packet->options[end] = code;
    packet->options[end+1] = 2;
    packet->options[end+2] = dp[0];
    packet->options[end+3] = dp[1];
    packet->options[end+4] = DCODE_END;
    return 4;
}

// Data should be in network byte order.
static size_t add_u32_option(struct dhcpmsg *packet, uint8_t code,
                             uint32_t data)
{
    ssize_t end = add_option_check(packet, code, 4);
    if (end < 0)
        return 0;
    uint8_t *dp = (uint8_t *)&data;
    packet->options[end] = code;
    packet->options[end+1] = 4;
    packet->options[end+2] = dp[0];
    packet->options[end+3] = dp[1];
    packet->options[end+4] = dp[2];
    packet->options[end+5] = dp[3];
    packet->options[end+6] = DCODE_END;
    return 6;
}

// Add a parameter request list for stubborn DHCP servers
size_t add_option_request_list(struct dhcpmsg *packet)
{
    static const uint8_t reqdata[] = {
        DCODE_SUBNET, DCODE_ROUTER, DCODE_DNS, DCODE_HOSTNAME, DCODE_DOMAIN,
        DCODE_BROADCAST,
    };
    return add_option_string(packet, DCODE_PARAM_REQ,
                             (char *)reqdata, sizeof reqdata);
}

void add_option_msgtype(struct dhcpmsg *packet, uint8_t type)
{
    add_u8_option(packet, DCODE_MSGTYPE, type);
}

void add_option_reqip(struct dhcpmsg *packet, uint32_t ip)
{
    add_u32_option(packet, DCODE_REQIP, ip);
}

void add_option_maxsize(struct dhcpmsg *packet)
{
    add_u16_option(packet, DCODE_MAX_SIZE,
                   htons(sizeof(struct ip_udp_dhcp_packet)));
}

void add_option_serverid(struct dhcpmsg *packet, uint32_t sid)
{
    add_u32_option(packet, DCODE_SERVER_ID, sid);
}

void add_option_vendor(struct dhcpmsg *packet)
{
    size_t len = strlen(client_config.vendor);
    if (len)
        add_option_string(packet, DCODE_VENDOR, client_config.vendor, len);
    else
        add_option_string(packet, DCODE_VENDOR, "ndhc", sizeof "ndhc" - 1);
}

void add_option_clientid(struct dhcpmsg *packet)
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
    add_option_string(packet, DCODE_CLIENT_ID, buf, len+1);
}

void add_option_hostname(struct dhcpmsg *packet)
{
    size_t len = strlen(client_config.hostname);
    if (len)
        add_option_string(packet, DCODE_HOSTNAME, client_config.hostname, len);
}

uint32_t get_option_router(struct dhcpmsg *packet)
{
    ssize_t ol;
    uint32_t ret = 0;
    uint8_t buf[MAX_DOPT_SIZE];
    ol = get_dhcp_opt(packet, DCODE_ROUTER, buf, sizeof buf);
    if (ol == sizeof ret)
        memcpy(&ret, buf, sizeof ret);
    return ret;
}

uint8_t get_option_msgtype(struct dhcpmsg *packet)
{
    ssize_t ol;
    uint8_t ret = 0;
    uint8_t buf[MAX_DOPT_SIZE];
    ol = get_dhcp_opt(packet, DCODE_MSGTYPE, buf, sizeof buf);
    if (ol == sizeof ret)
        ret = buf[0];
    return ret;
}

uint32_t get_option_serverid(struct dhcpmsg *packet, int *found)
{
    ssize_t ol;
    uint32_t ret = 0;
    uint8_t buf[MAX_DOPT_SIZE];
    *found = 0;
    ol = get_dhcp_opt(packet, DCODE_SERVER_ID, buf, sizeof buf);
    if (ol == sizeof ret) {
        *found = 1;
        memcpy(&ret, buf, sizeof ret);
    }
    return ret;
}

uint32_t get_option_leasetime(struct dhcpmsg *packet)
{
    ssize_t ol;
    uint32_t ret = 0;
    uint8_t buf[MAX_DOPT_SIZE];
    ol = get_dhcp_opt(packet, DCODE_LEASET, buf, sizeof buf);
    if (ol == sizeof ret) {
        memcpy(&ret, buf, sizeof ret);
        ret = ntohl(ret);
    }
    return ret;
}
