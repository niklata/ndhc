/* options.c - DHCP options handling
 *
 * Copyright (c) 2004-2015 Nicholas J. Kain <njkain at gmail dot com>
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
#include <arpa/inet.h>
#include "nk/log.h"

#include "options.h"

static int do_overload_value(const uint8_t buf[static 1], ssize_t blen,
                             int overload)
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

static int overload_value(const struct dhcpmsg packet[static 1])
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

static void do_get_dhcp_opt(const uint8_t *sbuf, ssize_t slen, uint8_t code,
                            uint8_t *dbuf, ssize_t dlen, ssize_t *didx)
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
        ssize_t soptsiz = sbuf[i+1];
        if (sbuf[i] == code) {
            if (dlen - *didx < soptsiz)
                return;
            if (slen - i - 2 < soptsiz)
                return;
            memcpy(dbuf + *didx, sbuf+i+2, soptsiz);
            *didx += soptsiz;
        }
        i += soptsiz + 2;
    }
}

ssize_t get_dhcp_opt(const struct dhcpmsg packet[static 1], uint8_t code,
                     uint8_t *dbuf, ssize_t dlen)
{
    int ol = overload_value(packet);
    ssize_t didx = 0;
    do_get_dhcp_opt(packet->options, sizeof packet->options, code,
                    dbuf, dlen, &didx);
    if (ol & 1)
        do_get_dhcp_opt(packet->file, sizeof packet->file, code,
                        dbuf, dlen, &didx);
    if (ol & 2)
        do_get_dhcp_opt(packet->sname, sizeof packet->sname, code,
                        dbuf, dlen, &didx);
    return didx;
}

// return the position of the 'end' option
ssize_t get_end_option_idx(const struct dhcpmsg packet[static 1])
{
    for (size_t i = 0; i < sizeof packet->options; ++i) {
        if (packet->options[i] == DCODE_END)
            return i;
        if (packet->options[i] == DCODE_PADDING)
            continue;
        if (i + 1 >= sizeof packet->options)
            break;
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
size_t add_option_string(struct dhcpmsg packet[static 1], uint8_t code,
                         const char str[static 1], size_t slen)
{
    size_t len = sizeof_option_str(code, slen);
    if (slen > 255 || len != slen + 2) {
        log_warning("add_option_string: Length checks failed.");
        return 0;
    }

    ssize_t end = get_end_option_idx(packet);
    if (end < 0) {
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

static ssize_t add_option_check(struct dhcpmsg packet[static 1], uint8_t code,
                                uint8_t rlen)
{
    ssize_t end = get_end_option_idx(packet);
    if (end < 0) {
        log_warning("add_u%01u_option: Buffer has no DCODE_END marker.", rlen*8);
        return -1;
    }
    if ((size_t)end + 2 + rlen >= sizeof packet->options) {
        log_warning("add_u%01u_option: No space for option 0x%02x.",
                    rlen*8, code);
        return -1;
    }
    return end;
}

static size_t add_u8_option(struct dhcpmsg packet[static 1], uint8_t code,
                            uint8_t data)
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

#ifndef NDHS_BUILD
// Data should be in network byte order.
static size_t add_u16_option(struct dhcpmsg packet[static 1], uint8_t code,
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
#endif

// Data should be in network byte order.
size_t add_u32_option(struct dhcpmsg packet[static 1], uint8_t code,
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
size_t add_option_request_list(struct dhcpmsg packet[static 1])
{
    static const uint8_t reqdata[] = {
        DCODE_SUBNET, DCODE_ROUTER, DCODE_DNS, DCODE_HOSTNAME, DCODE_DOMAIN,
        DCODE_BROADCAST,
    };
    return add_option_string(packet, DCODE_PARAM_REQ,
                             (char *)reqdata, sizeof reqdata);
}

#ifdef NDHS_BUILD
size_t add_option_domain_name(struct dhcpmsg packet[static 1],
                              const char dom[static 1], size_t domlen)
{
    return add_option_string(packet, DCODE_DOMAIN, dom, domlen);
}

void add_option_subnet_mask(struct dhcpmsg packet[static 1], uint32_t subnet)
{
    add_u32_option(packet, DCODE_SUBNET, subnet);
}

void add_option_broadcast(struct dhcpmsg packet[static 1], uint32_t bc)
{
    add_u32_option(packet, DCODE_BROADCAST, bc);
}
#endif

void add_option_msgtype(struct dhcpmsg packet[static 1], uint8_t type)
{
    add_u8_option(packet, DCODE_MSGTYPE, type);
}

void add_option_reqip(struct dhcpmsg packet[static 1], uint32_t ip)
{
    add_u32_option(packet, DCODE_REQIP, ip);
}

void add_option_serverid(struct dhcpmsg packet[static 1], uint32_t sid)
{
    add_u32_option(packet, DCODE_SERVER_ID, sid);
}

void add_option_clientid(struct dhcpmsg packet[static 1],
                         const char clientid[static 1],
                         size_t clen)
{
    add_option_string(packet, DCODE_CLIENT_ID, clientid, clen);
}

#ifndef NDHS_BUILD
void add_option_maxsize(struct dhcpmsg packet[static 1])
{
    add_u16_option(packet, DCODE_MAX_SIZE,
                   htons(sizeof(struct ip_udp_dhcp_packet)));
}

void add_option_vendor(struct dhcpmsg packet[static 1])
{
    size_t len = strlen(client_config.vendor);
    if (len)
        add_option_string(packet, DCODE_VENDOR, client_config.vendor, len);
    else
        add_option_string(packet, DCODE_VENDOR, "ndhc", sizeof "ndhc" - 1);
}

void add_option_hostname(struct dhcpmsg packet[static 1])
{
    size_t len = strlen(client_config.hostname);
    if (len)
        add_option_string(packet, DCODE_HOSTNAME, client_config.hostname, len);
}
#endif

uint32_t get_option_router(const struct dhcpmsg packet[static 1])
{
    ssize_t ol;
    uint32_t ret = 0;
    uint8_t buf[MAX_DOPT_SIZE];
    ol = get_dhcp_opt(packet, DCODE_ROUTER, buf, sizeof buf);
    if (ol == sizeof ret)
        memcpy(&ret, buf, sizeof ret);
    return ret;
}

uint8_t get_option_msgtype(const struct dhcpmsg packet[static 1])
{
    ssize_t ol;
    uint8_t ret = 0;
    uint8_t buf[MAX_DOPT_SIZE];
    ol = get_dhcp_opt(packet, DCODE_MSGTYPE, buf, sizeof buf);
    if (ol == sizeof ret)
        ret = buf[0];
    return ret;
}

uint32_t get_option_serverid(const struct dhcpmsg packet[static 1], int *found)
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

uint32_t get_option_leasetime(const struct dhcpmsg packet[static 1])
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

// Returned buffer is not nul-terminated.
size_t get_option_clientid(const struct dhcpmsg packet[static 1],
                           char cbuf[static 1], size_t clen)
{
    if (clen < 1)
        return 0;
    ssize_t ol = get_dhcp_opt(packet, DCODE_CLIENT_ID,
                              (uint8_t *)cbuf, clen);
    return ol > 0 ? ol : 0;
}
