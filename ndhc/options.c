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

struct dhcp_option {
    uint8_t code;
    uint8_t type;
    char name[6];
};

// Marks an option that will be sent on the parameter request list to the
// remote DHCP server.
#define OPTION_REQ 16
// Marks an option that can be sent as a list of multiple items.
#define OPTION_LIST 32

// This structure is mostly used here and for finding the correct strings
// to describe option commands when sending to ifchd.  The type is the more
// useful part and helps for safety checks and determining what options to
// send in the initial DHCP option request packet.
static const struct dhcp_option options[] = {
    {DCODE_SUBNET   , OPTION_IP | OPTION_LIST | OPTION_REQ, CMD_SUBNET   },
    {DCODE_TIMEZONE , OPTION_S32,                           CMD_TIMEZONE },
    {DCODE_ROUTER   , OPTION_IP | OPTION_REQ,               CMD_ROUTER   },
    {DCODE_DNS      , OPTION_IP | OPTION_LIST | OPTION_REQ, CMD_DNS      },
    {DCODE_LPRSVR   , OPTION_IP | OPTION_LIST,              CMD_LPRSVR   },
    {DCODE_HOSTNAME , OPTION_STRING | OPTION_REQ,           CMD_HOSTNAME },
    {DCODE_DOMAIN   , OPTION_STRING | OPTION_REQ,           CMD_DOMAIN   },
    {DCODE_IPTTL    , OPTION_U8,                            CMD_IPTTL    },
    {DCODE_MTU      , OPTION_U16,                           CMD_MTU      },
    {DCODE_BROADCAST, OPTION_IP | OPTION_REQ,               CMD_BROADCAST},
    {DCODE_NTPSVR   , OPTION_IP | OPTION_LIST,              CMD_NTPSVR   },
    {DCODE_WINS     , OPTION_IP | OPTION_LIST,              CMD_WINS     },
    {0x00           , OPTION_NONE,                          CMD_NULL     }
};

enum option_type option_type(uint8_t code)
{
    for (int i = 0; options[i].code; ++i)
        if (options[i].code == code)
            return options[i].type & 0xf;
    return OPTION_NONE;
}

static const char bad_option_name[] = "BAD";
const char *option_name(uint8_t code)
{
    for (int i = 0; options[i].code; ++i)
        if (options[i].code == code)
            return options[i].name;
    return bad_option_name;
}

static uint8_t option_type_length(enum option_type type)
{
    switch (type) {
        case OPTION_IP: return 4;
        case OPTION_U8: return 1;
        case OPTION_U16: return 2;
        case OPTION_S16: return 2;
        case OPTION_U32: return 4;
        case OPTION_S32: return 4;
        default: return 0;
    }
}

uint8_t option_length(uint8_t code)
{
    for (int i = 0; options[i].code; i++)
        if (options[i].code == code)
            return option_type_length(options[i].type & 0xf);
    log_warning("option_length: Unknown length for code 0x%02x.", code);
    return 0;
}

int option_valid_list(uint8_t code)
{
    for (int i = 0; options[i].code; ++i)
        if ((options[i].code == code) && (options[i].type & OPTION_LIST))
            return 1;
    return 0;
}

static size_t sizeof_option(uint8_t code, size_t datalen)
{
    if (code == DCODE_PADDING || code == DCODE_END)
        return 1;
    return 2 + datalen;
}

// Worker function for get_option_data().  Optlen will be set to the length
// of the option data.
static uint8_t *do_get_option_data(uint8_t *buf, ssize_t buflen, int code,
                                   char *overload, ssize_t *optlen)
{
    // option bytes: [code][len]([data1][data2]..[dataLEN])
    *overload = 0;
    while (buflen > 0) {
        // Advance over padding.
        if (buf[0] == DCODE_PADDING) {
            buflen--;
            buf++;
            continue;
        }

        // We hit the end.
        if (buf[0] == DCODE_END) {
            *optlen = 0;
            return NULL;
        }

        buflen -= buf[1] + 2;
        if (buflen < 0) {
            log_warning("Bad option data: length would exceed options field size.");
            *optlen = 0;
            return NULL;
        }

        if (buf[0] == code) {
            *optlen = buf[1];
            return buf + 2;
        }

        if (buf[0] == DCODE_OVERLOAD) {
            if (buf[1] == 1)
                *overload |= buf[2];
            // fall through
        }
        buf += buf[1] + 2;
    }
    // End of options field was unmarked: no option data
    *optlen = 0;
    return NULL;
}

// XXX: Never concatenates options.  If this is added, refer to RFC3396.
// Get an option with bounds checking (warning, result is not aligned)
// optlen will be equal to the length of the option data.
uint8_t *get_option_data(struct dhcpmsg *packet, int code, ssize_t *optlen)
{
    uint8_t *option, *buf;
    ssize_t buflen;
    char overload, parsed_ff = 0;

    buf = packet->options;
    buflen = sizeof packet->options;

    option = do_get_option_data(buf, buflen, code, &overload, optlen);
    if (option)
        return option;

    if (overload & 1) {
        parsed_ff = 1;
        option = do_get_option_data(packet->file, sizeof packet->file,
                                    code, &overload, optlen);
        if (option)
            return option;
    }
    if (overload & 2) {
        option = do_get_option_data(packet->sname, sizeof packet->sname,
                                    code, &overload, optlen);
        if (option)
            return option;
        if (!parsed_ff && overload & 1)
            option = do_get_option_data(packet->file, sizeof packet->file,
                                        code, &overload, optlen);
    }
    return option;
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

// add an option string to the options (an option string contains an option
// code, length, then data)
size_t add_option_string(struct dhcpmsg *packet, uint8_t code, char *str,
                         size_t slen)
{
    size_t len = sizeof_option(code, slen);
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

size_t add_u8_option(struct dhcpmsg *packet, uint8_t code, uint8_t data)
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
size_t add_u16_option(struct dhcpmsg *packet, uint8_t code, uint16_t data)
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
size_t add_u32_option(struct dhcpmsg *packet, uint8_t code, uint32_t data)
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

// Add a paramater request list for stubborn DHCP servers
size_t add_option_request_list(struct dhcpmsg *packet)
{
    uint8_t reqdata[256];
    size_t j = 0;
    for (int i = 0; options[i].code; i++) {
        if (options[i].type & OPTION_REQ)
            reqdata[j++] = options[i].code;
    }
    return add_option_string(packet, DCODE_PARAM_REQ, (char *)reqdata, j);
}

