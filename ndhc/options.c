/* options.c - DHCP options handling
 * Time-stamp: <2011-03-30 18:29:18 nk>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "options.h"
#include "log.h"

struct dhcp_option {
    char name[10];
    enum option_type type;
    uint8_t code;
};

// Marks an option that will be sent on the parameter request list to the
// remote DHCP server.
#define OPTION_REQ 16
// Marks an option that can be sent as a list of multiple items.
#define OPTION_LIST 32
static struct dhcp_option options[] = {
    // name[10]     type                                    code
    {"subnet"   ,   OPTION_IP | OPTION_LIST | OPTION_REQ,   0x01},
    {"timezone" ,   OPTION_S32,                             0x02},
    {"router"   ,   OPTION_IP | OPTION_REQ,                 0x03},
    {"timesvr"  ,   OPTION_IP | OPTION_LIST,                0x04},
    {"namesvr"  ,   OPTION_IP | OPTION_LIST,                0x05},
    {"dns"      ,   OPTION_IP | OPTION_LIST | OPTION_REQ,   0x06},
    {"logsvr"   ,   OPTION_IP | OPTION_LIST,                0x07},
    {"cookiesvr",   OPTION_IP | OPTION_LIST,                0x08},
    {"lprsvr"   ,   OPTION_IP | OPTION_LIST,                0x09},
    {"hostname" ,   OPTION_STRING | OPTION_REQ,             0x0c},
    {"bootsize" ,   OPTION_U16,                             0x0d},
    {"domain"   ,   OPTION_STRING | OPTION_REQ,             0x0f},
    {"swapsvr"  ,   OPTION_IP,                              0x10},
    {"rootpath" ,   OPTION_STRING,                          0x11},
    {"ipttl"    ,   OPTION_U8,                              0x17},
    {"mtu"      ,   OPTION_U16,                             0x1a},
    {"broadcast",   OPTION_IP | OPTION_REQ,                 0x1c},
    {"ntpsrv"   ,   OPTION_IP | OPTION_LIST,                0x2a},
    {"wins"     ,   OPTION_IP | OPTION_LIST,                0x2c},
    {"requestip",   OPTION_IP,                              0x32},
    {"lease"    ,   OPTION_U32,                             0x33},
    {"dhcptype" ,   OPTION_U8,                              0x35},
    {"serverid" ,   OPTION_IP,                              0x36},
    {"message"  ,   OPTION_STRING,                          0x38},
    {"maxsize"  ,   OPTION_U16,                             0x39},
    {"tftp"     ,   OPTION_STRING,                          0x42},
    {"bootfile" ,   OPTION_STRING,                          0x43},
    {"NONE"     ,   OPTION_NONE,                            0x00}
};

enum option_type option_type(uint8_t code)
{
    for (int i = 0; options[i].code; ++i)
        if (options[i].code == code)
            return options[i].type & 0xf;
    return OPTION_NONE;
}

static const char bad_option_name[] = "BADOPTION";
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
    log_warning("option_length: unknown length for code 0x%02x", code);
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
    if (code == DHCP_PADDING || code == DHCP_END)
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
        if (buf[0] == DHCP_PADDING) {
            buflen--;
            buf++;
            continue;
        }

        // We hit the end.
        if (buf[0] == DHCP_END) {
            *optlen = 0;
            return NULL;
        }

        buflen -= buf[1] + 2;
        if (buflen < 0) {
            log_warning("Bad dhcp data: option length would exceed options field length");
            *optlen = 0;
            return NULL;
        }

        if (buf[0] == code) {
            *optlen = buf[1];
            return buf + 2;
        }

        if (buf[0] == DHCP_OPTION_OVERLOAD) {
            if (buf[1] == 1)
                *overload |= buf[2];
            // fall through
        }
        buf += buf[1] + 2;
    }
    log_warning("Bad dhcp data: unmarked end of options field");
    *optlen = 0;
    return NULL;
}

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
        if (packet->options[i] == DHCP_END)
            return i;
        if (packet->options[i] == DHCP_PADDING)
            continue;
        if (packet->options[i] != DHCP_PADDING)
            i += packet->options[i+1] + 1;
    }
    log_warning("get_end_option_idx(): did not find DHCP_END marker");
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

    size_t end = get_end_option_idx(packet);
    if (end == -1) {
        log_warning("add_option_string: Buffer has no DHCP_END marker");
        return 0;
    }
    if (end + len >= sizeof packet->options) {
        log_warning("add_option_string: No space for option 0x%02x", code);
        return 0;
    }
    packet->options[end] = code;
    packet->options[end+1] = slen;
    memcpy(packet->options + end + 2, str, slen);
    packet->options[end+len] = DHCP_END;
    return len;
}

// XXX: length=1 and length=2 will fail if data is big-endian.
size_t add_u32_option(struct dhcpmsg *packet, uint8_t code, uint32_t data)
{
    size_t length = option_length(code);

    if (!length) {
        log_warning("add_u32_option: option code 0x%02x has 0 length", code);
        return 0;
    }
    size_t end = get_end_option_idx(packet);
    if (end == -1) {
        log_warning("add_u32_option: Buffer has no DHCP_END marker");
        return 0;
    }
    if (end + 2 + length >= sizeof packet->options) {
        log_warning("add_u32_option: No space for option 0x%02x", code);
        return 0;
    }
    packet->options[end] = code;
    packet->options[end+1] = length;
    // XXX: this is broken: it's alignment-safe, but the endianness is wrong
    memcpy(packet->options + end + 2, &data, length);
    packet->options[end+length+2] = DHCP_END;
    return length+2;
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
    return add_option_string(packet, DHCP_PARAM_REQ, (char *)reqdata, j);
}

