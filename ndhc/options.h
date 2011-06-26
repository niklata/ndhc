/* options.h - DHCP options handling
 * Time-stamp: <2011-03-30 16:34:55 nk>
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
#ifndef OPTIONS_H_
#define OPTIONS_H_

#include "packet.h"

#define DHCP_OPTIONS_BUFSIZE    308

/* DHCP option codes (partial list) */
#define DHCP_PADDING            0x00
#define DHCP_SUBNET             0x01
#define DHCP_TIME_OFFSET        0x02
#define DHCP_ROUTER             0x03
#define DHCP_TIME_SERVER        0x04
#define DHCP_NAME_SERVER        0x05
#define DHCP_DNS_SERVER         0x06
#define DHCP_LOG_SERVER         0x07
#define DHCP_COOKIE_SERVER      0x08
#define DHCP_LPR_SERVER         0x09
#define DHCP_HOST_NAME          0x0c
#define DHCP_BOOT_SIZE          0x0d
#define DHCP_DOMAIN_NAME        0x0f
#define DHCP_SWAP_SERVER        0x10
#define DHCP_ROOT_PATH          0x11
#define DHCP_IP_TTL             0x17
#define DHCP_MTU                0x1a
#define DHCP_BROADCAST          0x1c
#define DHCP_NIS_DOMAIN         0x28
#define DHCP_NIS_SERVER         0x29
#define DHCP_NTP_SERVER         0x2a
#define DHCP_WINS_SERVER        0x2c
#define DHCP_REQUESTED_IP       0x32
#define DHCP_LEASE_TIME         0x33
#define DHCP_OPTION_OVERLOAD    0x34
#define DHCP_MESSAGE_TYPE       0x35
#define DHCP_SERVER_ID          0x36
#define DHCP_PARAM_REQ          0x37
#define DHCP_MESSAGE            0x38
#define DHCP_MAX_SIZE           0x39
#define DHCP_T1                 0x3a
#define DHCP_T2                 0x3b
#define DHCP_VENDOR             0x3c
#define DHCP_CLIENT_ID          0x3d
#define DHCP_TFTP_SERVER_NAME   0x42
#define DHCP_BOOT_FILE          0x43
#define DHCP_USER_CLASS         0x4d
#define DHCP_FQDN               0x51
#define DHCP_DOMAIN_SEARCH      0x77
#define DHCP_SIP_SERVERS        0x78
#define DHCP_STATIC_ROUTES      0x79
#define DHCP_WPAD               0xfc
#define DHCP_END                0xff

enum option_type {
    OPTION_NONE = 0,
    OPTION_IP = 1,
    OPTION_STRING = 2,
    OPTION_U8 = 3,
    OPTION_U16 = 4,
    OPTION_S16 = 5,
    OPTION_U32 = 6,
    OPTION_S32 = 7
};

const char *option_name(uint8_t code);
enum option_type option_type(uint8_t code);
uint8_t option_length(uint8_t code);
int option_valid_list(uint8_t code);
size_t sizeof_option(uint8_t code, size_t datalen);
size_t set_option(uint8_t *buf, size_t buflen, uint8_t code, uint8_t *optdata,
                  size_t datalen);
uint8_t *alloc_option(uint8_t code, uint8_t *optdata, size_t datalen);

uint8_t *alloc_dhcp_client_id_option(uint8_t type, uint8_t *idstr,
                                     size_t idstrlen);

uint8_t *get_option_data(struct dhcpmsg *packet, int code, ssize_t *optlen);
ssize_t get_end_option_idx(uint8_t *optbuf, size_t bufsize);
size_t add_option_string(uint8_t *optbuf, size_t buflen, uint8_t *optstr);
size_t add_u32_option(uint8_t *optbuf, size_t buflen, uint8_t code,
                      uint32_t data);
void add_option_request_list(uint8_t *optbuf, size_t buflen);

#endif
