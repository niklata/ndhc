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

#include "dhcp.h"

enum dhcp_codes {
    DHCP_PADDING             = 0x00,
    DHCP_SUBNET              = 0x01,
    DHCP_TIME_OFFSET         = 0x02,
    DHCP_ROUTER              = 0x03,
    DHCP_TIME_SERVER         = 0x04,
    DHCP_NAME_SERVER         = 0x05,
    DHCP_DNS_SERVER          = 0x06,
    DHCP_LOG_SERVER          = 0x07,
    DHCP_COOKIE_SERVER       = 0x08,
    DHCP_LPR_SERVER          = 0x09,
    DHCP_HOST_NAME           = 0x0c,
    DHCP_BOOT_SIZE           = 0x0d,
    DHCP_DOMAIN_NAME         = 0x0f,
    DHCP_SWAP_SERVER         = 0x10,
    DHCP_ROOT_PATH           = 0x11,
    DHCP_IP_TTL              = 0x17,
    DHCP_MTU                 = 0x1a,
    DHCP_BROADCAST           = 0x1c,
    DHCP_NIS_DOMAIN          = 0x28,
    DHCP_NIS_SERVER          = 0x29,
    DHCP_NTP_SERVER          = 0x2a,
    DHCP_WINS_SERVER         = 0x2c,
    DHCP_REQUESTED_IP        = 0x32,
    DHCP_LEASE_TIME          = 0x33,
    DHCP_OPTION_OVERLOAD     = 0x34,
    DHCP_MESSAGE_TYPE        = 0x35,
    DHCP_SERVER_ID           = 0x36,
    DHCP_PARAM_REQ           = 0x37,
    DHCP_MESSAGE             = 0x38,
    DHCP_MAX_SIZE            = 0x39,
    DHCP_T1                  = 0x3a,
    DHCP_T2                  = 0x3b,
    DHCP_VENDOR              = 0x3c,
    DHCP_CLIENT_ID           = 0x3d,
    DHCP_TFTP_SERVER_NAME    = 0x42,
    DHCP_BOOT_FILE           = 0x43,
    DHCP_USER_CLASS          = 0x4d,
    DHCP_FQDN                = 0x51,
    DHCP_DOMAIN_SEARCH       = 0x77,
    DHCP_SIP_SERVERS         = 0x78,
    DHCP_STATIC_ROUTES       = 0x79,
    DHCP_WPAD                = 0xfc,
    DHCP_END                 = 0xff,
};

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

uint8_t *get_option_data(struct dhcpmsg *packet, int code, ssize_t *optlen);
ssize_t get_end_option_idx(struct dhcpmsg *packet);
size_t add_option_string(struct dhcpmsg *packet, uint8_t code, char *str,
                         size_t slen);
size_t add_u8_option(struct dhcpmsg *packet, uint8_t code, uint8_t data);
size_t add_u16_option(struct dhcpmsg *packet, uint8_t code, uint16_t data);
size_t add_u32_option(struct dhcpmsg *packet, uint8_t code, uint32_t data);
size_t add_option_request_list(struct dhcpmsg *packet);

#endif
