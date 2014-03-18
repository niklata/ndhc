/* options.h - DHCP options handling
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
#ifndef OPTIONS_H_
#define OPTIONS_H_

#include "dhcp.h"

#define DCODE_PADDING      0x00
#define DCODE_SUBNET       0x01
#define DCODE_TIMEZONE     0x02
#define DCODE_ROUTER       0x03
#define DCODE_DNS          0x06
#define DCODE_LPRSVR       0x09
#define DCODE_HOSTNAME     0x0c
#define DCODE_DOMAIN       0x0f
#define DCODE_IPTTL        0x17
#define DCODE_MTU          0x1a
#define DCODE_BROADCAST    0x1c
#define DCODE_NTPSVR       0x2a
#define DCODE_WINS         0x2c
#define DCODE_REQIP        0x32
#define DCODE_LEASET       0x33
#define DCODE_OVERLOAD     0x34
#define DCODE_MSGTYPE      0x35
#define DCODE_SERVER_ID    0x36
#define DCODE_PARAM_REQ    0x37
#define DCODE_MAX_SIZE     0x39
#define DCODE_VENDOR       0x3c
#define DCODE_CLIENT_ID    0x3d
#define DCODE_END          0xff

#define MAX_DOPT_SIZE 500

ssize_t get_dhcp_opt(const struct dhcpmsg *packet, uint8_t code, uint8_t *dbuf,
                     ssize_t dlen);
ssize_t get_end_option_idx(const struct dhcpmsg *packet);

size_t add_option_string(struct dhcpmsg *packet, uint8_t code, const char *str,
                         size_t slen);
size_t add_u32_option(struct dhcpmsg *packet, uint8_t code, uint32_t data);

size_t add_option_request_list(struct dhcpmsg *packet);
size_t add_option_domain_name(struct dhcpmsg *packet, const char *dom,
                              size_t domlen);
void add_option_subnet_mask(struct dhcpmsg *packet, uint32_t subnet);
void add_option_broadcast(struct dhcpmsg *packet, uint32_t bc);
void add_option_msgtype(struct dhcpmsg *packet, uint8_t type);
void add_option_reqip(struct dhcpmsg *packet, uint32_t ip);
void add_option_serverid(struct dhcpmsg *packet, uint32_t sid);
void add_option_clientid(struct dhcpmsg *packet, const char *clientid,
                         size_t clen);
#ifndef NDHS_BUILD
void add_option_maxsize(struct dhcpmsg *packet);
void add_option_vendor(struct dhcpmsg *packet);
void add_option_hostname(struct dhcpmsg *packet);
#endif
uint32_t get_option_router(const struct dhcpmsg *packet);
uint8_t get_option_msgtype(const struct dhcpmsg *packet);
uint32_t get_option_serverid(const struct dhcpmsg *packet, int *found);
uint32_t get_option_leasetime(const struct dhcpmsg *packet);
size_t get_option_clientid(const struct dhcpmsg *packet, const char *cbuf,
                           size_t clen);

#endif
