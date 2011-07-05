/* ifchange.c - functions to call the interface change daemon
 * Time-stamp: <2011-07-05 19:22:50 njk>
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

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <errno.h>

#include "options.h"
#include "config.h"
#include "dhcp.h"
#include "options.h"
#include "arp.h"
#include "log.h"
#include "io.h"
#include "strl.h"
#include "ifchange.h"

static int cfg_deconfig; // Set if the interface has already been deconfigured.
static struct dhcpmsg cfg_packet; // Copy of the current configuration packet.

// Fill buf with the ifchd command text of option 'option'.
// Returns 0 if successful, -1 if nothing was filled in.
static int ifchd_cmd(char *buf, size_t buflen, uint8_t *option, ssize_t optlen,
                     uint8_t code)
{
    char *obuf = buf;
    uint8_t *ooption = option;
    const char *optname = option_name(code);
    enum option_type type = option_type(code);
    ssize_t typelen = option_length(code);

    if (!option || type == OPTION_NONE)
        return -1;

    if (type == OPTION_STRING) {
        buf += snprintf(buf, buflen, "%s:", optname);
        if (buflen < optlen + 1)
            return -1;
        memcpy(buf, option, optlen);
        buf[optlen] = ':';
        return 0;
    }

    // Length and type checking.
    if (optlen != typelen) {
        if (option_valid_list(code)) {
            if ((optlen % typelen)) {
                log_warning("Bad data received - option list size mismatch: code=0x%02x proplen=0x%02x optlen=0x%02x",
                            code, typelen, optlen);
                return -1;
            }
        } else {
            log_warning("Bad data received - option size mismatch: code=0x%02x proplen=0x%02x optlen=0x%02x",
                        code, typelen, optlen);
            return -1;
        }
    }

    buf += snprintf(buf, buflen, "%s:", optname);

    for(;;) {
        switch (type) {
            case OPTION_IP: {
                if (inet_ntop(AF_INET, option, buf, buflen - (buf - obuf) - 1))
                    buf += strlen(buf);
                break;
            }
            case OPTION_U8:
                buf += snprintf(buf, buflen - (buf - obuf) - 1, "%u ", *option);
                break;
            case OPTION_U16: {
                uint16_t val_u16;
                memcpy(&val_u16, option, 2);
                buf += snprintf(buf, buflen - (buf - obuf) - 1, "%u ",
                                ntohs(val_u16));
                break;
            }
            case OPTION_S16: {
                int16_t val_s16;
                memcpy(&val_s16, option, 2);
                buf += snprintf(buf, buflen - (buf - obuf) - 1, "%d ",
                                ntohs(val_s16));
                break;
            }
            case OPTION_U32: {
                uint32_t val_u32;
                memcpy(&val_u32, option, 4);
                buf += snprintf(buf, buflen - (buf - obuf) - 1, "%u ",
                                ntohl(val_u32));
                break;
            }
            case OPTION_S32: {
                int32_t val_s32;
                memcpy(&val_s32, option, 4);
                buf += snprintf(buf, buflen - (buf - obuf) - 1, "%d ",
                                ntohl(val_s32));
                break;
            }
            default:
                return 0;
        }
        option += typelen;
        if ((option - ooption) >= optlen)
            break;
        *(buf++) = ':';
    }
    *(buf++) = ':';
    return 0;
}

static int open_ifch(void) {
    int sockfd, ret;
    struct sockaddr_un address = {
        .sun_family = AF_UNIX,
        .sun_path = "/var/state/ifchange"
    };

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ret = connect(sockfd, (struct sockaddr *)&address, sizeof(address));

    if (ret == -1) {
        log_error("unable to connect to ifchd!");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static void sockwrite(int fd, const char *buf, size_t count)
{
    if (safe_write(fd, buf, count) == -1)
        log_error("sockwrite: write failed: %s", strerror(errno));
}

void ifchange_deconfig(void)
{
    int sockfd;
    char buf[256];

    if (cfg_deconfig)
        return;

    sockfd = open_ifch();

    snprintf(buf, sizeof buf, "interface:%s:ip:0.0.0.0:",
             client_config.interface);
    log_line("sent to ifchd: ip:0.0.0.0:");
    sockwrite(sockfd, buf, strlen(buf));

    cfg_deconfig = 1;
    memset(&cfg_packet, 0, sizeof cfg_packet);

    close(sockfd);
}

static size_t send_client_ip(char *out, size_t olen, struct dhcpmsg *packet)
{
    char ip[32], ipb[64];
    if (!memcmp(&packet->yiaddr, &cfg_packet.yiaddr, sizeof packet->yiaddr))
        return 0;
    inet_ntop(AF_INET, &packet->yiaddr, ip, sizeof ip);
    snprintf(ipb, sizeof ipb, "ip:%s:", ip);
    strlcat(out, ipb, olen);
    log_line("sent to ifchd: %s", ipb);
    return strlen(ipb);
}

static size_t send_cmd(char *out, size_t olen, struct dhcpmsg *packet,
                       uint8_t code)
{
    char buf[256];
    uint8_t *optdata, *olddata;
    ssize_t optlen, oldlen;

    if (!packet)
        return 0;

    memset(buf, '\0', sizeof buf);
    optdata = get_option_data(packet, code, &optlen);
    if (!optlen)
        return 0;
    olddata = get_option_data(&cfg_packet, code, &oldlen);
    if (oldlen == optlen && !memcmp(optdata, olddata, optlen))
        return 0;
    if (ifchd_cmd(buf, sizeof buf, optdata, optlen, code) == -1)
        return 0;
    strlcat(out, buf, olen);
    log_line("sent to ifchd: %s", buf);
    return strlen(buf);
}

void ifchange_bind(struct dhcpmsg *packet)
{
    char buf[2048];
    int sockfd;
    int tbs = 0;

    if (!packet)
        return;

    snprintf(buf, sizeof buf, "interface:%s:", client_config.interface);
    tbs |= send_client_ip(buf, sizeof buf, packet);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_SUBNET);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_ROUTER);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_DNS_SERVER);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_HOST_NAME);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_DOMAIN_NAME);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_MTU);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_BROADCAST);
    tbs |= send_cmd(buf, sizeof buf, packet, DHCP_WINS_SERVER);
    if (tbs) {
        sockfd = open_ifch();
        sockwrite(sockfd, buf, strlen(buf));
        close(sockfd);
    }

    cfg_deconfig = 0;
    memcpy(&cfg_packet, packet, sizeof cfg_packet);
}
