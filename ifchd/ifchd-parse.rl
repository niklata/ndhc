/* ifchd-parse.rl - interface change daemon parser
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

#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

#include "ifchd-defines.h"
#include "log.h"
#include "ifch_proto.h"
#include "strl.h"
#include "linux.h"

%%{
    machine ipv4set_parser;

    action XSt { arg_start = p; }
    action IpEn {
        arg_len = p - arg_start;
        if (arg_len > sizeof ip4_addr - 1) {
            have_ip = true;
            memcpy(ip4_addr, arg_start, arg_len);
        }
        ip4_addr[arg_len] = 0;
    }
    action SnEn {
        arg_len = p - arg_start;
        if (arg_len > sizeof ip4_subnet - 1) {
            have_subnet = true;
            memcpy(ip4_subnet, arg_start, arg_len);
        }
        ip4_subnet[arg_len] = 0;
    }
    action BcEn {
        arg_len = p - arg_start;
        if (arg_len > sizeof ip4_bcast - 1) {
            have_ip = true;
            memcpy(ip4_bcast, arg_start, arg_len);
        }
        ip4_bcast[arg_len] = 0;
    }

    v4addr = digit{1,3} '.' digit{1,3} '.' digit{1,3} '.' digit{1,3};
    ip4_nobc = (v4addr > XSt % IpEn) ',' (v4addr > XSt % SnEn);
    ip4_bc = (v4addr > XSt % IpEn) ',' (v4addr > XSt % SnEn) ','
             (v4addr > XSt % BcEn);
    main := (ip4_bc|ip4_nobc);
}%%

%% write data;

static void perform_ip4set(struct ifchd_client *cl, const char *buf,
                           size_t len)
{
    char ip4_addr[INET_ADDRSTRLEN];
    char ip4_subnet[INET_ADDRSTRLEN];
    char ip4_bcast[INET_ADDRSTRLEN];
    const char *p = buf;
    const char *pe = p + len;
    const char *eof = pe;
    const char *arg_start;
    size_t arg_len;
    unsigned int cs = 0;
    bool have_ip = false;
    bool have_subnet = false;
    bool have_bcast = false;

    %% write init;
    %% write exec;

    if (cs < ipv4set_parser_first_final) {
        log_line("%s: received invalid arguments", __func__);
        return;
    }

    // These should never trigger because of the above check, but be safe...
    if (!have_ip) {
        log_line("%s: No IPv4 address specified.", __func__);
        return;
    }
    if (!have_subnet) {
        log_line("%s: No IPv4 subnet specified.", __func__);
        return;
    }

    perform_ip_subnet_bcast(cl, ip4_addr, ip4_subnet,
                            have_bcast ? ip4_bcast : NULL);
}

%%{
    machine ifchd_parser;

    action Reset { cl->state = STATE_NOTHING; }
    action ArgSt { arg_start = p; }
    action ArgEn {
        arg_len = p - arg_start;
        if (arg_len > sizeof tb - 1) {
            log_line("command argument would overflow");
            return -1;
        }
        memcpy(tb, arg_start, arg_len);
        tb[arg_len] = 0;
    }

    action Dispatch {
        switch (cl->state) {
        case STATE_INTERFACE: perform_interface(cl, tb, arg_len); break;
        case STATE_IP4SET: perform_ip4set(cl, tb, arg_len); break;
        case STATE_IP: perform_ip(cl, tb, arg_len); break;
        case STATE_SUBNET: perform_subnet(cl, tb, arg_len); break;
        case STATE_TIMEZONE: perform_timezone(cl, tb, arg_len); break;
        case STATE_ROUTER: perform_router(cl, tb, arg_len); break;
        case STATE_DNS: perform_dns(cl, tb, arg_len); break;
        case STATE_LPRSVR: perform_lprsvr(cl, tb, arg_len); break;
        case STATE_HOSTNAME: perform_hostname(cl, tb, arg_len); break;
        case STATE_DOMAIN: perform_domain(cl, tb, arg_len); break;
        case STATE_IPTTL: perform_ipttl(cl, tb, arg_len); break;
        case STATE_MTU: perform_mtu(cl, tb, arg_len); break;
        case STATE_BROADCAST: perform_broadcast(cl, tb, arg_len); break;
        case STATE_NTPSVR: perform_ntpsrv(cl, tb, arg_len); break;
        case STATE_WINS: perform_wins(cl, tb, arg_len); break;
        default:
            log_line("error: invalid state in dispatch_work");
            return -1;
        }
    }

    terminator = ';' > Dispatch;
    v4addr = digit{1,3} '.' digit{1,3} '.' digit{1,3} '.' digit{1,3};
    ip_arg = (v4addr > ArgSt % ArgEn) terminator;
    ip4set_arg = (((v4addr ','){1,2} v4addr) > ArgSt % ArgEn) terminator;
    iplist_arg = (((v4addr ',')* v4addr) > ArgSt % ArgEn) terminator;
    str_arg = ([^;\0]+ > ArgSt % ArgEn) terminator;
    s32_arg = (extend{4} > ArgSt % ArgEn) terminator;
    u16_arg = (extend{2} > ArgSt % ArgEn) terminator;
    u8_arg = (extend{1} > ArgSt % ArgEn) terminator;

    cmd_ip = ('ip:' % { cl->state = STATE_IP; }
             |'snet:' % { cl->state = STATE_SUBNET; }
             |'routr:' % { cl->state = STATE_ROUTER; }
             |'bcast:' % { cl->state = STATE_BROADCAST; }
             ) ip_arg;
    cmd_ip4set = ('ip4:' % { cl->state = STATE_IP4SET; }) ip4set_arg;
    cmd_iplist = ('dns:' % { cl->state = STATE_DNS; }
                 |'lpr:' % { cl->state = STATE_LPRSVR; }
                 |'ntp:' % { cl->state = STATE_NTPSVR; }
                 |'wins:' % { cl->state = STATE_WINS; }
                 ) iplist_arg;
    cmd_str = ('iface:' % { cl->state = STATE_INTERFACE; }
              |'host:' % { cl->state = STATE_HOSTNAME; }
              |'dom:' % { cl->state = STATE_DOMAIN; }
              ) str_arg;
    cmd_s32 = ('tzone:' % { cl->state = STATE_TIMEZONE; }) s32_arg;
    cmd_u16 = ('mtu:' % { cl->state = STATE_MTU; }) u16_arg;
    cmd_u8  = ('ipttl:' % { cl->state = STATE_IPTTL; }) u8_arg;

    command = (cmd_ip|cmd_iplist|cmd_str|cmd_s32|cmd_u16|cmd_u8);
    main := (command > Reset)+;
}%%

%% write data;

/*
 * Returns -1 on fatal error; that leads to peer connection being closed.
 */
int execute_buffer(struct ifchd_client *cl, char *newbuf)
{
    char buf[MAX_BUF * 2];
    char tb[MAX_BUF];

    if (strnkcpy(buf, cl->ibuf, sizeof buf))
        goto buftooshort;
    if (strnkcat(buf, newbuf, sizeof buf)) {
buftooshort:
        log_line("error: input is too long for buffer");
        return -1;
    }

    size_t init_siz = strlen(buf);
    const char *p = buf;
    const char *pe = p + init_siz;
    const char *arg_start;
    size_t arg_len;
    unsigned int cs = 0;

    %% write init;
    %% write exec;

    size_t bytes_left = pe - p;
    if (bytes_left > 0) {
        size_t taken = init_siz - bytes_left;
        strnkcpy(cl->ibuf, buf + taken, MAX_BUF);
    }

    if (cs < ifchd_parser_first_final) {
        log_line("error: received invalid commands");
        return -1;
    }
    log_line("Commands received and successfully executed.");
    return 0;
}

