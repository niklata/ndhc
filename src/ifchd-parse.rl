/* ifchd-parse.rl - interface change daemon parser
 *
 * Copyright (c) 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "nk/log.h"

#include "ifchd-parse.h"
#include "ifchd.h"
#include "ifset.h"
#include "ndhc.h"

%%{
    machine ipv4set_parser;

    action XSt { arg_start = p; }
    action IpEn {
        ptrdiff_t arg_len = p - arg_start;
        if (arg_len > 0 && (size_t)arg_len < sizeof ip4_addr) {
            have_ip = true;
            memcpy(ip4_addr, arg_start, (size_t)arg_len);
        }
        ip4_addr[arg_len] = 0;
    }
    action SnEn {
        ptrdiff_t arg_len = p - arg_start;
        if (arg_len > 0 && (size_t)arg_len < sizeof ip4_subnet) {
            have_subnet = true;
            memcpy(ip4_subnet, arg_start, (size_t)arg_len);
        }
        ip4_subnet[arg_len] = 0;
    }
    action BcEn {
        ptrdiff_t arg_len = p - arg_start;
        if (arg_len > 0 && (size_t)arg_len < sizeof ip4_bcast) {
            have_ip = true;
            memcpy(ip4_bcast, arg_start, (size_t)arg_len);
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

static int perform_ip4set(const char buf[static 1], size_t len)
{
    char ip4_addr[INET_ADDRSTRLEN];
    char ip4_subnet[INET_ADDRSTRLEN];
    char ip4_bcast[INET_ADDRSTRLEN];
    const char *p = buf;
    const char *pe = p + len;
    const char *eof = pe;
    const char *arg_start;
    int cs = 0;
    bool have_ip = false;
    bool have_subnet = false;
    bool have_bcast = false;

    %% write init;
    %% write exec;

    if (cs < ipv4set_parser_first_final) {
        log_line("%s: received invalid arguments", __func__);
        return -1;
    }

    // These should never trigger because of the above check, but be safe...
    if (!have_ip) {
        log_line("%s: No IPv4 address specified.", __func__);
        return -1;
    }
    if (!have_subnet) {
        log_line("%s: No IPv4 subnet specified.", __func__);
        return -1;
    }

    return perform_ip_subnet_bcast(ip4_addr, ip4_subnet,
                                   have_bcast ? ip4_bcast : NULL);
}

%%{
    machine ifchd_parser;

    action Reset { cl.state = STATE_NOTHING; }
    action ArgSt { arg_start = p; }
    action ArgEn {
        ptrdiff_t al = p - arg_start;
        if (al < 0 || (size_t)al > sizeof tb - 1) {
            log_line("command argument would overflow");
            return -99;
        }
        arg_len = (size_t)al;
        memcpy(tb, arg_start, arg_len);
        tb[arg_len] = 0;
    }

    action Dispatch {
        int pr = 0;
        switch (cl.state) {
        case STATE_IP4SET: pr = perform_ip4set(tb, arg_len); break;
        case STATE_TIMEZONE: pr = perform_timezone( tb, arg_len); break;
        case STATE_ROUTER: pr = perform_router(tb, arg_len); break;
        case STATE_DNS: pr = perform_dns(tb, arg_len); break;
        case STATE_LPRSVR: pr = perform_lprsvr(tb, arg_len); break;
        case STATE_HOSTNAME: pr = perform_hostname(tb, arg_len); break;
        case STATE_DOMAIN: pr = perform_domain(tb, arg_len); break;
        case STATE_IPTTL: pr = perform_ipttl(tb, arg_len); break;
        case STATE_MTU: pr = perform_mtu(tb, arg_len); break;
        case STATE_NTPSVR: pr = perform_ntpsrv(tb, arg_len); break;
        case STATE_WINS: pr = perform_wins(tb, arg_len); break;
        case STATE_CARRIER: pr = perform_carrier(); break;
        default:
            arg_len = 0;
            log_line("error: invalid state in dispatch_work");
            return -99;
        }
        arg_len = 0;
        if (pr == -99)
            return -99;
        cmdf |= pr;
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

    cmd_ip = ('routr:' % { cl.state = STATE_ROUTER; }) ip_arg;
    cmd_ip4set = ('ip4:' % { cl.state = STATE_IP4SET; }) ip4set_arg;
    cmd_iplist = ('dns:' % { cl.state = STATE_DNS; }
                 |'lpr:' % { cl.state = STATE_LPRSVR; }
                 |'ntp:' % { cl.state = STATE_NTPSVR; }
                 |'wins:' % { cl.state = STATE_WINS; }
                 ) iplist_arg;
    cmd_str = ('host:' % { cl.state = STATE_HOSTNAME; }
              |'dom:' % { cl.state = STATE_DOMAIN; }
              ) str_arg;
    cmd_s32 = ('tzone:' % { cl.state = STATE_TIMEZONE; }) s32_arg;
    cmd_u16 = ('mtu:' % { cl.state = STATE_MTU; }) u16_arg;
    cmd_u8  = ('ipttl:' % { cl.state = STATE_IPTTL; }) u8_arg;
    cmd_none = ('carrier:' % { cl.state = STATE_CARRIER; }) terminator;

    command = (cmd_ip|cmd_ip4set|cmd_iplist|cmd_str|cmd_s32|cmd_u16|cmd_u8|cmd_none);
    main := (command > Reset)+;
}%%

%% write data;

/*
 * Returns -99 on fatal error; that leads to peer connection being closed.
 * Returns -1 if one of the commands failed.
 * Returns 0 on success.
 */
int execute_buffer(const char newbuf[static 1])
{
    char buf[MAX_BUF * 2];
    char tb[MAX_BUF];
    int cmdf = 0;

    ssize_t buflen = snprintf(buf, sizeof buf, "%s%s", cl.ibuf, newbuf);
    if (buflen < 0) {
        log_error("%s: (%s) snprintf1 failed; your system is broken?",
                  client_config.interface, __func__);
        return -99;
    }
    if ((size_t)buflen >= sizeof buf) {
        log_error("%s: (%s) input is too long for buffer",
                  client_config.interface, __func__);
        return -99;
    }

    size_t init_siz = strlen(buf);
    const char *p = buf;
    const char *pe = p + init_siz;
    const char *arg_start;
    size_t arg_len = 0;
    int cs = 0;

    %% write init;
    %% write exec;

    ptrdiff_t blt = pe - p;
    size_t bytes_left = blt >= 0 ? (size_t)blt : 0;
    if (bytes_left > 0) {
        size_t taken = init_siz - bytes_left;
        ssize_t ilen = snprintf(cl.ibuf, sizeof cl.ibuf, "%s", buf + taken);
        if (ilen < 0) {
            log_error("%s: (%s) snprintf2 failed; your system is broken?",
                      client_config.interface, __func__);
            return -99;
        }
        if ((size_t)ilen >= sizeof buf) {
            log_error("%s: (%s) unconsumed input too long for buffer",
                      client_config.interface, __func__);
            return -99;
        }
    }

    if (cs < ifchd_parser_first_final) {
        log_error("%s: ifch received invalid commands",
                  client_config.interface);
        return -99;
    }
    return !cmdf ? 0 : -1;
}

