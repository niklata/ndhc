/* ifchd-parse.rl - interface change daemon parser
 *
 * Copyright (c) 2004-2013 Nicholas J. Kain <njkain at gmail dot com>
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

#include "ifchd-defines.h"
#include "log.h"
#include "ifch_proto.h"
#include "strl.h"
#include "linux.h"

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

    interface = 'iface';
    ip = 'ip';
    subnet = 'snet';
    dns = 'dns';
    lprsvr = 'lpr';
    ntpsvr = 'ntp';
    wins = 'wins';
    router = 'routr';
    broadcast = 'bcast';
    timezone = 'tzone';
    hostname = 'host';
    domain = 'dom';
    ipttl = 'ipttl';
    mtu = 'mtu';

    cmdname = (interface % { cl->state = STATE_INTERFACE; }
              |ip % { cl->state = STATE_IP; }
              |subnet % { cl->state = STATE_SUBNET; }
              |dns % { cl->state = STATE_DNS; }
              |lprsvr % { cl->state = STATE_LPRSVR; }
              |ntpsvr % { cl->state = STATE_NTPSVR; }
              |wins % { cl->state = STATE_WINS; }
              |router % { cl->state = STATE_ROUTER; }
              |broadcast % { cl->state = STATE_BROADCAST; }
              |timezone % { cl->state = STATE_TIMEZONE; }
              |hostname % { cl->state = STATE_HOSTNAME; }
              |domain % { cl->state = STATE_DOMAIN; }
              |ipttl % { cl->state = STATE_IPTTL; }
              |mtu % { cl->state = STATE_MTU; }
              );

    command = cmdname ':' ([^;\0]+ > ArgSt % ArgEn) (';' > Dispatch);
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

