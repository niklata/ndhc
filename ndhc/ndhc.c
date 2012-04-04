/* ndhc.c - DHCP client
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <net/if.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "ndhc-defines.h"
#include "config.h"
#include "state.h"
#include "options.h"
#include "dhcp.h"
#include "sys.h"
#include "ifchange.h"
#include "arp.h"
#include "nl.h"
#include "netlink.h"
#include "leasefile.h"

#include "log.h"
#include "chroot.h"
#include "cap.h"
#include "strl.h"
#include "pidfile.h"
#include "io.h"

#define VERSION "1.0"

struct client_state_t cs = {
    .init = 1,
    .epollFd = -1,
    .signalFd = -1,
    .listenFd = -1,
    .arpFd = -1,
    .nlFd = -1,
    .routerArp = "\0\0\0\0\0\0",
    .serverArp = "\0\0\0\0\0\0",
};

struct client_config_t client_config = {
    .interface = "eth0",
    .arp = "\0\0\0\0\0\0",
};

static void show_usage(void)
{
    printf(
"ndhc " VERSION ", dhcp client.  Licensed under GNU GPL.\n"
"Copyright (C) 2004-2011 Nicholas J. Kain\n"
"Usage: ndhc [OPTIONS]\n\n"
"  -c, --clientid=CLIENTID         Client identifier\n"
"  -h, --hostname=HOSTNAME         Client hostname\n"
"  -V, --vendorid=VENDORID         Client vendor identification string\n"
"  -f, --foreground                Do not fork after getting lease\n"
"  -b, --background                Fork to background if lease cannot be\n"
"                                  immediately negotiated.\n"
"  -p, --pidfile=FILE              File to which the pid will be written\n"
"  -l, --leasefile=FILE            File to which the lease IP will be written\n"
"  -i, --interface=INTERFACE       Interface to use (default: eth0)\n"
"  -n, --now                       Exit with failure if lease cannot be\n"
"                                  immediately negotiated.\n"
"  -q, --quit                      Quit after obtaining lease\n"
"  -r, --request=IP                IP address to request (default: none)\n"
"  -u, --user=USER                 Change privileges to this user\n"
"  -C, --chroot=DIR                Chroot to this directory\n"
"  -d, --relentless-defense        Never back off in defending IP against\n"
"                                  conflicting hosts (servers only)\n"
"  -v, --version                   Display version\n"
           );
    exit(EXIT_SUCCESS);
}

static void signal_dispatch()
{
    int t, off = 0;
    struct signalfd_siginfo si;
  again:
    t = read(cs.signalFd, (char *)&si + off, sizeof si - off);
    if (t < sizeof si - off) {
        if (t < 0) {
            if (t == EAGAIN || t == EWOULDBLOCK || t == EINTR)
                goto again;
            else
                suicide("signalfd read error");
        }
        off += t;
    }
    switch (si.ssi_signo) {
        case SIGUSR1:
            force_renew_action(&cs);
            break;
        case SIGUSR2:
            force_release_action(&cs);
            break;
        case SIGTERM:
            log_line("Received SIGTERM.  Exiting gracefully.");
            exit(EXIT_SUCCESS);
        default:
            break;
    }
}

static int is_string_hwaddr(char *str, size_t slen)
{
    if (slen == 17 && str[2] == ':' && str[5] == ':' && str[8] == ':' &&
        str[11] == ':' && str[14] == ':' &&
        isxdigit(str[0]) && isxdigit(str[1]) && isxdigit(str[3]) &&
        isxdigit(str[4]) && isxdigit(str[6]) && isxdigit(str[7]) &&
        isxdigit(str[9]) && isxdigit(str[10]) && isxdigit(str[12]) &&
        isxdigit(str[13]) && isxdigit(str[15]) && isxdigit(str[16])
        )
        return 1;
    return 0;
}

static int get_clientid_mac_string(char *str, size_t slen)
{
    if (!is_string_hwaddr(str, slen))
        return 0;
    client_config.clientid[0] = strtol(str, NULL, 16);
    client_config.clientid[1] = strtol(str+3, NULL, 16);
    client_config.clientid[2] = strtol(str+6, NULL, 16);
    client_config.clientid[3] = strtol(str+9, NULL, 16);
    client_config.clientid[4] = strtol(str+12, NULL, 16);
    client_config.clientid[5] = strtol(str+15, NULL, 16);
    client_config.clientid[6] = '\0';
    return 1;
}

static void do_work(void)
{
    struct epoll_event events[3];
    long long nowts;
    int timeout;

    cs.epollFd = epoll_create1(0);
    if (cs.epollFd == -1)
        suicide("epoll_create1 failed");
    setup_signals(&cs);
    epoll_add(&cs, cs.nlFd);
    set_listen_raw(&cs);
    nowts = curms();
    goto jumpstart;

    for (;;) {
        int r = epoll_wait(cs.epollFd, events, 3, timeout);
        if (r == -1) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        for (int i = 0; i < r; ++i) {
            int fd = events[i].data.fd;
            if (fd == cs.signalFd)
                signal_dispatch();
            else if (fd == cs.listenFd)
                handle_packet(&cs);
            else if (fd == cs.arpFd)
                handle_arp_response(&cs);
            else if (fd == cs.nlFd)
                handle_nl_message(&cs);
            else
                suicide("epoll_wait: unknown fd");
        }

        for (;;) {
            nowts = curms();
            long long arp_wake_ts = arp_get_wake_ts();
            long long dhcp_wake_ts = dhcp_get_wake_ts();
            if (arp_wake_ts == -1) {
                if (dhcp_wake_ts != -1) {
                    timeout = dhcp_wake_ts - nowts;
                    if (timeout < 0)
                        timeout = 0;
                } else
                    timeout = -1;
            } else {
                // If dhcp_wake_ts is -1 then we want to sleep anyway.
                timeout = (arp_wake_ts < dhcp_wake_ts ?
                           arp_wake_ts : dhcp_wake_ts) - nowts;
                if (timeout < 0)
                    timeout = 0;
            }

            if (!timeout) {
jumpstart:
                timeout_action(&cs, nowts);
            } else
                break;
        }
    }
}

int main(int argc, char **argv)
{
    char chroot_dir[MAX_PATH_LENGTH] = "";
    int c;
    struct passwd *pwd;
    uid_t uid = 0;
    gid_t gid = 0;
    static const struct option arg_options[] = {
        {"clientid",    required_argument,  0, 'c'},
        {"foreground",  no_argument,        0, 'f'},
        {"background",  no_argument,        0, 'b'},
        {"pidfile",     required_argument,  0, 'p'},
        {"leasefile",   required_argument,  0, 'l'},
        {"hostname",    required_argument,  0, 'h'},
        {"interface",   required_argument,  0, 'i'},
        {"now",         no_argument,        0, 'n'},
        {"quit",        no_argument,        0, 'q'},
        {"request",     required_argument,  0, 'r'},
        {"vendorid",    required_argument,  0, 'V'},
        {"user",        required_argument,  0, 'u'},
        {"chroot",      required_argument,  0, 'C'},
        {"relentless-defense", no_argument, 0, 'd'},
        {"version",     no_argument,        0, 'v'},
        {"help",        no_argument,        0, '?'},
        {0, 0, 0, 0}
    };

    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "c:fbp:h:i:np:l:qr:V:u:C:dv", arg_options,
                        &option_index);
        if (c == -1) break;

        switch (c) {
            case 'c':
                if (!get_clientid_mac_string(optarg, strlen(optarg)))
                    strlcpy(client_config.clientid, optarg,
                            sizeof client_config.clientid);
                else
                    client_config.clientid_mac = 1;
                break;
            case 'f':
                client_config.foreground = 1;
                gflags_detach = 0;
                break;
            case 'b':
                client_config.background_if_no_lease = 1;
                gflags_detach = 1;
                break;
            case 'p':
                strlcpy(pidfile, optarg, sizeof pidfile);
                break;
            case 'l':
                set_leasefile(optarg);
                break;
            case 'h':
                strlcpy(client_config.hostname, optarg,
                        sizeof client_config.hostname);
                break;
            case 'i':
                client_config.interface = optarg;
                break;
            case 'n':
                client_config.abort_if_no_lease = 1;
                break;
            case 'q':
                client_config.quit_after_lease = 1;
                break;
            case 'r':
                cs.clientAddr = inet_addr(optarg);
                break;
            case 'u':
                pwd = getpwnam(optarg);
                if (pwd) {
                    uid = (int)pwd->pw_uid;
                    gid = (int)pwd->pw_gid;
                } else {
                    printf("Bad username provided.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'C':
                strlcpy(chroot_dir, optarg, sizeof chroot_dir);
                break;
            case 'd':
                arp_relentless_def = 1;
                break;
            case 'v':
                printf(
"ndhc %s, dhcp client.  Licensed under GNU GPL.\n", VERSION);
                printf(
"Copyright (C) 2004-2011 Nicholas J. Kain\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
                exit(EXIT_SUCCESS);
                break;
            case 'V':
                strlcpy(client_config.vendor, optarg,
                        sizeof client_config.vendor);
                break;
            default:
                show_usage();
        }
    }

    log_line("ndhc client " VERSION " started.");

    if (client_config.foreground && !client_config.background_if_no_lease) {
        if (file_exists(pidfile, "w") == -1) {
            log_line("FATAL - cannot open pidfile for write!");
            exit(EXIT_FAILURE);
        }
        write_pid(pidfile);
    }

    if ((cs.nlFd = nl_open(NETLINK_ROUTE, RTMGRP_LINK, &nlportid)) < 0) {
        log_line("FATAL - failed to open netlink socket");
        exit(EXIT_FAILURE);
    }
    if (nl_getifdata(&cs) < 0) {
        log_line("FATAL - failed to get interface MAC and index");
        exit(EXIT_FAILURE);
    }

    open_leasefile();

    if (chdir(chroot_dir)) {
        printf("Failed to chdir(%s)!\n", chroot_dir);
        exit(EXIT_FAILURE);
    }

    if (chroot(chroot_dir)) {
        printf("Failed to chroot(%s)!\n", chroot_dir);
        exit(EXIT_FAILURE);
    }

    set_cap(uid, gid,
            "cap_net_bind_service,cap_net_broadcast,cap_net_raw=ep");
    drop_root(uid, gid);

    if (cs.ifsPrevState != IFS_UP)
        ifchange_deconfig();

    do_work();
    return EXIT_SUCCESS; // Never reached.
}
