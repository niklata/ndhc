/* ndhc.c - DHCP client
 *
 * Copyright (c) 2004-2015 Nicholas J. Kain <njkain at gmail dot com>
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
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
#include <sys/prctl.h>
#include <net/if.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include "nk/log.h"
#include "nk/privilege.h"
#include "nk/pidfile.h"
#include "nk/io.h"
#include "nk/copy_cmdarg.h"

#include "ndhc.h"
#include "ndhc-defines.h"
#include "cfg.h"
#include "seccomp.h"
#include "state.h"
#include "options.h"
#include "dhcp.h"
#include "sys.h"
#include "ifchange.h"
#include "arp.h"
#include "nl.h"
#include "netlink.h"
#include "leasefile.h"
#include "ifset.h"
#include "ifchd.h"
#include "duiaid.h"
#include "sockd.h"
#include "rfkill.h"

struct client_state_t cs = {
    .init = 1,
    .epollFd = -1,
    .signalFd = -1,
    .listenFd = -1,
    .arpFd = -1,
    .nlFd = -1,
    .nlPortId = -1,
    .rfkillFd = -1,
    .dhcp_wake_ts = -1,
    .routerArp = "\0\0\0\0\0\0",
    .serverArp = "\0\0\0\0\0\0",
};

struct client_config_t client_config = {
    .interface = "eth0",
    .arp = "\0\0\0\0\0\0",
    .clientid_len = 0,
    .metric = 0,
    .foreground = 1,
};

void set_client_addr(const char v[static 1]) { cs.clientAddr = inet_addr(v); }

void print_version(void)
{
    printf("ndhc %s, dhcp client.\n", NDHC_VERSION);
    printf("Copyright (c) 2004-2015 Nicholas J. Kain\n"
           "All rights reserved.\n\n"
           "Redistribution and use in source and binary forms, with or without\n"
           "modification, are permitted provided that the following conditions are met:\n\n"
           "- Redistributions of source code must retain the above copyright notice,\n"
           "  this list of conditions and the following disclaimer.\n"
           "- Redistributions in binary form must reproduce the above copyright notice,\n"
           "  this list of conditions and the following disclaimer in the documentation\n"
           "  and/or other materials provided with the distribution.\n\n"
           "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
           "AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
           "IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
           "ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE\n"
           "LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
           "CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
           "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
           "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
           "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
           "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
           "POSSIBILITY OF SUCH DAMAGE.\n");
    exit(EXIT_SUCCESS);
}

void show_usage(void)
{
    printf(
"ndhc " NDHC_VERSION ", dhcp client.  Licensed under 2-clause BSD.\n"
"Copyright (C) 2004-2015 Nicholas J. Kain\n"
"Usage: ndhc [OPTIONS]\n\n"
"  -c, --config=FILE               Path to ndhc configuration file\n"
"  -I, --clientid=CLIENTID         Client identifier\n"
"  -h, --hostname=HOSTNAME         Client hostname\n"
"  -V, --vendorid=VENDORID         Client vendor identification string\n"
"  -b, --background                Fork to background if lease cannot be\n"
"                                  immediately negotiated.\n"
"  -p, --pidfile=FILE              File where the ndhc pid will be written\n"
"  -i, --interface=INTERFACE       Interface to use (default: eth0)\n"
"  -n, --now                       Exit with failure if lease cannot be\n"
"                                  immediately negotiated.\n"
"  -q, --quit                      Quit after obtaining lease\n"
"  -r, --request=IP                IP address to request (default: none)\n"
"  -u, --user=USER                 Change ndhc privileges to this user\n"
"  -U, --ifch-user=USER            Change ndhc-ifch privileges to this user\n"
"  -D, --sockd-user=USER           Change ndhc-sockd privileges to this user\n"
"  -C, --chroot=DIR                Chroot to this directory\n"
"  -s, --state-dir=DIR             State storage dir (default: /etc/ndhc)\n"
#ifdef ENABLE_SECCOMP_FILTER
"  -S, --seccomp-enforce           Enforce seccomp syscall restrictions\n"
#endif
"  -d, --relentless-defense        Never back off in defending IP against\n"
"                                  conflicting hosts (servers only)\n"
"  -w, --arp-probe-wait            Time to delay before first ARP probe\n"
"  -W, --arp-probe-num             Number of ARP probes before lease is ok\n"
"  -m, --arp-probe-min             Min ms to wait for ARP response\n"
"  -M, --arp-probe-max             Max ms to wait for ARP response\n"
"  -t, --gw-metric                 Route metric for default gw (default: 0)\n"
"  -R, --resolve-conf=FILE         Path to resolv.conf or equivalent\n"
"  -H, --dhcp-set-hostname         Allow DHCP to set machine hostname\n"
"  -v, --version                   Display version\n"
           );
    exit(EXIT_SUCCESS);
}

static void setup_signals_ndhc(void)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");
    if (cs.signalFd >= 0) {
        epoll_del(cs.epollFd, cs.signalFd);
        close(cs.signalFd);
    }
    cs.signalFd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (cs.signalFd < 0)
        suicide("signalfd failed");
    epoll_add(cs.epollFd, cs.signalFd);
}

static int signal_dispatch(void)
{
    struct signalfd_siginfo si;
    memset(&si, 0, sizeof si);
    ssize_t r = safe_read(cs.signalFd, (char *)&si, sizeof si);
    if (r < 0) {
        log_error("%s: ndhc: error reading from signalfd: %s",
                  client_config.interface, strerror(errno));
        return SIGNAL_NONE;
    }
    if ((size_t)r < sizeof si) {
        log_error("%s: ndhc: short read from signalfd: %zd < %zu",
                  client_config.interface, r, sizeof si);
        return SIGNAL_NONE;
    }
    switch (si.ssi_signo) {
        case SIGUSR1: return SIGNAL_RENEW;
        case SIGUSR2: return SIGNAL_RELEASE;
        case SIGCHLD:
            suicide("ndhc-master: Subprocess terminated unexpectedly.  Exiting.");
        case SIGTERM:
            log_line("Received SIGTERM.  Exiting gracefully.");
            exit(EXIT_SUCCESS);
        default: return SIGNAL_NONE;
    }
}

static int is_string_hwaddr(const char str[static 1], size_t slen)
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

int get_clientid_string(const char str[static 1], size_t slen)
{
    if (!slen)
        return -1;
    if (!is_string_hwaddr(str, slen)) {
        client_config.clientid[0] = 0;
        memcpy(client_config.clientid + 1, str,
               min_size_t(slen, sizeof client_config.clientid - 1));
        client_config.clientid_len = slen + 1;
        return 0;
    }

    uint8_t mac[6];
    for (size_t i = 0; i < sizeof mac; ++i)
        mac[i] = strtol(str+i*3, NULL, 16);
    client_config.clientid[0] = 1; // Ethernet MAC type
    memcpy(client_config.clientid + 1, mac,
           min_size_t(sizeof mac, sizeof client_config.clientid - 1));
    client_config.clientid_len = 7;
    return 1;
}

static void fail_if_state_dir_dne(void)
{
    if (strlen(state_dir) == 0)
        suicide("state_dir path is empty; it must be specified");
    struct stat st;
    if (stat(state_dir, &st) < 0)
        suicide("failed to stat state_dir path '%s': %s",
                state_dir, strerror(errno));
    if (!S_ISDIR(st.st_mode))
        suicide("state_dir path '%s' does not specify a directory", state_dir);
}

static void do_ndhc_work(void)
{
    static bool rfkill_set; // Is the rfkill switch set?
    static bool rfkill_nl_state_changed; // iface state changed during rfkill
    static int rfkill_nl_state; // current iface state during rfkill
    struct dhcpmsg dhcp_packet;
    struct epoll_event events[1];
    long long nowts;
    int timeout;

    cs.epollFd = epoll_create1(0);
    if (cs.epollFd < 0)
        suicide("epoll_create1 failed");

    if (enforce_seccomp_ndhc())
        log_line("ndhc seccomp filter cannot be installed");

    setup_signals_ndhc();

    epoll_add(cs.epollFd, cs.nlFd);
    epoll_add(cs.epollFd, ifchStream[0]);
    epoll_add(cs.epollFd, sockdStream[0]);
    if (client_config.enable_rfkill && cs.rfkillFd != -1)
        epoll_add(cs.epollFd, cs.rfkillFd);
    start_dhcp_listen(&cs);
    timeout = 0;

    for (;;) {
        int maxi = epoll_wait(cs.epollFd, events, 1, timeout);
        if (maxi < 0) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        int sev_dhcp = -1;
        uint32_t dhcp_srcaddr;
        uint8_t dhcp_msgtype;
        int sev_arp = ARPP_NONE;
        int sev_nl = IFS_NONE;
        int sev_rfk = RFK_NONE;
        int sev_signal = SIGNAL_NONE;
        bool force_fingerprint = false;
        for (int i = 0; i < maxi; ++i) {
            int fd = events[i].data.fd;
            if (fd == cs.signalFd) {
                if (!(events[i].events & EPOLLIN))
                    return;
                sev_signal = signal_dispatch();
            } else if (fd == cs.listenFd) {
                if (!(events[i].events & EPOLLIN))
                    return;
                sev_dhcp = dhcp_packet_get(&cs, &dhcp_packet, &dhcp_msgtype,
                                           &dhcp_srcaddr);
            } else if (fd == cs.arpFd) {
                if (!(events[i].events & EPOLLIN))
                    return;
                sev_arp = arp_packet_get(&cs);
            } else if (fd == cs.nlFd) {
                if (!(events[i].events & EPOLLIN))
                    return;
                sev_nl = nl_event_get(&cs);
            } else if (fd == ifchStream[0]) {
                if (events[i].events & (EPOLLHUP|EPOLLERR|EPOLLRDHUP))
                    exit(EXIT_FAILURE);
            } else if (fd == sockdStream[0]) {
                if (events[i].events & (EPOLLHUP|EPOLLERR|EPOLLRDHUP))
                    exit(EXIT_FAILURE);
            } else if (fd == cs.rfkillFd && client_config.enable_rfkill) {
                if (!(events[i].events & EPOLLIN))
                    return;
                sev_rfk = rfkill_get(&cs, 1, client_config.rfkillIdx);
            } else
                suicide("epoll_wait: unknown fd");

            if (sev_rfk == RFK_ENABLED) {
                rfkill_set = 1;
                rfkill_nl_state = cs.ifsPrevState;
                rfkill_nl_state_changed = false;
                log_line("rfkill: radio now blocked");
            } else if (sev_rfk == RFK_DISABLED) {
                rfkill_set = 0;
                log_line("rfkill: radio now unblocked");
                // We now simulate the state changes that may have happened
                // during rfkill.
                if (rfkill_nl_state != cs.ifsPrevState)
                    nl_event_react(&cs, rfkill_nl_state);
                else if (rfkill_nl_state_changed && rfkill_nl_state == IFS_UP) {
                    // We might have changed networks even if we ended up
                    // back in IFS_UP state.  We need to fingerprint the
                    // network and confirm that we're on the same network.
                    force_fingerprint = true;
                }
            }
        }

        if (sev_nl != IFS_NONE) {
            if (!rfkill_set) {
                if (nl_event_react(&cs, sev_nl))
                    force_fingerprint = true;
            } else {
                // Store the state so it can be replayed later.
                rfkill_nl_state_changed = true;
                rfkill_nl_state = sev_nl;
            }
        }

        if (rfkill_set || cs.ifsPrevState != IFS_UP) {
            // We can't do anything while the iface is disabled, anyway.
            // XXX: It may be smart to set a non-infinite timeout
            // and periodically poll to see if the rfkill or iface
            // state changed; it might happen during suspend.
            timeout = -1;
            continue;
        }

        nowts = curms();
        long long arp_wake_ts = arp_get_wake_ts();
        int dhcp_ok = dhcp_handle(&cs, nowts, sev_dhcp, &dhcp_packet,
                                  dhcp_msgtype, dhcp_srcaddr,
                                  sev_arp, force_fingerprint,
                                  cs.dhcp_wake_ts <= nowts,
                                  arp_wake_ts <= nowts, sev_signal);
        if (sev_arp)
            arp_reply_clear();

        // XXX: Would be best if we detected RFKILL being set via an
        //      error message and propagated it back to here as a
        //      distinct return value.
        if (dhcp_ok == COR_ERROR) {
            timeout = -1;
            continue;
        }

        arp_wake_ts = arp_get_wake_ts();
        if (arp_wake_ts < 0) {
            if (cs.dhcp_wake_ts != -1) {
                timeout = cs.dhcp_wake_ts - nowts;
                if (timeout < 0)
                    timeout = 0;
            } else
                timeout = -1;
        } else {
            // If cs.dhcp_wake_ts is -1 then we want to sleep anyway.
            timeout = (arp_wake_ts < cs.dhcp_wake_ts ?
                       arp_wake_ts : cs.dhcp_wake_ts) - nowts;
            if (timeout < 0)
                timeout = 0;
        }
    }
}

char state_dir[PATH_MAX] = "/etc/ndhc";
char chroot_dir[PATH_MAX] = "";
char resolv_conf_d[PATH_MAX] = "";
char pidfile[PATH_MAX] = PID_FILE_DEFAULT;
uid_t ndhc_uid = 0;
gid_t ndhc_gid = 0;
int ifchSock[2];
int sockdSock[2];
int ifchStream[2];
int sockdStream[2];

static void create_ifch_ipc_sockets(void) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ifchSock) < 0)
        suicide("FATAL - can't create ndhc/ifch socket: %s", strerror(errno));
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, ifchStream) < 0)
        suicide("FATAL - can't create ndhc/ifch socket: %s", strerror(errno));
}

static void create_sockd_ipc_sockets(void) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockdSock) < 0)
        suicide("FATAL - can't create ndhc/sockd socket: %s", strerror(errno));
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockdStream) < 0)
        suicide("FATAL - can't create ndhc/ifch socket: %s", strerror(errno));
}

static void spawn_ifch(void)
{
    create_ifch_ipc_sockets();
    pid_t ifch_pid = fork();
    if (ifch_pid == 0) {
        close(ifchSock[0]);
        close(ifchStream[0]);
        // Don't share the RNG state with the master process.
        nk_random_u32_init(&cs.rnd32_state);
        ifch_main();
    } else if (ifch_pid > 0) {
        close(ifchSock[1]);
        close(ifchStream[1]);
    } else
        suicide("failed to fork ndhc-ifch: %s", strerror(errno));
}

static void spawn_sockd(void)
{
    create_sockd_ipc_sockets();
    pid_t sockd_pid = fork();
    if (sockd_pid == 0) {
        close(sockdSock[0]);
        close(sockdStream[0]);
        // Don't share the RNG state with the master process.
        nk_random_u32_init(&cs.rnd32_state);
        sockd_main();
    } else if (sockd_pid > 0) {
        close(sockdSock[1]);
        close(sockdStream[1]);
    } else
        suicide("failed to fork ndhc-sockd: %s", strerror(errno));
}

static void ndhc_main(void) {
    prctl(PR_SET_NAME, "ndhc: master");
    log_line("ndhc client " NDHC_VERSION " started on interface [%s].",
             client_config.interface);

    if ((cs.nlFd = nl_open(NETLINK_ROUTE, RTMGRP_LINK, &cs.nlPortId)) < 0)
        suicide("%s: failed to open netlink socket", __func__);

    cs.rfkillFd = rfkill_open(&client_config.enable_rfkill);

    if (client_config.foreground && !client_config.background_if_no_lease) {
        if (file_exists(pidfile, "w") < 0)
            suicide("%s: can't open pidfile '%s' for write!",
                    __func__, pidfile);
        write_pid(pidfile);
    }

    open_leasefile();

    nk_set_chroot(chroot_dir);
    memset(chroot_dir, '\0', sizeof chroot_dir);
    nk_set_uidgid(ndhc_uid, ndhc_gid, NULL, 0);

    if (cs.ifsPrevState != IFS_UP) {
        if (ifchange_deconfig(&cs) < 0)
            suicide("%s: can't deconfigure interface settings", __func__);
    }

    do_ndhc_work();
}

void background(void)
{
    static char called;
    if (!called) {
        called = 1;  // Do not fork again.
        if (daemon(0, 0) < 0) {
            perror("fork");
            exit(EXIT_SUCCESS);
        }
    }
    if (file_exists(pidfile, "w") < 0) {
        log_warning("Cannot open pidfile for write!");
    } else
        write_pid(pidfile);
}

static void wait_for_rfkill()
{
    struct epoll_event events[2];
    cs.rfkillFd = rfkill_open(&client_config.enable_rfkill);
    if (cs.rfkillFd < 0)
        suicide("can't wait for rfkill to end if /dev/rfkill can't be opened");
    int epfd = epoll_create1(0);
    if (epfd < 0)
        suicide("epoll_create1 failed");
    epoll_add(epfd, cs.rfkillFd);
    for (;;) {
        int r = epoll_wait(epfd, events, 2, -1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        for (int i = 0; i < r; ++i) {
            int fd = events[i].data.fd;
            if (fd != cs.rfkillFd)
                suicide("epoll_wait: unknown fd");
            if (events[i].events & EPOLLIN) {
                int rfk = rfkill_get(&cs, 0, 0);
                if (rfk == RFK_DISABLED) {
                    switch (perform_ifup()) {
                    case 1: case 0: goto rfkill_gone;
                    case -3:
                        log_line("rfkill: radio immediately blocked again; spurious?");
                        break;
                    default: suicide("failed to set the interface to up state");
                    }
                }
            }
        }
    }
rfkill_gone:
    close(epfd);
    // We always close because ifchd and sockd shouldn't keep
    // an rfkill fd open.
    close(cs.rfkillFd);
    cs.rfkillFd = -1;
}

int main(int argc, char *argv[])
{
    parse_cmdline(argc, argv);

    nk_random_u32_init(&cs.rnd32_state);

    if (getuid())
        suicide("I need to be started as root.");
    if (!strncmp(chroot_dir, "", sizeof chroot_dir))
        suicide("No chroot path is specified.  Refusing to run.");
    fail_if_state_dir_dne();

    if (nl_getifdata() < 0)
        suicide("failed to get interface MAC or index");

    get_clientid(&cs, &client_config);

    switch (perform_ifup()) {
    case 1: cs.ifsPrevState = IFS_UP;
    case 0: break;
    case -3: wait_for_rfkill(); break;
    default: suicide("failed to set the interface to up state");
    }

    if (setpgid(0, 0) < 0) {
        // EPERM is returned if we are already a process group leader.
        if (errno != EPERM)
            suicide("setpgid failed: %s", strerror(errno));
    }

    spawn_ifch();
    spawn_sockd();
    ndhc_main();
    exit(EXIT_SUCCESS);
}

