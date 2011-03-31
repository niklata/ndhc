/* ndhc.c - DHCP client
 * Time-stamp: <2011-03-30 23:58:05 nk>
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <net/if.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "ndhc-defines.h"
#include "config.h"
#include "options.h"
#include "dhcpmsg.h"
#include "packet.h"
#include "timeout.h"
#include "sys.h"
#include "ifchange.h"
#include "socket.h"
#include "arp.h"
#include "netlink.h"

#include "log.h"
#include "chroot.h"
#include "cap.h"
#include "strl.h"
#include "pidfile.h"
#include "malloc.h"
#include "io.h"

#define VERSION "1.0"

struct client_state_t cs = {
    .dhcpState = DS_INIT_SELECTING,
    .arpPrevState = DS_NULL,
    .ifsPrevState = IFS_NONE,
    .listenMode = LM_NONE,
    .packetNum = 0,
    .xid = 0,
    .timeout = 0,
    .oldTimeout = 0,
    .leaseStartTime = 0,
    .requestedIP = 0,
    .serverAddr = 0,
    .routerAddr = 0,
    .lease = 0,
    .t1 = 0,
    .t2 = 0,
    .epollFd = -1,
    .signalFd = -1,
    .listenFd = -1,
    .arpFd = -1,
    .nlFd = -1,
    .routerArp = "\0\0\0\0\0\0",
};

struct client_config_t client_config = {
    /* Default options. */
    .abort_if_no_lease = 0,
    .foreground = 0,
    .quit_after_lease = 0,
    .background_if_no_lease = 0,
    .interface = "eth0",
    .clientid = NULL,
    .hostname = NULL,
    .ifindex = 0,
    .arp = "\0\0\0\0\0\0",
};

static void show_usage(void)
{
    printf(
"Usage: ndhc [OPTIONS]\n\n"
"  -c, --clientid=CLIENTID         Client identifier\n"
"  -H, --hostname=HOSTNAME         Client hostname\n"
"  -h                              Alias for -H\n"
"  -f, --foreground                Do not fork after getting lease\n"
"  -b, --background                Fork to background if lease cannot be\n"
"                                  immediately negotiated.\n"
"  -p, --pidfile                   File to which the pid will be written\n"
"  -i, --interface=INTERFACE       Interface to use (default: eth0)\n"
"  -n, --now                       Exit with failure if lease cannot be\n"
"                                  immediately negotiated.\n"
"  -q, --quit                      Quit after obtaining lease\n"
"  -r, --request=IP                IP address to request (default: none)\n"
"  -u, --user                      Change privileges to this user\n"
"  -C, --chroot                    Directory to which udhcp should chroot\n"
"  -v, --version                   Display version\n"
           );
    exit(EXIT_SUCCESS);
}

/* perform a renew */
static void perform_renew(void)
{
    log_line("Performing a DHCP renew...");
  retry:
    switch (cs.dhcpState) {
        case DS_BOUND:
            change_listen_mode(&cs, LM_KERNEL);
        case DS_ARP_CHECK:
            // Cancel arp ping in progress and treat as previous state.
            epoll_del(&cs, cs.arpFd);
            close(cs.arpFd);
            cs.arpFd = -1;
            cs.dhcpState = cs.arpPrevState;
            goto retry;
        case DS_RENEWING:
        case DS_REBINDING:
            cs.dhcpState = DS_RENEW_REQUESTED;
            break;
        case DS_RENEW_REQUESTED: /* impatient are we? fine, square 1 */
            ifchange(NULL, IFCHANGE_DECONFIG);
        case DS_REQUESTING:
        case DS_RELEASED:
            change_listen_mode(&cs, LM_RAW);
            cs.dhcpState = DS_INIT_SELECTING;
            break;
        case DS_INIT_SELECTING:
        default:
            break;
    }

    /* start things over */
    cs.packetNum = 0;

    /* Kill any timeouts because the user wants this to hurry along */
    cs.timeout = 0;
}


/* perform a release */
static void perform_release(void)
{
    struct in_addr temp_saddr, temp_raddr;

    /* send release packet */
    if (cs.dhcpState == DS_BOUND || cs.dhcpState == DS_RENEWING ||
        cs.dhcpState == DS_REBINDING || cs.dhcpState == DS_ARP_CHECK) {
        temp_saddr.s_addr = cs.serverAddr;
        temp_raddr.s_addr = cs.requestedIP;
        log_line("Unicasting a release of %s to %s.",
                 inet_ntoa(temp_raddr), inet_ntoa(temp_saddr));
        send_release(cs.serverAddr, cs.requestedIP); /* unicast */
        ifchange(NULL, IFCHANGE_DECONFIG);
    }
    log_line("Entering released state.");

    if (cs.dhcpState == DS_ARP_CHECK) {
        epoll_del(&cs, cs.arpFd);
        close(cs.arpFd);
        cs.arpFd = -1;
    }
    change_listen_mode(&cs, LM_NONE);
    cs.dhcpState = DS_RELEASED;
    cs.timeout = -1;
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
            perform_renew();
            break;
        case SIGUSR2:
            perform_release();
            break;
        case SIGTERM:
            log_line("Received SIGTERM.  Exiting gracefully.");
            exit(EXIT_SUCCESS);
        default:
            break;
    }
}

static void do_work(void)
{
    struct epoll_event events[3];
    long long last_awake;
    int timeout_delta;

    cs.epollFd = epoll_create1(0);
    if (cs.epollFd == -1)
        suicide("epoll_create1 failed");
    setup_signals(&cs);
    epoll_add(&cs, cs.nlFd);
    change_listen_mode(&cs, LM_RAW);
    handle_timeout(&cs);

    for (;;) {
        last_awake = curms();
        int r = epoll_wait(cs.epollFd, events, 3, cs.timeout);
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

        timeout_delta = curms() - last_awake;
        cs.timeout -= timeout_delta;
        if (cs.timeout <= 0) {
            cs.timeout = 0;
            handle_timeout(&cs);
        }
    }
}

int main(int argc, char **argv)
{
    char chroot_dir[MAX_PATH_LENGTH] = "";
    int c, len;
    struct passwd *pwd;
    uid_t uid = 0;
    gid_t gid = 0;
    static struct option arg_options[] = {
        {"clientid",    required_argument,  0, 'c'},
        {"foreground",  no_argument,        0, 'f'},
        {"background",  no_argument,        0, 'b'},
        {"pidfile",     required_argument,  0, 'p'},
        {"hostname",    required_argument,  0, 'H'},
        {"hostname",    required_argument,      0, 'h'},
        {"interface",   required_argument,  0, 'i'},
        {"now",         no_argument,        0, 'n'},
        {"quit",    no_argument,        0, 'q'},
        {"request", required_argument,  0, 'r'},
        {"version", no_argument,        0, 'v'},
        {"user",        required_argument,      0, 'u'},
        {"chroot",      required_argument,      0, 'C'},
        {"help",    no_argument,        0, '?'},
        {0, 0, 0, 0}
    };

    /* get options */
    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "c:fbp:H:h:i:np:qr:u:C:v", arg_options,
                        &option_index);
        if (c == -1) break;

        switch (c) {
            case 'c':
                len = strlen(optarg) > 64 ? 64 : strlen(optarg);
                if (client_config.clientid)
                    free(client_config.clientid);
                client_config.clientid =
                    alloc_dhcp_client_id_option(0, (uint8_t *)optarg, len);
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
            case 'h':
            case 'H':
                len = strlen(optarg) > 64 ? 64 : strlen(optarg);
                if (client_config.hostname)
                    free(client_config.hostname);
                client_config.hostname =
                    alloc_option(DHCP_HOST_NAME, (uint8_t *)optarg, len);
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
                cs.requestedIP = inet_addr(optarg);
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
            case 'v':
                printf("ndhc, version " VERSION "\n\n");
                exit(EXIT_SUCCESS);
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

    if (nl_open(&cs) < 0) {
        log_line("FATAL - failed to open netlink socket");
        exit(EXIT_FAILURE);
    }
    if (nl_getifdata(client_config.interface, &cs) < 0) {
        log_line("FATAL - failed to get interface MAC and index");
        exit(EXIT_FAILURE);
    }

    if (!client_config.clientid) {
        client_config.clientid =
            alloc_dhcp_client_id_option(1, client_config.arp, 6);
    }

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

    ifchange(NULL, IFCHANGE_DECONFIG);

    do_work();

    nl_close(&cs);
    return EXIT_SUCCESS;
}
