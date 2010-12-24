/* ndhc.c
 *
 * ndhc DHCP client, originally based on udhcpc
 *
 * Nicholas J. Kain <njkain at gmail dot com> 2004-2010
 * Russ Dill <Russ.Dill@asu.edu> July 2001
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
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <net/if.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "ndhc-defines.h"
#include "dhcpd.h"
#include "config.h"
#include "options.h"
#include "clientpacket.h"
#include "packet.h"
#include "script.h"
#include "socket.h"
#include "arpping.h"
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
    .listenMode = LM_NONE,
    .packetNum = 0,
    .xid = 0,
    .timeout = 0,
    .leaseStartTime = 0,
    .requestedIP = 0,
    .serverAddr = 0,
    .lease = 0,
    .t1 = 0,
    .t2 = 0,
    .epollFd = -1,
    .signalFd = -1,
    .listenFd = -1,
    .arpFd = -1,
};

struct client_config_t client_config = {
    /* Default options. */
    .abort_if_no_lease = 0,
    .foreground = 0,
    .quit_after_lease = 0,
    .background_if_no_lease = 0,
    .interface = "eth0",
    .script = "none",
    .clientid = NULL,
    .hostname = NULL,
    .ifindex = 0,
    .arp = "\0",
};

static char pidfile[MAX_PATH_LENGTH] = PID_FILE_DEFAULT;

static unsigned long long curms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

static void epoll_add(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(cs.epollFd, EPOLL_CTL_ADD, fd, &ev);
    if (r == -1)
        suicide("epoll_add failed %s", strerror(errno));
}

static void epoll_del(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(cs.epollFd, EPOLL_CTL_DEL, fd, &ev);
    if (r == -1)
        suicide("epoll_del failed %s", strerror(errno));
}

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

/* Switch listen socket between raw (if-bound), kernel (ip-bound), and none */
void change_listen_mode(int new_mode)
{
    log_line("entering %s listen mode",
             new_mode ? (new_mode == 1 ? "kernel" : "raw") : "none");
    cs.listenMode = new_mode;
    if (cs.listenFd >= 0) {
        epoll_del(cs.listenFd);
        close(cs.listenFd);
        cs.listenFd = -1;
    }
    if (new_mode == LM_KERNEL) {
        cs.listenFd = listen_socket(INADDR_ANY, CLIENT_PORT,
                                 client_config.interface);
        epoll_add(cs.listenFd);
    }
    else if (new_mode == LM_RAW) {
        cs.listenFd = raw_socket(client_config.ifindex);
        epoll_add(cs.listenFd);
    }
    else /* LM_NONE */
        return;
    if (cs.listenFd < 0) {
        log_error("FATAL: couldn't listen on socket: %s.", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/* perform a renew */
static void perform_renew(void)
{
    log_line("Performing a DHCP renew...");
  retry:
    switch (cs.dhcpState) {
        case DS_BOUND:
            change_listen_mode(LM_KERNEL);
        case DS_ARP_CHECK:
            // Cancel arp ping in progress and treat as previous state.
            epoll_del(cs.arpFd);
            cs.arpFd = -1;
            cs.dhcpState = cs.arpPrevState;
            goto retry;
        case DS_RENEWING:
        case DS_REBINDING:
            cs.dhcpState = DS_RENEW_REQUESTED;
            break;
        case DS_RENEW_REQUESTED: /* impatient are we? fine, square 1 */
            run_script(NULL, SCRIPT_DECONFIG);
        case DS_REQUESTING:
        case DS_RELEASED:
            change_listen_mode(LM_RAW);
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
        run_script(NULL, SCRIPT_DECONFIG);
    }
    log_line("Entering released state.");

    if (cs.dhcpState == DS_ARP_CHECK) {
        epoll_del(cs.arpFd);
        cs.arpFd = -1;
    }
    change_listen_mode(LM_NONE);
    cs.dhcpState = DS_RELEASED;
    cs.timeout = -1;
}

static void background(void)
{
    static char called;
    if (!called && daemon(0, 0) == -1) {
        perror("fork");
        exit(EXIT_SUCCESS);
    }
    called = 1;  /* Do not fork again. */
    if (file_exists(pidfile, "w") == -1) {
        log_line("FATAL - cannot open pidfile for write!");
        exit(EXIT_FAILURE);
    }
    write_pid(pidfile);
}

static struct arpMsg arpreply;
static int arpreply_offset;
static struct dhcpMessage arp_dhcp_packet;

void arp_check(struct dhcpMessage *packet)
{
    cs.arpPrevState = cs.dhcpState;
    cs.dhcpState = DS_ARP_CHECK;
    memcpy(&arp_dhcp_packet, packet, sizeof (struct dhcpMessage));
    cs.arpFd = arpping(arp_dhcp_packet.yiaddr, NULL, 0,
                        client_config.arp, client_config.interface);
    epoll_add(cs.arpFd);
    cs.timeout = 2000;
    memset(&arpreply, 0, sizeof arpreply);
    arpreply_offset = 0;
}

static void arp_failed(void)
{
    log_line("Offered address is in use: declining.");
    epoll_del(cs.arpFd);
    cs.arpFd = -1;
    send_decline(cs.xid, cs.serverAddr, arp_dhcp_packet.yiaddr);

    if (cs.arpPrevState != DS_REQUESTING)
        run_script(NULL, SCRIPT_DECONFIG);
    cs.dhcpState = DS_INIT_SELECTING;
    cs.requestedIP = 0;
    cs.timeout = 0;
    cs.packetNum = 0;
    change_listen_mode(LM_RAW);
}

static void arp_success(void)
{
    struct in_addr temp_addr;

    epoll_del(cs.arpFd);
    cs.arpFd = -1;

    /* enter bound state */
    cs.t1 = cs.lease >> 1;
    /* little fixed point for n * .875 */
    cs.t2 = (cs.lease * 0x7) >> 3;
    cs.timeout = cs.t1 * 1000;
    cs.leaseStartTime = curms();

    temp_addr.s_addr = arp_dhcp_packet.yiaddr;
    log_line("Lease of %s obtained, lease time %ld.",
             inet_ntoa(temp_addr), cs.lease);
    cs.requestedIP = arp_dhcp_packet.yiaddr;
    run_script(&arp_dhcp_packet,
               ((cs.arpPrevState == DS_RENEWING ||
                 cs.arpPrevState == DS_REBINDING)
                ? SCRIPT_RENEW : SCRIPT_BOUND));

    cs.dhcpState = DS_BOUND;
    change_listen_mode(LM_NONE);
    if (client_config.quit_after_lease)
        exit(EXIT_SUCCESS);
    if (!client_config.foreground)
        background();
}

static void init_selecting_timeout()
{
    if (cs.packetNum < NUMPACKETS) {
        if (cs.packetNum == 0)
            cs.xid = random_xid();
        /* broadcast */
        send_discover(cs.xid, cs.requestedIP);

        cs.timeout = ((cs.packetNum == NUMPACKETS - 1) ? 4 : 2) * 1000;
        cs.packetNum++;
    } else {
        if (client_config.background_if_no_lease) {
            log_line("No lease, going to background.");
            background();
        } else if (client_config.abort_if_no_lease) {
            log_line("No lease, failing.");
            exit(EXIT_FAILURE);
        }
        /* wait to try again */
        cs.packetNum = 0;
        cs.timeout = RETRY_DELAY * 1000;
    }
}

static void renew_requested_timeout()
{
    if (cs.packetNum < NUMPACKETS) {
        /* send unicast request packet */
        send_renew(cs.xid, cs.serverAddr, cs.requestedIP);
        cs.timeout = ((cs.packetNum == NUMPACKETS - 1) ? 10 : 2) * 1000;
        cs.packetNum++;
    } else {
        /* timed out, go back to init state */
        run_script(NULL, SCRIPT_DECONFIG);
        cs.dhcpState = DS_INIT_SELECTING;
        cs.timeout = 0;
        cs.packetNum = 0;
        change_listen_mode(LM_RAW);
    }
}

static void requesting_timeout()
{
    if (cs.packetNum < NUMPACKETS) {
        /* send broadcast request packet */
        send_selecting(cs.xid, cs.serverAddr, cs.requestedIP);
        cs.timeout = ((cs.packetNum == NUMPACKETS - 1) ? 10 : 2) * 1000;
        cs.packetNum++;
    } else {
        /* timed out, go back to init state */
        cs.dhcpState = DS_INIT_SELECTING;
        cs.timeout = 0;
        cs.packetNum = 0;
        change_listen_mode(LM_RAW);
    }
}

static void renewing_timeout()
{
    /* Either set a new T1, or enter DS_REBINDING state */
    if ((cs.t2 - cs.t1) <= (cs.lease / 14400 + 1)) {
        /* timed out, enter rebinding state */
        cs.dhcpState = DS_REBINDING;
        cs.timeout = (cs.t2 - cs.t1) * 1000;
        log_line("Entering rebinding state.");
    } else {
        /* send a request packet */
        send_renew(cs.xid, cs.serverAddr, cs.requestedIP); /* unicast */

        cs.t1 = ((cs.t2 - cs.t1) >> 1) + cs.t1;
        cs.timeout = (cs.t1 * 1000) - (curms() - cs.leaseStartTime);
    }
}

static void bound_timeout()
{
    /* Lease is starting to run out, time to enter renewing state */
    cs.dhcpState = DS_RENEWING;
    change_listen_mode(LM_KERNEL);
    log_line("Entering renew state.");
    renewing_timeout();
}

static void rebinding_timeout()
{
    /* Either set a new T2, or enter INIT state */
    if ((cs.lease - cs.t2) <= (cs.lease / 14400 + 1)) {
        /* timed out, enter init state */
        cs.dhcpState = DS_INIT_SELECTING;
        log_line("Lease lost, entering init state.");
        run_script(NULL, SCRIPT_DECONFIG);
        cs.timeout = 0;
        cs.packetNum = 0;
        change_listen_mode(LM_RAW);
    } else {
        /* send a request packet */
        send_renew(cs.xid, 0, cs.requestedIP); /* broadcast */

        cs.t2 = ((cs.lease - cs.t2) >> 1) + cs.t2;
        cs.timeout = (cs.t2 * 1000) - (curms() - cs.leaseStartTime);
    }
}

/* Handle epoll timeout expiring */
static void handle_timeout(void)
{
    switch (cs.dhcpState) {
        case DS_INIT_SELECTING: init_selecting_timeout(); break;
        case DS_RENEW_REQUESTED: renew_requested_timeout(); break;
        case DS_REQUESTING: requesting_timeout(); break;
        case DS_RENEWING: renewing_timeout(); break;
        case DS_BOUND: bound_timeout(); break;
        case DS_REBINDING: rebinding_timeout(); break;
        case DS_RELEASED: cs.timeout = -1; break;
        case DS_ARP_CHECK: arp_success(); break;
        default: break;
    }
}

typedef uint32_t aliased_uint32_t __attribute__((__may_alias__));
static void handle_arp_response(void)
{
    if (arpreply_offset < sizeof arpreply) {
        int r = safe_read(cs.arpFd, (char *)&arpreply + arpreply_offset,
                          sizeof arpreply - arpreply_offset);
        if (r < 0) {
            arp_failed();
            return;
        } else
            arpreply_offset += r;
    }

    //log3("sHaddr %02x:%02x:%02x:%02x:%02x:%02x",
    //arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2],
    //arp.sHaddr[3], arp.sHaddr[4], arp.sHaddr[5]);

    if (arpreply_offset >= ARP_MSG_SIZE) {
        if (arpreply.operation == htons(ARPOP_REPLY)
            /* don't check: Linux returns invalid tHaddr (fixed in 2.6.24?) */
            /* && memcmp(arpreply.tHaddr, from_mac, 6) == 0 */
            && *(aliased_uint32_t*)arpreply.sInaddr == arp_dhcp_packet.yiaddr)
        {
            /* if ARP source MAC matches safe_mac
             * (which is client's MAC), then it's not a conflict
             * (client simply already has this IP and replies to ARPs!)
             */
            /* if (memcmp(safe_mac, arpreply.sHaddr, 6) == 0) */
            /*     arp_success(); */
            arp_failed();
        } else {
            memset(&arpreply, 0, sizeof arpreply);
            arpreply_offset = 0;
        }
    }
}

static void setup_signals()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");
    cs.signalFd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (cs.signalFd < 0)
        suicide("signalfd failed");
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
    epoll_add(cs.signalFd);
    change_listen_mode(LM_RAW);
    handle_timeout();

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
                handle_arp_response();
            else
                suicide("epoll_wait: unknown fd");
        }

        timeout_delta = curms() - last_awake;
        cs.timeout -= timeout_delta;
        if (cs.timeout <= 0) {
            cs.timeout = 0;
            handle_timeout();
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
                len = strlen(optarg) > 255 ? 255 : strlen(optarg);
                if (client_config.clientid)
                    free(client_config.clientid);
                client_config.clientid = xmalloc(len + 1);
                client_config.clientid[OPT_CODE] = DHCP_CLIENT_ID;
                client_config.clientid[OPT_LEN] = len;
                strlcpy((char *)client_config.clientid + OPT_DATA, optarg,
                        len + 1 - (OPT_DATA - OPT_CODE));
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
                len = strlen(optarg) > 255 ? 255 : strlen(optarg);
                if (client_config.hostname)
                    free(client_config.hostname);
                client_config.hostname = xmalloc(len + 1);
                client_config.hostname[OPT_CODE] = DHCP_HOST_NAME;
                client_config.hostname[OPT_LEN] = len;
                strlcpy((char*)client_config.hostname + OPT_DATA, optarg,
                        len + 1 - (OPT_DATA - OPT_CODE));
                break;
            case 'i':
                client_config.interface =  optarg;
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

    if (read_interface(client_config.interface, &client_config.ifindex,
                       NULL, client_config.arp) < 0)
        exit(EXIT_FAILURE);

    if (!client_config.clientid) {
        client_config.clientid = xmalloc(6 + 3);
        client_config.clientid[OPT_CODE] = DHCP_CLIENT_ID;
        client_config.clientid[OPT_LEN] = 7;
        client_config.clientid[OPT_DATA] = 1;
        memcpy(client_config.clientid + 3, client_config.arp, 6);
    }

    setup_signals();

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

    run_script(NULL, SCRIPT_DECONFIG);

    do_work();

    return EXIT_SUCCESS;
}
