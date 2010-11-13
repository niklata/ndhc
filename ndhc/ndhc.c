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
#include <net/if.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "ndhc-defines.h"
#include "dhcpd.h"
#include "dhcpc.h"
#include "options.h"
#include "clientpacket.h"
#include "packet.h"
#include "script.h"
#include "socket.h"
#include "log.h"
#include "chroot.h"
#include "cap.h"
#include "strl.h"
#include "pidfile.h"
#include "malloc.h"

#define VERSION "1.0"
#define NUMPACKETS 3 /* number of packets to send before delay */
#define RETRY_DELAY 30 /* time in seconds to delay after sending NUMPACKETS */

static char pidfile[MAX_PATH_LENGTH] = PID_FILE_DEFAULT;

static uint32_t requested_ip, server_addr, timeout;
static uint32_t lease, t1, t2, xid, start;
static int state, packet_num, fd, listen_mode;
static sig_atomic_t pending_exit, pending_renew, pending_release;

enum {
    LISTEN_NONE,
    LISTEN_KERNEL,
    LISTEN_RAW
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
static void change_listen_mode(int new_mode)
{
    log_line("entering %s listen mode",
             new_mode ? (new_mode == 1 ? "kernel" : "raw") : "none");
    listen_mode = new_mode;
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
    if (new_mode == LISTEN_KERNEL)
        fd = listen_socket(INADDR_ANY, CLIENT_PORT, client_config.interface);
    else if (new_mode == LISTEN_RAW)
        fd = raw_socket(client_config.ifindex);
}

/* perform a renew */
static void perform_renew(void)
{
    log_line("Performing a DHCP renew...");
    switch (state) {
        case BOUND:
            change_listen_mode(LISTEN_KERNEL);
        case RENEWING:
        case REBINDING:
            state = RENEW_REQUESTED;
            break;
        case RENEW_REQUESTED: /* impatient are we? fine, square 1 */
            run_script(NULL, SCRIPT_DECONFIG);
        case REQUESTING:
        case RELEASED:
            change_listen_mode(LISTEN_RAW);
            state = INIT_SELECTING;
            break;
        case INIT_SELECTING:
            break;
    }

    /* start things over */
    packet_num = 0;

    /* Kill any timeouts because the user wants this to hurry along */
    timeout = 0;
}


/* perform a release */
static void perform_release(void)
{
    char buf[32];
    struct in_addr temp_addr;

    memset(buf, '\0', sizeof buf);

    /* send release packet */
    if (state == BOUND || state == RENEWING || state == REBINDING) {
        temp_addr.s_addr = server_addr;
        snprintf(buf, sizeof buf, "%s", inet_ntoa(temp_addr));
        temp_addr.s_addr = requested_ip;
        log_line("Unicasting a release of %s to %s.",
                 inet_ntoa(temp_addr), buf);
        send_release(server_addr, requested_ip); /* unicast */
        run_script(NULL, SCRIPT_DECONFIG);
    }
    log_line("Entering released state.");

    change_listen_mode(LISTEN_NONE);
    state = RELEASED;
    timeout = 0x7fffffff;
}

static void signal_handler(int sig)
{
    switch (sig) {
        case SIGUSR1:
            pending_renew = 1;
            break;
        case SIGUSR2:
            pending_release = 1;
            break;
        case SIGTERM:
            pending_exit = 1;
            break;
    }
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

static void handle_timeout(void)
{
    time_t now = time(0);

    /* timeout dropped to zero */
    switch (state) {
        case INIT_SELECTING:
            if (packet_num < NUMPACKETS) {
                if (packet_num == 0)
                    xid = random_xid();

                /* send discover packet */
                send_discover(xid, requested_ip); /* broadcast */

                timeout = now + ((packet_num == NUMPACKETS - 1) ? 4 : 2);
                packet_num++;
            } else {
                if (client_config.background_if_no_lease) {
                    log_line("No lease, going to background.");
                    background();
                } else if (client_config.abort_if_no_lease) {
                    log_line("No lease, failing.");
                    exit(EXIT_FAILURE);
                }
                /* wait to try again */
                packet_num = 0;
                timeout = now + RETRY_DELAY;
            }
            break;
        case RENEW_REQUESTED:
        case REQUESTING:
            if (packet_num < NUMPACKETS) {
                /* send request packet */
                if (state == RENEW_REQUESTED)
                    /* unicast */
                    send_renew(xid, server_addr, requested_ip);
                else
                    /* broadcast */
                    send_selecting(xid, server_addr, requested_ip);
                timeout = now + ((packet_num == NUMPACKETS - 1) ? 10 : 2);
                packet_num++;
            } else {
                /* timed out, go back to init state */
                if (state == RENEW_REQUESTED)
                    run_script(NULL, SCRIPT_DECONFIG);
                state = INIT_SELECTING;
                timeout = now;
                packet_num = 0;
                change_listen_mode(LISTEN_RAW);
            }
            break;
        case BOUND:
            /* Lease is starting to run out, time to enter renewing state */
            state = RENEWING;
            change_listen_mode(LISTEN_KERNEL);
            log_line("Entering renew state.");
            /* fall right through */
        case RENEWING:
            /* Either set a new T1, or enter REBINDING state */
            if ((t2 - t1) <= (lease / 14400 + 1)) {
                /* timed out, enter rebinding state */
                state = REBINDING;
                timeout = now + (t2 - t1);
                log_line("Entering rebinding state.");
            } else {
                /* send a request packet */
                send_renew(xid, server_addr, requested_ip); /* unicast */

                t1 = ((t2 - t1) >> 1) + t1;
                timeout = t1 + start;
            }
            break;
        case REBINDING:
            /* Either set a new T2, or enter INIT state */
            if ((lease - t2) <= (lease / 14400 + 1)) {
                /* timed out, enter init state */
                state = INIT_SELECTING;
                log_line("Lease lost, entering init state.");
                run_script(NULL, SCRIPT_DECONFIG);
                timeout = now;
                packet_num = 0;
                change_listen_mode(LISTEN_RAW);
            } else {
                /* send a request packet */
                send_renew(xid, 0, requested_ip); /* broadcast */

                t2 = ((lease - t2) >> 1) + t2;
                timeout = t2 + start;
            }
            break;
        case RELEASED:
            /* yah, I know, *you* say it would never happen */
            timeout = 0x7fffffff;
            break;
    }
}

static void handle_packet(void)
{
    unsigned char *temp = NULL, *message = NULL;
    int len;
    struct in_addr temp_addr;
    struct dhcpMessage packet;

    if (listen_mode == LISTEN_KERNEL)
        len = get_packet(&packet, fd);
    else if (listen_mode == LISTEN_RAW)
        len = get_raw_packet(&packet, fd);
    else /* LISTEN_NONE */
        return;

    if (len == -1 && errno != EINTR) {
        log_error("reopening socket.");
        change_listen_mode(listen_mode); /* just close and reopen */
    }

    if (len < 0)
        return;

    if (packet.xid != xid) {
        log_line("Ignoring XID %lx (our xid is %lx).",
                 (uint32_t) packet.xid, xid);
        return;
    }

    if ((message = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
        log_line("couldnt get option from packet -- ignoring");
        return;
    }

    time_t now = time(0);
    switch (state) {
        case INIT_SELECTING:
            /* Must be a DHCPOFFER to one of our xid's */
            if (*message == DHCPOFFER) {
                if ((temp = get_option(&packet, DHCP_SERVER_ID))) {
                    memcpy(&server_addr, temp, 4);
                    xid = packet.xid;
                    requested_ip = packet.yiaddr;

                    /* enter requesting state */
                    state = REQUESTING;
                    timeout = now;
                    packet_num = 0;
                } else {
                    log_line("No server ID in message");
                }
            }
            break;
        case RENEW_REQUESTED:
        case REQUESTING:
        case RENEWING:
        case REBINDING:
            if (*message == DHCPACK) {
                if (!(temp = get_option(&packet, DHCP_LEASE_TIME))) {
                    log_line("No lease time received, assuming 1h.");
                    lease = 60 * 60;
                } else {
                    memcpy(&lease, temp, 4);
                    lease = ntohl(lease);
                }

                /* enter bound state */
                t1 = lease >> 1;

                /* little fixed point for n * .875 */
                t2 = (lease * 0x7) >> 3;
                temp_addr.s_addr = packet.yiaddr;
                log_line("Lease of %s obtained, lease time %ld.",
                         inet_ntoa(temp_addr), lease);
                start = now;
                timeout = t1 + start;
                requested_ip = packet.yiaddr;
                run_script(&packet,
                           ((state == RENEWING || state == REBINDING)
                            ? SCRIPT_RENEW : SCRIPT_BOUND));

                state = BOUND;
                change_listen_mode(LISTEN_NONE);
                if (client_config.quit_after_lease)
                    exit(EXIT_SUCCESS);
                if (!client_config.foreground)
                    background();

            } else if (*message == DHCPNAK) {
                /* return to init state */
                log_line("Received DHCP NAK.");
                run_script(&packet, SCRIPT_NAK);
                if (state != REQUESTING)
                    run_script(NULL, SCRIPT_DECONFIG);
                state = INIT_SELECTING;
                timeout = now;
                requested_ip = 0;
                packet_num = 0;
                change_listen_mode(LISTEN_RAW);
                sleep(3); /* avoid excessive network traffic */
            }
            break;
        case BOUND:
        case RELEASED:
        default:
            break;
    }
}

static int do_work(void)
{
    struct timeval tv;
    fd_set rfds;
    for (;;) {

        /* Handle signals asynchronously. */
        if (pending_renew)
            perform_renew();
        if (pending_release)
            perform_release();
        if (pending_exit) {
            log_line("Received SIGTERM.  Exiting gracefully.");
            exit(EXIT_SUCCESS);
        }

        tv.tv_sec = timeout - time(0);
        tv.tv_usec = 0;

        if (tv.tv_sec <= 0) {
            handle_timeout();
            continue;
        }

        FD_ZERO(&rfds);
        if (fd >= 0)
            FD_SET(fd, &rfds);
        if (select(fd + 1, &rfds, NULL, NULL, &tv) == -1) {
            switch (errno) {
                case EBADF:
                    fd = -1;
                default:
                    log_error("Error: \"%s\" on select!",
                              strerror(errno));
                case EINTR:  /* Signal received, go back to top. */
                    continue;
            }
        }

        if (FD_ISSET(fd, &rfds))
            handle_packet();
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
                break;
            case 'b':
                client_config.background_if_no_lease = 1;
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
                requested_ip = inet_addr(optarg);
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

    /* setup signal handlers */
    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);
    signal(SIGTERM, signal_handler);

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

    state = INIT_SELECTING;
    run_script(NULL, SCRIPT_DECONFIG);
    change_listen_mode(LISTEN_RAW);

    do_work();

    return EXIT_SUCCESS;
}
