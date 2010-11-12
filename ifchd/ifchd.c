/* ifchd.c - interface change daemon
 * Time-stamp: <2010-11-12 14:27:47 njk>
 *
 * (C) 2004-2010 Nicholas J. Kain <njkain at gmail dot com>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <pwd.h>
#include <grp.h>

#include <signal.h>
#include <errno.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "defines.h"
#include "malloc.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "signals.h"
#include "strlist.h"
#include "ifproto.h"
#include "strl.h"
#include "cap.h"
#include "linux.h"

enum states {
    STATE_NOTHING,
    STATE_INTERFACE,
    STATE_IP,
    STATE_SUBNET,
    STATE_TIMEZONE,
    STATE_ROUTER,
    STATE_TIMESVR,
    STATE_DNS,
    STATE_LPRSVR,
    STATE_HOSTNAME,
    STATE_DOMAIN,
    STATE_IPTTL,
    STATE_MTU,
    STATE_BROADCAST,
    STATE_NTPSRV,
    STATE_WINS
};

static volatile sig_atomic_t pending_exit;

/* Socket fd, current state, and idle time for connections. */
static int sks[SOCK_QUEUE], state[SOCK_QUEUE], idle_time[SOCK_QUEUE];

/* Per-connection buffers. */
static char ibuf[SOCK_QUEUE][MAX_BUF];

/*
 * Per-connection pointers into the command lists.  Respectively, the
 * topmost item on the list, the current item, and the last item on the list.
 */
static strlist_t *head[SOCK_QUEUE], *curl[SOCK_QUEUE], *last[SOCK_QUEUE];

int resolv_conf_fd = -1;
/* int ntp_conf_fd = -1; */

/* If true, allow HOSTNAME changes from dhcp server. */
int allow_hostname = 0;

static uid_t peer_uid;
static gid_t peer_gid;
static pid_t peer_pid;

/* Lists of nameservers and search domains.  Unfortunately they must be
 * per-connection, since otherwise seperate clients could race against
 * one another to write out unpredictable data.
 */
static strlist_t *namesvrs[SOCK_QUEUE];
static strlist_t *domains[SOCK_QUEUE];

static void sighandler(int sig) {
    pending_exit = 1;
}

static void fix_signals(void) {
    disable_signal(SIGPIPE);
    disable_signal(SIGUSR1);
    disable_signal(SIGUSR2);
    disable_signal(SIGTSTP);
    disable_signal(SIGTTIN);
    disable_signal(SIGCHLD);
    disable_signal(SIGHUP);

    hook_signal(SIGINT, sighandler, 0);
    hook_signal(SIGTERM, sighandler, 0);
}

static void die_nulstr(strlist_t *p)
{
    if (!p)
        suicide("FATAL - NULL passed to die_nulstr");
    if (!p->str)
        suicide("FATAL - NULL string in strlist");
}

static void safe_write(int fd, const char *buf, int len)
{
    ssize_t r;
  retry:
    r = write(fd, buf, len);
    if (r != len) {
        if (r == -1) {
            if (errno == EINTR)
                goto retry;
            else
                suicide("write returned error");
        } else {
            len -= r;
            goto retry;
        }
    }
}

/* Writes out each element in a strlist as an argument to a keyword in
 * a file. */
static void write_resolve_list(const char *keyword, strlist_t *list)
{
    char *buf;
    strlist_t *p = list;
    unsigned int len;

    if (!keyword || resolv_conf_fd == -1)
        return;

    while (p) {
        buf = p->str;
        len = strlen(buf);
        if (len) {
            safe_write(resolv_conf_fd, keyword, strlen(keyword));
            safe_write(resolv_conf_fd, buf, strlen(buf));
            safe_write(resolv_conf_fd, "\n", 1);
        }
        p = p->next;
    }
}

/* Writes a new resolv.conf based on the information we have received. */
static void write_resolve_conf(int idx)
{
    int r;
    off_t off;

    if (resolv_conf_fd == -1)
        return;
    if (lseek(resolv_conf_fd, 0, SEEK_SET) == -1)
        return;

    write_resolve_list("nameserver ", namesvrs[idx]);
    write_resolve_list("search ", domains[idx]);
    off = lseek(resolv_conf_fd, 0, SEEK_CUR);
    if (off == -1) {
        log_line("write_resolve_conf: lseek returned error: %s\n",
                strerror(errno));
        return;
    }
  retry:
    r = ftruncate(resolv_conf_fd, off);
    if (r == -1) {
        if (errno == EINTR)
            goto retry;
        log_line("write_resolve_conf: ftruncate returned error: %s\n",
                 strerror(errno));
        return;
    }
    r = fsync(resolv_conf_fd);
    if (r == -1) {
        log_line("write_resolve_conf: fsync returned error: %s\n",
                 strerror(errno));
        return;
    }
}

/* Decomposes a ' '-delimited flat character array onto a strlist, then
 * calls the given function to perform work on the generated strlist. */
static void parse_list(int idx, char *str, strlist_t **toplist,
                       void (*fn)(int))
{
    char *p, n[256];
    unsigned int i;
    strlist_t *newn = 0;

    if (!str || !toplist || !fn)
        return;
    p = str;

    while (p != '\0') {
        memset(n, '\0', sizeof n);
        for (i = 0; i < sizeof n - 1 && *p != '\0' && *p != ' '; ++p, ++i)
            n[i] = *p;
        if (*p == ' ')
            ++p;
        add_to_strlist(&newn, n);
    }

    if (newn) {
        free_strlist(*toplist);
        *toplist = newn;
    } else
        return;

    (*fn)(idx);
}

/* XXX: addme */
static void perform_timezone(int idx, char *str)
{}

/* Does anyone use this command? */
static void perform_timesvr(int idx, char *str)
{}

/* Add a dns server to the /etc/resolv.conf -- we already have a fd. */
static void perform_dns(int idx, char *str)
{
    if (!str || resolv_conf_fd == -1)
        return;
    parse_list(idx, str, &(namesvrs[idx]), &write_resolve_conf);
}

/* Updates for print daemons are too non-standard to be useful. */
static void perform_lprsvr(int idx, char *str)
{}

/* Sets machine hostname. */
static void perform_hostname(int idx, char *str)
{
    if (!allow_hostname || !str)
        return;
    if (sethostname(str, strlen(str) + 1) == -1)
        log_line("sethostname returned %s\n", strerror(errno));
}

/* update "search" in /etc/resolv.conf */
static void perform_domain(int idx, char *str)
{
    if (!str || resolv_conf_fd == -1)
        return;
    parse_list(idx, str, &(domains[idx]), &write_resolve_conf);
}

/* I don't think this can be done without a netfilter extension
 * that isn't in the mainline kernels. */
static void perform_ipttl(int idx, char *str)
{}

/* XXX: addme */
static void perform_ntpsrv(int idx, char *str)
{}

/* Maybe Samba cares about this feature?  I don't know. */
static void perform_wins(int idx, char *str)
{}

/* Wipes all state associated with a given connection. */
static void new_sk(int idx, int val)
{
    sks[idx] = val;
    memset(ibuf[idx], '\0', sizeof(ibuf[idx]));
    free_strlist(head[idx]);
    free_strlist(namesvrs[idx]);
    free_strlist(domains[idx]);
    head[idx] = NULL;
    curl[idx] = NULL;
    last[idx] = NULL;
    namesvrs[idx] = NULL;
    domains[idx] = NULL;
    idle_time[idx] = time(NULL);
    state[idx] = STATE_NOTHING;
    clear_if_data(idx);
}

/* Conditionally accepts a new connection and initializes data structures. */
static void add_sk(int sk)
{
    int i;

    if (authorized_peer(sk, peer_pid, peer_uid, peer_gid)) {
        for (i=0; i<SOCK_QUEUE; i++)
            if (sks[i] == -1) {
                new_sk(i, sk);
                return;
            }
    }
    close(sk);
}

/* Closes idle connections. */
static void close_idle_sk(void)
{
    int i;

    for (i=0; i<SOCK_QUEUE; i++) {
        if (sks[i] == -1)
            continue;
        if (time(NULL) - idle_time[i] > CONN_TIMEOUT) {
            close(sks[i]);
            new_sk(i, -1);
        }
    }
}

/* Decomposes a ':'-delimited flat character array onto a strlist. */
static int stream_onto_list(int i)
{
    int e, s;

    for (e = 0, s = 0; ibuf[i][e] != '\0'; e++) {
        if (ibuf[i][e] == ':') {
            /* Zero-length command: skip. */
            if (s == e) {
                s = e + 1;
                continue;
            }
            curl[i] = xmalloc(sizeof(strlist_t));

            if (head[i] == NULL) {
                head[i] = curl[i];
                last[i] = NULL;
            }

            curl[i]->next = NULL;
            if (last[i] != NULL)
                last[i]->next = curl[i];

            curl[i]->str = xmalloc(e - s + 1);

            strlcpy(curl[i]->str, ibuf[i] + s, e - s);
            last[i] = curl[i];
            s = e + 1;
        }
    }
    return s;
}

/* State machine that runs over the command and argument list,
 * executing commands. */
static void execute_list(int i)
{
    char *p;

    for (;;) {
        if (!curl[i])
            break;
        die_nulstr(curl[i]);

        p = curl[i]->str;

        switch (state[i]) {
            case STATE_NOTHING:
                if (strncmp(p, CMD_INTERFACE, sizeof(CMD_INTERFACE)) == 0)
                    state[i] = STATE_INTERFACE;
                if (strncmp(p, CMD_IP, sizeof(CMD_IP)) == 0)
                    state[i] = STATE_IP;
                if (strncmp(p, CMD_SUBNET, sizeof(CMD_SUBNET)) == 0)
                    state[i] = STATE_SUBNET;
                if (strncmp(p, CMD_TIMEZONE, sizeof(CMD_TIMEZONE)) == 0)
                    state[i] = STATE_TIMEZONE;
                if (strncmp(p, CMD_ROUTER, sizeof(CMD_ROUTER)) == 0)
                    state[i] = STATE_ROUTER;
                if (strncmp(p, CMD_TIMESVR, sizeof(CMD_TIMESVR)) == 0)
                    state[i] = STATE_TIMESVR;
                if (strncmp(p, CMD_DNS, sizeof(CMD_DNS)) == 0)
                    state[i] = STATE_DNS;
                if (strncmp(p, CMD_LPRSVR, sizeof(CMD_LPRSVR)) == 0)
                    state[i] = STATE_LPRSVR;
                if (strncmp(p, CMD_HOSTNAME, sizeof(CMD_HOSTNAME)) == 0)
                    state[i] = STATE_HOSTNAME;
                if (strncmp(p, CMD_DOMAIN, sizeof(CMD_DOMAIN)) == 0)
                    state[i] = STATE_DOMAIN;
                if (strncmp(p, CMD_IPTTL, sizeof(CMD_IPTTL)) == 0)
                    state[i] = STATE_IPTTL;
                if (strncmp(p, CMD_MTU, sizeof(CMD_MTU)) == 0)
                    state[i] = STATE_MTU;
                if (strncmp(p, CMD_BROADCAST, sizeof(CMD_BROADCAST)) == 0)
                    state[i] = STATE_BROADCAST;
                if (strncmp(p, CMD_NTPSRV, sizeof(CMD_NTPSRV)) == 0)
                    state[i] = STATE_NTPSRV;
                if (strncmp(p, CMD_WINS, sizeof(CMD_WINS)) == 0)
                    state[i] = STATE_WINS;
                free_stritem(&(curl[i]));
                break;

            case STATE_INTERFACE:
                perform_interface(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_IP:
                perform_ip(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_SUBNET:
                perform_subnet(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_TIMEZONE:
                perform_timezone(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_ROUTER:
                perform_router(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_TIMESVR:
                perform_timesvr(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_DNS:
                perform_dns(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_LPRSVR:
                perform_lprsvr(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_HOSTNAME:
                perform_hostname(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_DOMAIN:
                perform_domain(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_IPTTL:
                perform_ipttl(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_MTU:
                perform_mtu(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_BROADCAST:
                perform_broadcast(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_NTPSRV:
                perform_ntpsrv(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            case STATE_WINS:
                perform_wins(i, p);
                free_stritem(&(curl[i]));
                state[i] = STATE_NOTHING;
                break;

            default:
                log_line("warning: invalid state in dispatch_work\n");
                break;
        }
    }
    head[i] = curl[i];
}

/* Opens a non-blocking listening socket with the appropriate properties. */
static int get_listen(void)
{
    int lsock, ret;
    struct sockaddr_un lsock_addr =
    {
        .sun_family = AF_UNIX,
        .sun_path = COMM_SOCKET_PATH
    };

    lsock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (lsock == -1)
        suicide("dispatch_work - failed to create socket");

    fcntl(lsock, F_SETFL, O_NONBLOCK);

    (void) unlink(COMM_SOCKET_PATH);
    ret = bind(lsock, (struct sockaddr *) &lsock_addr, sizeof(lsock_addr));
    if (ret)
        suicide("dispatch_work - failed to bind socket");
    ret = chmod(COMM_SOCKET_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (ret)
        suicide("dispatch_work - failed to chmod socket");
    ret = listen(lsock, SOCK_QUEUE);
    if (ret)
        suicide("dispatch_work - failed to listen on socket");

    return lsock;
}

/* Abstracts away the details of accept()ing a socket connection. */
static void accept_conns(int *lsock)
{
    int ret;
    struct sockaddr_un sock_addr;
    socklen_t sock_len = sizeof(sock_addr);

    for(;;)
    {
        ret = accept(*lsock, (struct sockaddr *) &sock_addr, &sock_len);
        if (ret != -1) {
            add_sk(ret);
            return;
        }
        switch (errno) {
            case EAGAIN:
#ifdef LINUX
            case ENETDOWN:
            case EPROTO:
            case ENOPROTOOPT:
            case EHOSTDOWN:
            case ENONET:
            case EHOSTUNREACH:
            case EOPNOTSUPP:
            case ENETUNREACH:
#endif
                return;

            case EINTR:
                continue;

            case EBADF:
            case ENOTSOCK:
            case EINVAL:
                log_line("warning: accept returned %s!\n", strerror(errno));
                close(*lsock);
                *lsock = get_listen();
                return;

            case ECONNABORTED:
            case EMFILE:
            case ENFILE:
                log_line("warning: accept returned %s!\n", strerror(errno));
                return;

            default:
                log_line("warning: accept returned a mysterious error: %s\n",
                        strerror(errno));
                return;
        }
    }
}

/* Core function that handles connections, gathers input, and calls
 * the state machine to do actual work. */
static void dispatch_work(void)
{
    int lsock, ret, highfd, i, index;
    fd_set rfds;
    char buf[MAX_BUF];

    /* Initialize all structures to blank state. */
    for (i=0; i<SOCK_QUEUE; i++)
        sks[i] = -1;
    initialize_if_data();

    lsock = get_listen();

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(lsock, &rfds);

        /* find highest fd */
        for (i=0, highfd=0; i<SOCK_QUEUE; i++) {
            if (sks[i] != -1) {
                FD_SET(sks[i], &rfds);
                if (sks[i] > highfd)
                    highfd = sks[i];
            }
        }
        if (lsock > highfd)
            highfd = lsock;

        ret = select(highfd + 1, &rfds, NULL, NULL, NULL);
        switch (ret) {
            case 0:
                close_idle_sk();
                break;
            case -1:
                if (pending_exit == 1)
                    return;
                suicide("dispatch_work - select returned an error!");
                break;
        }

        if (pending_exit == 1)
            return;

        /* handle pending connections */
        if (FD_ISSET(lsock, &rfds))
            accept_conns(&lsock);

        /* Read in and process data on waiting connections */
        for (i=0; i<SOCK_QUEUE; i++) {
            if (sks[i] == -1)
                continue;
            if (!FD_ISSET(sks[i], &rfds))
                continue;

            idle_time[i] = time(NULL);
            memset(buf, '\0', sizeof(buf));

read_again:
            ret = (int) read(sks[i], buf, MAX_BUF / 2 - 1);

            /* Check to see if peer closed socket */
            if (ret == 0) {
                close(sks[i]);
                new_sk(i, -1);
                continue;
            }

            if (ret == -1) {
                if (errno == EINTR)
                    goto read_again;
                log_line("dispatch_work: read returned %s.\n", strerror(errno));
                close(sks[i]);
                new_sk(i, -1);
                continue;
            }

            /* Discard everything and close connection if we risk overflow.
             * This approach is maximally conservative... worst case is that
             * some client requests will get dropped. */
            index = strlen(ibuf[i]);
            if (index + strlen(buf) > MAX_BUF - 2) {
                close(sks[i]);
                new_sk(i, -1);
                continue;
            }

            /* Append new stream input avoiding overflow. */
            strlcpy(ibuf[i] + index, buf, sizeof(ibuf[i]) - index - 1);

            /* Decompose ibuf contents onto strlist. */
            index = stream_onto_list(i);

            /* Remove everything that we've parsed into the list. */
            strlcpy(buf, ibuf[i] + index, sizeof(buf));
            strlcpy(ibuf[i], buf, sizeof(ibuf[i]));

            /* Now we have a strlist of commands and arguments.
             * Decompose and execute it. */
            if (!head[i])
                continue;
            curl[i] = head[i];
            execute_list(i);
        }
        close_idle_sk();
    }
}

int main(int argc, char** argv) {
    int c, t;
    uid_t uid = 0;
    gid_t gid = 0;
    char pidfile[MAX_PATH_LENGTH] = PID_FILE_DEFAULT;
    char chrootd[MAX_PATH_LENGTH] = "";
    char resolv_conf_d[MAX_PATH_LENGTH] = "";
    char *p;
    struct passwd *pws;
    struct group *grp;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"detach", 0, 0, 'd'},
            {"nodetach", 0, 0, 'n'},
            {"pidfile", 1, 0, 'p'},
            {"quiet", 0, 0, 'q'},
            {"chroot", 1, 0, 'c'},
            {"resolve", 1, 0, 'r'},
            {"hostname", 0, 0, 'o'},
            {"user", 1, 0, 'u'},
            {"group", 1, 0, 'g'},
            {"cuser", 1, 0, 'U'},
            {"cgroup", 1, 0, 'G'},
            {"cpid", 1, 0, 'P'},
            {"interface", 1, 0, 'i'},
            {"help", 0, 0, 'h'},
            {"version", 0, 0, 'v'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "dnp:qc:r:ou:g:U:G:P:i:hv", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {

            case 'h':
                printf(
"ifchd %s, if change daemon.  Licensed under GNU GPL.\n", IFCHD_VERSION);
                printf(
"Copyright (C) 2004-2010 Nicholas J. Kain\n"
"Usage: ifchd [OPTIONS]\n"
"  -d, --detach                detach from TTY and daemonize\n"
"  -n, --nodetach              stay attached to TTY\n"
"  -q, --quiet                 don't print to std(out|err) or log\n"
"  -c, --chroot                path where ifchd should chroot\n"
"  -r, --resolve               path to resolv.conf or equiv\n"
"  -o, --hostname              allow dhcp to set machine hostname\n"
"  -p, --pidfile               pidfile path\n");
                printf(
"  -u, --user                  user name that ifchd should run as\n"
"  -g, --group                 group name that ifchd should run as\n"
"  -U, --cuser                 user name of clients\n"
"  -G, --cgroup                group name of clients\n"
"  -P, --cpid                  process id of client\n"
"  -i, --interface             ifchd clients may modify this interface\n"
"  -h, --help                  print this help and exit\n"
"  -v, --version               print version information and exit\n");
                exit(EXIT_FAILURE);
                break;

            case 'v':
                printf(
"ifchd %s, if change daemon.  Licensed under GNU GPL.\n", IFCHD_VERSION);
                printf(
"Copyright (C) 2004-2010 Nicholas J. Kain\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
                exit(EXIT_FAILURE);
                break;

            case 'd':
                gflags_detach = 1;
                break;

            case 'n':
                gflags_detach = 0;
                break;

            case 'q':
                gflags_quiet = 1;
                break;

            case 'c':
                strlcpy(chrootd, optarg, MAX_PATH_LENGTH);
                break;

            case 'p':
                strlcpy(pidfile, optarg, MAX_PATH_LENGTH);
                break;

            case 'r':
                strlcpy(resolv_conf_d, optarg, MAX_PATH_LENGTH);
                break;

            case 'o':
                allow_hostname = 1;
                break;

            case 'u':
                t = (unsigned int) strtol(optarg, &p, 10);
                if (*p != '\0') {
                    pws = getpwnam(optarg);
                    if (pws) {
                        uid = (int)pws->pw_uid;
                        if (!gid)
                            gid = (int)pws->pw_gid;
                    } else suicide("FATAL - Invalid uid specified.");
                } else
                    uid = t;
                break;

            case 'g':
                t = (unsigned int) strtol(optarg, &p, 10);
                if (*p != '\0') {
                    grp = getgrnam(optarg);
                    if (grp) {
                        gid = (int)grp->gr_gid;
                    } else
                        suicide("FATAL - Invalid gid specified.");
                } else
                    gid = t;
                break;

            case 'U':
                t = (unsigned int) strtol(optarg, &p, 10);
                if (*p != '\0') {
                    pws = getpwnam(optarg);
                    if (pws) {
                        peer_uid = (int)pws->pw_uid;
                        if (!peer_gid)
                            peer_gid = (int)pws->pw_gid;
                    } else
                        suicide("FATAL - Invalid uid specified.");
                } else
                    peer_uid = t;
                break;

            case 'G':
                t = (unsigned int) strtol(optarg, &p, 10);
                if (*p != '\0') {
                    grp = getgrnam(optarg);
                    if (grp) {
                        peer_gid = (int)grp->gr_gid;
                    } else
                        suicide("FATAL - Invalid gid specified.");
                } else
                    peer_gid = t;
                break;

            case 'P':
                t = (unsigned int) strtol(optarg, &p, 10);
                if (*p == '\0')
                    peer_pid = t;
                break;

            case 'i':
                add_permitted_if(optarg);
                break;
        }
    }

    if (getuid())
        suicide("FATAL - I need root for CAP_NET_ADMIN and chroot!");

    if (gflags_detach)
        if (daemon(0,0)) {
            log_line("FATAL - detaching fork failed\n");
            exit(EXIT_FAILURE);
        }

    if (file_exists(pidfile, "w") == -1) {
        log_line("FATAL - cannot open pidfile for write!");
        exit(EXIT_FAILURE);
    }
    write_pid(pidfile);

    umask(077);
    fix_signals();

    /* If we are requested to update resolv.conf, preopen the fd before
     * we drop root privileges, making sure that if we create
     * resolv.conf, it will be world-readable.
     */
    if (strncmp(resolv_conf_d, "", MAX_PATH_LENGTH)) {
        umask(022);
        resolv_conf_fd = open(resolv_conf_d, O_RDWR | O_CREAT, 644);
        umask(077);
        if (resolv_conf_fd == -1) {
            suicide("FATAL - unable to open resolv.conf");
        }
    }

    if (!strncmp(chrootd, "", MAX_PATH_LENGTH))
        suicide("FATAL - No chroot path specified.  Refusing to run.");

    /* Note that failure cases are handled by called fns. */
    imprison(chrootd);
    set_cap(uid, gid, "cap_net_admin=ep");
    drop_root(uid, gid);

    /* Cover our tracks... */
    memset(chrootd, '\0', sizeof(chrootd));
    memset(resolv_conf_d, '\0', sizeof(resolv_conf_d));
    memset(pidfile, '\0', sizeof(pidfile));

    dispatch_work();

    /* Explicitly freed so memory debugger output has less static. */
    for (c=0; c<SOCK_QUEUE; ++c) {
        free_strlist(head[c]);
        free_strlist(namesvrs[c]);
        free_strlist(domains[c]);
    }

    exit(EXIT_SUCCESS);
}
