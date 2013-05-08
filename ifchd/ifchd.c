/* ifchd.c - interface change daemon
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <pwd.h>
#include <grp.h>

#include <signal.h>
#include <errno.h>

#include <getopt.h>

#include "ifchd-defines.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "signals.h"
#include "ifch_proto.h"
#include "strl.h"
#include "cap.h"
#include "io.h"
#include "linux.h"
#include "seccomp-bpf.h"

struct ifchd_client clients[SOCK_QUEUE];

static int epollfd, signalFd;
/* Extra two event slots are for signalFd and the listen socket. */
static struct epoll_event events[SOCK_QUEUE+2];

int resolv_conf_fd = -1;
/* int ntp_conf_fd = -1; */

/* If true, allow HOSTNAME changes from dhcp server. */
int allow_hostname = 0;

static uid_t peer_uid;
static gid_t peer_gid;
static pid_t peer_pid;

static int gflags_verbose = 0;

extern int execute_buffer(struct ifchd_client *cl, char *newbuf);

static void writeordie(int fd, const char *buf, int len)
{
    if (safe_write(fd, buf, len) == -1)
        suicide("write returned error");
}

static void epoll_add(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
    if (r == -1)
        suicide("epoll_add failed %s", strerror(errno));
}

static void epoll_del(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
    if (r == -1)
        suicide("epoll_del failed %s", strerror(errno));
}

static int enforce_seccomp(void)
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(accept),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(getsockopt),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(listen),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(fsync),
        ALLOW_SYSCALL(lseek),
        ALLOW_SYSCALL(truncate),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(unlink),
        ALLOW_SYSCALL(bind),
        ALLOW_SYSCALL(chmod),

        ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(clock_gettime),

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof filter / sizeof filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    return 0;
}

/* Writes a new resolv.conf based on the information we have received. */
static void write_resolve_conf(struct ifchd_client *cl)
{
    const static char ns_str[] = "nameserver ";
    const static char dom_str[] = "domain ";
    const static char srch_str[] = "search ";
    int r;
    off_t off;
    char buf[MAX_BUF];

    if (resolv_conf_fd == -1)
        return;
    if (strlen(cl->namesvrs) == 0)
        return;

    if (lseek(resolv_conf_fd, 0, SEEK_SET) == -1)
        return;

    char *p = cl->namesvrs;
    while (p && (*p != '\0')) {
        char *q = strchr(p, ' ');
        if (!q)
            q = strchr(p, '\0');
        else
            *q++ = '\0';
        strnkcpy(buf, p, sizeof buf);

        writeordie(resolv_conf_fd, ns_str, strlen(ns_str));
        writeordie(resolv_conf_fd, buf, strlen(buf));
        writeordie(resolv_conf_fd, "\n", 1);

        p = q;
    }

    p = cl->domains;
    int numdoms = 0;
    while (p && (*p != '\0')) {
        char *q = strchr(p, ' ');
        if (!q)
            q = strchr(p, '\0');
        else
            *q++ = '\0';
        strnkcpy(buf, p, sizeof buf);

        if (numdoms == 0) {
            writeordie(resolv_conf_fd, dom_str, strlen(dom_str));
            writeordie(resolv_conf_fd, buf, strlen(buf));
        } else {
            if (numdoms == 1) {
                writeordie(resolv_conf_fd, "\n", 1);
                writeordie(resolv_conf_fd, srch_str, strlen(srch_str));
                writeordie(resolv_conf_fd, buf, strlen(buf));
            } else {
                writeordie(resolv_conf_fd, " ", 1);
                writeordie(resolv_conf_fd, buf, strlen(buf));
            }
        }

        ++numdoms;
        p = q;
        if (numdoms > 6)
            break;
    }
    writeordie(resolv_conf_fd, "\n", 1);

    off = lseek(resolv_conf_fd, 0, SEEK_CUR);
    if (off == -1) {
        log_line("write_resolve_conf: lseek returned error: %s",
                strerror(errno));
        return;
    }
  retry:
    r = ftruncate(resolv_conf_fd, off);
    if (r == -1) {
        if (errno == EINTR)
            goto retry;
        log_line("write_resolve_conf: ftruncate returned error: %s",
                 strerror(errno));
        return;
    }
    r = fsync(resolv_conf_fd);
    if (r == -1) {
        log_line("write_resolve_conf: fsync returned error: %s",
                 strerror(errno));
        return;
    }
}

/* XXX: addme */
void perform_timezone(struct ifchd_client *cl, const char *str, size_t len)
{}

/* Add a dns server to the /etc/resolv.conf -- we already have a fd. */
void perform_dns(struct ifchd_client *cl, const char *str, size_t len)
{
    if (!str || resolv_conf_fd == -1)
        return;
    strnkcpy(cl->namesvrs, str, sizeof cl->namesvrs);
    write_resolve_conf(cl);
    log_line("Added DNS server: '%s'", str);
}

/* Updates for print daemons are too non-standard to be useful. */
void perform_lprsvr(struct ifchd_client *cl, const char *str, size_t len)
{}

/* Sets machine hostname. */
void perform_hostname(struct ifchd_client *cl, const char *str, size_t len)
{
    if (!allow_hostname || !str)
        return;
    if (sethostname(str, strlen(str) + 1) == -1)
        log_line("sethostname returned %s", strerror(errno));
    else
        log_line("Set hostname: '%s'", str);
}

/* update "domain" and "search" in /etc/resolv.conf */
void perform_domain(struct ifchd_client *cl, const char *str, size_t len)
{
    if (!str || resolv_conf_fd == -1)
        return;
    strnkcpy(cl->domains, str, sizeof cl->domains);
    write_resolve_conf(cl);
    log_line("Added DNS domain: '%s'", str);
}

/* I don't think this can be done without a netfilter extension
 * that isn't in the mainline kernels. */
void perform_ipttl(struct ifchd_client *cl, const char *str, size_t len)
{}

/* XXX: addme */
void perform_ntpsrv(struct ifchd_client *cl, const char *str, size_t len)
{}

/* Maybe Samba cares about this feature?  I don't know. */
void perform_wins(struct ifchd_client *cl, const char *str, size_t len)
{}

static inline void clock_or_die(struct timespec *ts)
{
    if (clock_gettime(CLOCK_MONOTONIC, ts))
        suicide("clock_gettime failed %s", strerror(errno));
}

static void ifchd_client_init(struct ifchd_client *p)
{
    p->fd = -1;
    struct timespec ts;
    clock_or_die(&ts);
    p->idle_time = ts.tv_sec;
    p->state = STATE_NOTHING;

    memset(p->ibuf, 0, sizeof p->ibuf);
    memset(p->ifnam, 0, sizeof p->ifnam);
    memset(p->namesvrs, 0, sizeof p->namesvrs);
    memset(p->domains, 0, sizeof p->domains);
}

static void ifchd_client_wipe(struct ifchd_client *p)
{
    if (p->fd >= 0) {
        epoll_del(p->fd);
        close(p->fd);
    }
    ifchd_client_init(p);
}

static void ifchd_client_new(struct ifchd_client *p, int fd)
{
    ifchd_client_wipe(p);
    p->fd = fd;
    epoll_add(fd);
}

/* Conditionally accepts a new connection and initializes data structures. */
static void add_sk(int sk)
{
    int i;

    if (authorized_peer(sk, peer_pid, peer_uid, peer_gid)) {
        for (i = 0; i < SOCK_QUEUE; i++) {
            struct ifchd_client *p = &clients[i];
            if (p->fd == -1) {
                ifchd_client_new(p, sk);
                return;
            }
        }
    }
    close(sk);
}

/* Closes idle connections. */
static void close_idle_sk(void)
{
    int i;

    for (i=0; i<SOCK_QUEUE; i++) {
        struct ifchd_client *p = &clients[i];
        if (p->fd == -1)
            continue;
        struct timespec ts;
        clock_or_die(&ts);
        if (ts.tv_sec - p->idle_time > CONN_TIMEOUT)
            ifchd_client_wipe(p);
    }
}

/* Opens a non-blocking listening socket with the appropriate properties. */
static int get_listen(void)
{
    int lsock, ret;
    static const struct sockaddr_un lsock_addr =
    {
        .sun_family = AF_UNIX,
        .sun_path = "/var/state/ifchange"
    };

    lsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lsock == -1)
        suicide("dispatch_work - failed to create socket");

    fcntl(lsock, F_SETFL, O_NONBLOCK);

    (void) unlink("/var/state/ifchange");
    ret = bind(lsock, (struct sockaddr *) &lsock_addr, sizeof(lsock_addr));
    if (ret)
        suicide("dispatch_work - failed to bind socket");
    ret = chmod("/var/state/ifchange", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (ret)
        suicide("dispatch_work - failed to chmod socket");
    ret = listen(lsock, SOCK_QUEUE);
    if (ret)
        suicide("dispatch_work - failed to listen on socket");

    return lsock;
}

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
                log_line("warning: accept returned %s!", strerror(errno));

                epoll_del(*lsock);
                close(*lsock);

                *lsock = get_listen();
                epoll_add(*lsock);
                return;

            case ECONNABORTED:
            case EMFILE:
            case ENFILE:
                log_line("warning: accept returned %s!", strerror(errno));
                return;

            default:
                log_line("warning: accept returned a mysterious error: %s",
                        strerror(errno));
                return;
        }
    }
}

static void setup_signals()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");
    signalFd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (signalFd < 0)
        suicide("signalfd failed");
}

static void signal_dispatch()
{
    int t, off = 0;
    struct signalfd_siginfo si;
  again:
    t = read(signalFd, (char *)&si + off, sizeof si - off);
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
        case SIGINT:
        case SIGTERM:
            exit(EXIT_SUCCESS);
        default:
            break;
    }
}

static void process_client_fd(int fd)
{
    struct ifchd_client *cl = NULL;
    int r;
    char buf[MAX_BUF];

    for (int j = 0; j < SOCK_QUEUE; ++j) {
        if (clients[j].fd == fd) {
            cl = &clients[j];
            break;
        }
    }
    if (!cl)
        suicide("epoll returned pending read for untracked fd");

    struct timespec ts;
    clock_or_die(&ts);
    cl->idle_time = ts.tv_sec;
    memset(buf, '\0', sizeof buf);

    r = safe_read(cl->fd, buf, sizeof buf - 1);
    if (r == 0) {
        // Remote end hung up.
        goto fail;
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        log_line("error reading from client fd: %s", strerror(errno));
        goto fail;
    }

    if (execute_buffer(cl, buf) == -1) {
        log_line("execute_buffer was passed invalid commands");
        goto fail;
    }
    return;
  fail:
    ifchd_client_wipe(cl);
}

/* Core function that handles connections, gathers input, and calls
 * the state machine to do actual work. */
static void dispatch_work(void)
{
    int lsock;

    /* Initialize all structures to blank state. */
    for (int i = 0; i < SOCK_QUEUE; i++)
        ifchd_client_init(&clients[i]);

    lsock = get_listen();

    epoll_add(lsock);
    epoll_add(signalFd);

    for (;;) {
        int r = epoll_wait(epollfd, events, SOCK_QUEUE + 2, -1);
        if (r == -1) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        for (int i = 0; i < r; ++i) {
            int fd = events[i].data.fd;
            if (fd == lsock)
                accept_conns(&lsock);
            else if (fd == signalFd)
                signal_dispatch();
            else
                process_client_fd(fd);
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
        static const struct option long_options[] = {
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
            {"verbose", 0, 0, 'V'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "dnp:qc:r:ou:g:U:G:P:i:hvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {

            case 'h':
                printf(
"ifchd %s, if change daemon.  Licensed under 2-clause BSD.\n", IFCHD_VERSION);
                printf(
"Copyright (C) 2004-2012 Nicholas J. Kain\n"
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
"  -V, --verbose               log detailed messages\n"
"  -h, --help                  print this help and exit\n"
"  -v, --version               print version information and exit\n");
                exit(EXIT_FAILURE);
                break;

            case 'v':
                printf("ifchd %s, if change daemon.\n", IFCHD_VERSION);
                printf("Copyright (c) 2004-2013 Nicholas J. Kain\n"
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
                strnkcpy(chrootd, optarg, MAX_PATH_LENGTH);
                break;

            case 'p':
                strnkcpy(pidfile, optarg, MAX_PATH_LENGTH);
                break;

            case 'r':
                strnkcpy(resolv_conf_d, optarg, MAX_PATH_LENGTH);
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

            case 'V':
                gflags_verbose = 1;
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
    setup_signals();

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

    epollfd = epoll_create1(0);
    if (epollfd == -1)
        suicide("epoll_create1 failed");

    if (enforce_seccomp())
        log_line("seccomp filter cannot be installed");

    dispatch_work();

    /* Explicitly freed so memory debugger output has less static. */
    for (size_t i = 0; i < SOCK_QUEUE; ++i)
        ifchd_client_wipe(&clients[i]);

    exit(EXIT_SUCCESS);
}
