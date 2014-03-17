/* ifchd.c - interface change daemon
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
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <signal.h>
#include <errno.h>

#include <getopt.h>

#include "ifchd.h"
#include "ndhc.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "signals.h"
#include "ifch_proto.h"
#include "ifchd-parse.h"
#include "strl.h"
#include "cap.h"
#include "io.h"
#include "sys.h"
#include "ifset.h"
#include "seccomp.h"

struct ifchd_client cl;

static int epollfd, signalFd;
/* Slots are for signalFd and the ndhc -> ifchd pipe. */
static struct epoll_event events[2];

static int resolv_conf_fd = -1;
/* int ntp_conf_fd = -1; */

/* If true, allow HOSTNAME changes from dhcp server. */
int allow_hostname = 0;

char pidfile_ifch[MAX_PATH_LENGTH] = PID_FILE_IFCH_DEFAULT;
uid_t ifch_uid = 0;
gid_t ifch_gid = 0;

static void writeordie(int fd, const char *buf, int len)
{
    if (safe_write(fd, buf, len) == -1)
        suicide("write returned error");
}

/* Writes a new resolv.conf based on the information we have received. */
static void write_resolve_conf(void)
{
    static const char ns_str[] = "nameserver ";
    static const char dom_str[] = "domain ";
    static const char srch_str[] = "search ";
    int r;
    off_t off;
    char buf[MAX_BUF];

    if (resolv_conf_fd < 0)
        return;
    if (strlen(cl.namesvrs) == 0)
        return;

    if (lseek(resolv_conf_fd, 0, SEEK_SET) == -1)
        return;

    char *p = cl.namesvrs;
    while (p && (*p != '\0')) {
        char *q = strchr(p, ',');
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

    p = cl.domains;
    int numdoms = 0;
    while (p && (*p != '\0')) {
        char *q = strchr(p, ',');
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
void perform_timezone(const char *str, size_t len)
{
    (void)len;
    log_line("Timezone setting NYI: '%s'", str);
}

/* Add a dns server to the /etc/resolv.conf -- we already have a fd. */
void perform_dns(const char *str, size_t len)
{
    if (!str || resolv_conf_fd == -1)
        return;
    if (len > sizeof cl.namesvrs) {
        log_line("DNS server list is too long: %zu > %zu", len, cl.namesvrs);
        return;
    }
    strnkcpy(cl.namesvrs, str, sizeof cl.namesvrs);
    write_resolve_conf();
    log_line("Added DNS server: '%s'", str);
}

/* Updates for print daemons are too non-standard to be useful. */
void perform_lprsvr(const char *str, size_t len)
{
    (void)len;
    log_line("Line printer server setting NYI: '%s'", str);
}

/* Sets machine hostname. */
void perform_hostname(const char *str, size_t len)
{
    if (!allow_hostname || !str)
        return;
    if (sethostname(str, len) == -1)
        log_line("sethostname returned %s", strerror(errno));
    else
        log_line("Set hostname: '%s'", str);
}

/* update "domain" and "search" in /etc/resolv.conf */
void perform_domain(const char *str, size_t len)
{
    if (!str || resolv_conf_fd == -1)
        return;
    if (len > sizeof cl.domains) {
        log_line("DNS domain list is too long: %zu > %zu", len, cl.namesvrs);
        return;
    }
    strnkcpy(cl.domains, str, sizeof cl.domains);
    write_resolve_conf();
    log_line("Added DNS domain: '%s'", str);
}

/* I don't think this can be done without a netfilter extension
 * that isn't in the mainline kernels. */
void perform_ipttl(const char *str, size_t len)
{
    (void)len;
    log_line("TTL setting NYI: '%s'", str);
}

/* XXX: addme */
void perform_ntpsrv(const char *str, size_t len)
{
    (void)len;
    log_line("NTP server setting NYI: '%s'", str);
}

/* Maybe Samba cares about this feature?  I don't know. */
void perform_wins(const char *str, size_t len)
{
    (void)str;
    (void)len;
}

static void ifchd_client_init(void)
{
    cl.state = STATE_NOTHING;

    memset(cl.ibuf, 0, sizeof cl.ibuf);
    memset(cl.namesvrs, 0, sizeof cl.namesvrs);
    memset(cl.domains, 0, sizeof cl.domains);
}

static void setup_signals_ifch(void)
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

static void signal_dispatch(void)
{
    int t;
    size_t off = 0;
    struct signalfd_siginfo si;
  again:
    t = read(signalFd, (char *)&si + off, sizeof si - off);
    if (t < 0) {
        if (t == EAGAIN || t == EWOULDBLOCK || t == EINTR)
            goto again;
        else
            suicide("signalfd read error");
    }
    if (off + (unsigned)t < sizeof si)
        off += t;
    switch (si.ssi_signo) {
        case SIGINT:
        case SIGTERM:
            exit(EXIT_SUCCESS);
            break;
        case SIGPIPE:
            log_line("ndhc-ifch: IPC pipe closed.  Exiting.");
            exit(EXIT_SUCCESS);
            break;
        default:
            break;
    }
}

static void inform_execute(int success)
{
    int r;
    char c = success ? '+' : '-';
  retry:
    r = safe_write(pToNdhcW, &c, sizeof c);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            goto retry;
        log_line("%s: (%s) error writing to ifch -> ndhc pipe: %s",
                 client_config.interface, __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void process_client_pipe(void)
{
    char buf[MAX_BUF];

    memset(buf, '\0', sizeof buf);
    int r = safe_read(pToIfchR, buf, sizeof buf - 1);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        log_line("%s: (%s) error reading from ndhc -> ifch pipe: %s",
                 client_config.interface, __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (execute_buffer(buf) == -1) {
        log_line("%s: (%s) execute_buffer was passed invalid commands: '%s'",
                 client_config.interface, __func__, buf);
        inform_execute(0);
        exit(EXIT_FAILURE);
    } else
        inform_execute(1);
}

void do_ifch_work(void)
{
    epollfd = epoll_create1(0);
    if (epollfd == -1)
        suicide("epoll_create1 failed");

    if (enforce_seccomp_ifch())
        log_line("ifch seccomp filter cannot be installed");

    ifchd_client_init();

    epoll_add(epollfd, pToIfchR);
    epoll_add(epollfd, signalFd);

    for (;;) {
        int r = epoll_wait(epollfd, events, 2, -1);
        if (r == -1) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        for (int i = 0; i < r; ++i) {
            int fd = events[i].data.fd;
            if (fd == pToIfchR) {
                process_client_pipe();
            } else if (fd == signalFd) {
                signal_dispatch();
            } else {
                log_line("ifch: unexpected fd while performing epoll");
                exit(EXIT_FAILURE);
            }
        }
    }
}

void ifch_main(void)
{
    prctl(PR_SET_NAME, "ndhc: ifch");
    if (file_exists(pidfile_ifch, "w") == -1) {
        log_line("FATAL - can't open ifch-pidfile '%s' for write!",
                 pidfile_ifch);
        exit(EXIT_FAILURE);
    }
    write_pid(pidfile_ifch);
    memset(pidfile_ifch, '\0', sizeof pidfile_ifch);

    umask(077);
    setup_signals_ifch();

    // If we are requested to update resolv.conf, preopen the fd before
    // we drop root privileges, making sure that if we create
    // resolv.conf, it will be world-readable.
    if (strncmp(resolv_conf_d, "", sizeof resolv_conf_d)) {
        umask(022);
        resolv_conf_fd = open(resolv_conf_d, O_RDWR | O_CREAT, 644);
        umask(077);
        if (resolv_conf_fd == -1) {
            suicide("FATAL - unable to open resolv.conf");
        }
    }
    memset(resolv_conf_d, '\0', sizeof resolv_conf_d);

    imprison(chroot_dir);
    memset(chroot_dir, '\0', sizeof chroot_dir);
    set_cap(ifch_uid, ifch_gid, "cap_net_admin=ep");
    drop_root(ifch_uid, ifch_gid);

    do_ifch_work();
}

