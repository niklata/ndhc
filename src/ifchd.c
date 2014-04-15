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
#include "nk/log.h"
#include "nk/privilege.h"
#include "nk/signals.h"
#include "nk/io.h"

#include "seccomp.h"
#include "ifchd.h"
#include "ndhc.h"
#include "ifchd-parse.h"
#include "sys.h"
#include "ifset.h"

struct ifchd_client cl;

static int epollfd, signalFd;
/* Slots are for signalFd and the ndhc -> ifchd socket. */
static struct epoll_event events[2];

static int resolv_conf_fd = -1;
/* int ntp_conf_fd = -1; */

/* If true, allow HOSTNAME changes from dhcp server. */
int allow_hostname = 0;

uid_t ifch_uid = 0;
gid_t ifch_gid = 0;

static void writeordie(int fd, const char *buf, size_t len)
{
    ssize_t r = safe_write(fd, buf, len);
    if (r < 0 || (size_t)r != len)
        suicide("%s: (%s) write failed: %d", client_config.interface,
                __func__, r);
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

    if (lseek(resolv_conf_fd, 0, SEEK_SET) < 0)
        return;

    char *p = cl.namesvrs;
    while (p && (*p != '\0')) {
        char *q = strchr(p, ',');
        if (!q)
            q = strchr(p, '\0');
        else
            *q++ = '\0';
        ssize_t sl = snprintf(buf, sizeof buf, "%s", p);
        if (sl < 0 || (size_t)sl >= sizeof buf) {
            log_warning("%s: (%s) snprintf failed appending nameservers",
                        client_config.interface, __func__);
        }

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
        ssize_t sl = snprintf(buf, sizeof buf, "%s", p);
        if (sl < 0 || (size_t)sl >= sizeof buf) {
            log_warning("%s: (%s) snprintf failed appending domains",
                        client_config.interface, __func__);
        }

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
    if (off < 0) {
        log_line("write_resolve_conf: lseek returned error: %s",
                strerror(errno));
        return;
    }
  retry:
    r = ftruncate(resolv_conf_fd, off);
    if (r < 0) {
        if (errno == EINTR)
            goto retry;
        log_line("write_resolve_conf: ftruncate returned error: %s",
                 strerror(errno));
        return;
    }
    r = fsync(resolv_conf_fd);
    if (r < 0) {
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
    if (!str || resolv_conf_fd < 0)
        return;
    if (len > sizeof cl.namesvrs) {
        log_line("DNS server list is too long: %zu > %zu", len, cl.namesvrs);
        return;
    }
    ssize_t sl = snprintf(cl.namesvrs, sizeof cl.namesvrs, "%s", str);
    if (sl < 0 || (size_t)sl >= sizeof cl.namesvrs) {
        log_warning("%s: (%s) snprintf failed",
                    client_config.interface, __func__);
    }
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
    if (sethostname(str, len) < 0)
        log_line("sethostname returned %s", strerror(errno));
    else
        log_line("Set hostname: '%s'", str);
}

/* update "domain" and "search" in /etc/resolv.conf */
void perform_domain(const char *str, size_t len)
{
    if (!str || resolv_conf_fd < 0)
        return;
    if (len > sizeof cl.domains) {
        log_line("DNS domain list is too long: %zu > %zu", len, cl.namesvrs);
        return;
    }
    ssize_t sl = snprintf(cl.domains, sizeof cl.domains, "%s", str);
    if (sl < 0 || (size_t)sl >= sizeof cl.domains) {
        log_warning("%s: (%s) snprintf failed",
                    client_config.interface, __func__);
    }
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

static void setup_signals_ifch(void)
{
    sigset_t mask;
    sigemptyset(&mask);
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
    struct signalfd_siginfo si = {0};
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
        case SIGHUP:
            exit(EXIT_SUCCESS);
            break;
        default:
            break;
    }
}

static void inform_execute(char c)
{
    ssize_t r = safe_write(ifchSock[1], &c, sizeof c);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0)
        suicide("%s: (%s) error writing to ifch -> ndhc socket: %s",
                client_config.interface, __func__, strerror(errno));
}

static void process_client_socket(void)
{
    char buf[MAX_BUF];

    memset(buf, '\0', sizeof buf);
    ssize_t r = safe_recv(ifchSock[1], buf, sizeof buf - 1, MSG_DONTWAIT);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        suicide("%s: (%s) error reading from ndhc -> ifch socket: %s",
                client_config.interface, __func__, strerror(errno));
    }

    if (execute_buffer(buf) < 0) {
        inform_execute('-');
        suicide("%s: (%s) received invalid commands: '%s'",
                client_config.interface, __func__, buf);
    } else
        inform_execute('+');
}

static void do_ifch_work(void)
{
    epollfd = epoll_create1(0);
    if (epollfd < 0)
        suicide("epoll_create1 failed");

    if (enforce_seccomp_ifch())
        log_line("ifch seccomp filter cannot be installed");

    cl.state = STATE_NOTHING;
    memset(cl.ibuf, 0, sizeof cl.ibuf);
    memset(cl.namesvrs, 0, sizeof cl.namesvrs);
    memset(cl.domains, 0, sizeof cl.domains);

    epoll_add(epollfd, ifchSock[1]);
    epoll_add(epollfd, signalFd);

    for (;;) {
        int r = epoll_wait(epollfd, events, 2, -1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        for (int i = 0; i < r; ++i) {
            int fd = events[i].data.fd;
            if (fd == ifchSock[1])
                process_client_socket();
            else if (fd == signalFd)
                signal_dispatch();
            else
                suicide("ifch: unexpected fd while performing epoll");
        }
    }
}

void ifch_main(void)
{
    prctl(PR_SET_NAME, "ndhc: ifch");
    prctl(PR_SET_PDEATHSIG, SIGHUP);
    umask(077);
    setup_signals_ifch();

    // If we are requested to update resolv.conf, preopen the fd before
    // we drop root privileges, making sure that if we create
    // resolv.conf, it will be world-readable.
    if (strncmp(resolv_conf_d, "", sizeof resolv_conf_d)) {
        umask(022);
        resolv_conf_fd = open(resolv_conf_d, O_RDWR | O_CREAT, 644);
        umask(077);
        if (resolv_conf_fd < 0) {
            suicide("FATAL - unable to open resolv.conf");
        }
    }
    memset(resolv_conf_d, '\0', sizeof resolv_conf_d);

    nk_set_chroot(chroot_dir);
    memset(chroot_dir, '\0', sizeof chroot_dir);
    unsigned char keepcaps[] = { CAP_NET_ADMIN };
    nk_set_uidgid(ifch_uid, ifch_gid, keepcaps, sizeof keepcaps);
    do_ifch_work();
}

