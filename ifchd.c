// Copyright 2004-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include "nk/log.h"
#include "nk/privs.h"
#include "nk/io.h"
#include "ifchd.h"
#include "ndhc.h"
#include "ifchd-parse.h"
#include "sys.h"
#include "ifset.h"

struct ifchd_client cl;

static int resolv_conf_fd = -1;
/* int ntp_conf_fd = -1; */
static int resolv_conf_head_fd = -1;
static int resolv_conf_tail_fd = -1;

/* If true, allow HOSTNAME changes from dhcp server. */
int allow_hostname = 0;

uid_t ifch_uid = 0;
gid_t ifch_gid = 0;

static void writeordie(int fd, const char *buf, size_t len)
{
    ssize_t r = safe_write(fd, buf, len);
    if (r < 0 || (size_t)r != len)
        suicide("%s: (%s) write failed: %zd\n", client_config.interface,
                __func__, r);
}

static int write_append_fd(int to_fd, int from_fd, const char *descr)
{
    if (from_fd < 0) return 0;
    if (to_fd < 0) return -1;

    const off_t lse = lseek(from_fd, 0, SEEK_END);
    if (lse < 0) {
        log_line("%s: (%s) lseek(SEEK_END) failed %s\n",
                 client_config.interface, __func__, descr);
        return -2;
    }
    if (lseek(from_fd, 0, SEEK_SET) < 0) {
        log_line("%s: (%s) lseek(SEEK_SET) failed %s\n",
                 client_config.interface, __func__, descr);
        return -2;
    }

    char buf[4096];
    size_t from_fd_len = (size_t)lse;
    while (from_fd_len > 0) {
        const size_t to_read = from_fd_len <= sizeof buf ? from_fd_len : sizeof buf;
        ssize_t r = safe_read(from_fd, buf, to_read);
        if (r < 0 || (size_t)r != to_read)
            suicide("%s: (%s) read failed %s\n", client_config.interface, __func__, descr);
        r = safe_write(to_fd, buf, to_read);
        if (r < 0 || (size_t)r != to_read)
            suicide("%s: (%s) write failed %s\n", client_config.interface, __func__, descr);
        from_fd_len -= to_read;
    }
    return 0;
}

/* Writes a new resolv.conf based on the information we have received. */
static int write_resolve_conf(void)
{
    static const char ns_str[] = "nameserver ";
    static const char dom_str[] = "domain ";
    static const char srch_str[] = "search ";
    off_t off;
    char buf[MAX_BUF];

    if (resolv_conf_fd < 0)
        return 0;
    if (strlen(cl.namesvrs) == 0)
        return -1;

    if (lseek(resolv_conf_fd, 0, SEEK_SET) < 0)
        return -1;

    write_append_fd(resolv_conf_fd, resolv_conf_head_fd, "prepending resolv_conf head");

    char *p = cl.namesvrs;
    while (p && (*p != '\0')) {
        char *q = strchr(p, ',');
        if (!q)
            q = strchr(p, '\0');
        else
            *q++ = '\0';
        if (!memccpy(buf, p, 0, sizeof buf)) {
            log_line("%s: (%s) memccpy failed appending nameservers\n",
                     client_config.interface, __func__);
            return -1;
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
        if (!memccpy(buf, p, 0, sizeof buf)) {
            log_line("%s: (%s) memccpy failed appending domains\n",
                     client_config.interface, __func__);
            return -1;
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

    write_append_fd(resolv_conf_fd, resolv_conf_tail_fd, "appending resolv_conf tail");

    off = lseek(resolv_conf_fd, 0, SEEK_CUR);
    if (off < 0) {
        log_line("%s: (%s) lseek returned error: %s\n", client_config.interface,
                 __func__, strerror(errno));
        return -1;
    }
    if (safe_ftruncate(resolv_conf_fd, off) < 0) {
        log_line("%s: (%s) ftruncate returned error: %s\n", client_config.interface,
                 __func__, strerror(errno));
        return -1;
    }
    if (fsync(resolv_conf_fd) < 0) {
        log_line("%s: (%s) fsync returned error: %s\n", client_config.interface,
                 __func__, strerror(errno));
        return -1;
    }
    return 0;
}

/* XXX: addme */
int perform_timezone(const char *str, size_t len)
{
    (void)len;
    log_line("Timezone setting NYI: '%s'\n", str);
    return 0;
}

/* Add a dns server to the /etc/resolv.conf -- we already have a fd. */
int perform_dns(const char *str, size_t len)
{
    if (resolv_conf_fd < 0)
        return 0;
    int ret = -1;
    if (len > sizeof cl.namesvrs) {
        log_line("DNS server list is too long: %zu > %zu\n", len, sizeof cl.namesvrs);
        return ret;
    }
    if (!memccpy(cl.namesvrs, str, 0, sizeof cl.namesvrs)) {
        memset(cl.namesvrs, 0, sizeof cl.namesvrs);
        log_line("%s: (%s) memccpy failed\n", client_config.interface, __func__);
        return ret;
    }
    ret = write_resolve_conf();
    if (ret >= 0)
        log_line("Added DNS server: '%s'\n", str);
    return ret;
}

/* Updates for print daemons are too non-standard to be useful. */
int perform_lprsvr(const char *str, size_t len)
{
    (void)len;
    log_line("Line printer server setting NYI: '%s'\n", str);
    return 0;
}

/* Sets machine hostname. */
int perform_hostname(const char *str, size_t len)
{
    if (!allow_hostname)
        return 0;
    if (sethostname(str, len) < 0) {
        log_line("sethostname returned %s\n", strerror(errno));
        return -1;
    }
    log_line("Set hostname: '%s'\n", str);
    return 0;
}

/* update "domain" and "search" in /etc/resolv.conf */
int perform_domain(const char *str, size_t len)
{
    if (resolv_conf_fd < 0)
        return 0;
    int ret = -1;
    if (len > sizeof cl.domains) {
        log_line("DNS domain list is too long: %zu > %zu\n", len, sizeof cl.domains);
        return ret;
    }
    if (!memccpy(cl.domains, str, 0, sizeof cl.domains)) {
        memset(cl.domains, 0, sizeof cl.domains);
        log_line("%s: (%s) memccpy failed\n", client_config.interface, __func__);
        return ret;
    }
    ret = write_resolve_conf();
    if (ret == 0)
        log_line("Added DNS domain: '%s'\n", str);
    return ret;
}

/* I don't think this can be done without a netfilter extension
 * that isn't in the mainline kernels. */
int perform_ipttl(const char *str, size_t len)
{
    (void)len;
    log_line("TTL setting NYI: '%s'\n", str);
    return 0;
}

/* XXX: addme */
int perform_ntpsrv(const char *str, size_t len)
{
    (void)len;
    log_line("NTP server setting NYI: '%s'\n", str);
    return 0;
}

/* Maybe Samba cares about this feature?  I don't know. */
int perform_wins(const char *str, size_t len)
{
    (void)str;
    (void)len;
    return 0;
}

static void inform_execute(char c)
{
    ssize_t r = safe_write(ifchSock[1], &c, sizeof c);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0)
        suicide("%s: (%s) error writing to ifch -> ndhc socket: %s\n",
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
        suicide("%s: (%s) error reading from ndhc -> ifch socket: %s\n",
                client_config.interface, __func__, strerror(errno));
    }

    int ebr = execute_buffer(buf);
    if (ebr < 0) {
        if (ebr == -99)
            suicide("%s: (%s) unrecoverable failure in command sequence: '%s'\n",
                    client_config.interface, __func__, buf);
        inform_execute('-');
    } else
        inform_execute('+');
}

static void do_ifch_work(void)
{
    cl.state = STATE_NOTHING;
    memset(cl.ibuf, 0, sizeof cl.ibuf);
    memset(cl.namesvrs, 0, sizeof cl.namesvrs);
    memset(cl.domains, 0, sizeof cl.domains);

    struct pollfd pfds[2] = {0};
    pfds[0].fd = ifchSock[1];
    pfds[0].events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
    pfds[1].fd = ifchStream[1];
    pfds[1].events = POLLHUP|POLLERR|POLLRDHUP;

    for (;;) {
        if (poll(pfds, 2, -1) < 0) {
            if (errno != EINTR) suicide("poll failed\n");
        }
        if (pfds[0].revents & POLLIN) {
            process_client_socket();
        }
        if (pfds[0].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
            suicide("ifchSock closed unexpectedly\n");
        }
        if (pfds[1].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
            exit(EXIT_SUCCESS);
        }
    }
}

// If we are requested to update resolv.conf, preopen the fd before we drop
// root, making sure that if we create resolv.conf, it will be world-readable.
static void setup_resolv_conf(void)
{
    if (strncmp(resolv_conf_d, "", sizeof resolv_conf_d)) {
        umask(022);
        resolv_conf_fd = open(resolv_conf_d, O_RDWR|O_CREAT|O_CLOEXEC, 644);
        umask(077);
        if (resolv_conf_fd < 0) {
            suicide("FATAL - unable to open resolv.conf\n");
        }
        char buf[PATH_MAX];

        ssize_t sl = snprintf(buf, sizeof buf, "%s.head", resolv_conf_d);
        if (sl < 0 || (size_t)sl > sizeof buf)
            log_line("snprintf failed appending resolv_conf_head; path too long?\n");
        else
            resolv_conf_head_fd = open(buf, O_RDONLY|O_CLOEXEC, 0);

        sl = snprintf(buf, sizeof buf, "%s.tail", resolv_conf_d);
        if (sl < 0 || (size_t)sl > sizeof buf)
            log_line("snprintf failed appending resolv_conf_tail; path too long?\n");
        else
            resolv_conf_tail_fd = open(buf, O_RDONLY|O_CLOEXEC, 0);

        memset(buf, '\0', sizeof buf);
    }
    memset(resolv_conf_d, '\0', sizeof resolv_conf_d);
}

void ifch_main(void)
{
    prctl(PR_SET_NAME, "ndhc: ifch");
    umask(077);
    setup_signals_subprocess();
    setup_resolv_conf();

    nk_set_chroot(chroot_dir);
    memset(chroot_dir, '\0', sizeof chroot_dir);
    unsigned char keepcaps[] = { CAP_NET_ADMIN };
    nk_set_uidgid(ifch_uid, ifch_gid, keepcaps, sizeof keepcaps);
    do_ifch_work();
}

