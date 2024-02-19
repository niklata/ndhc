// Copyright 2011-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "nk/log.h"
#include "nk/io.h"
#include "leasefile.h"
#include "ndhc.h"
#include "scriptd.h"

static int leasefilefd = -1;

static void get_leasefile_path(char *leasefile, size_t dlen, char *ifname)
{
    char *p = memccpy(leasefile, state_dir, 0, dlen);
    if (!p) suicide("%s: (%s) memccpy failed\n", client_config.interface, __func__);
    p = memccpy(p - 1, "/LEASE-", 0, dlen - (size_t)(p - leasefile - 1));
    if (!p) suicide("%s: (%s) memccpy failed\n", client_config.interface, __func__);
    p = memccpy(p - 1, ifname, 0, dlen - (size_t)(p - leasefile - 1));
    if (!p) suicide("%s: (%s) memccpy failed\n", client_config.interface, __func__);
}

void open_leasefile(void)
{
    char leasefile[PATH_MAX];
    get_leasefile_path(leasefile, sizeof leasefile, client_config.interface);
    leasefilefd = open(leasefile, O_WRONLY|O_CREAT|O_CLOEXEC, 0644);
    if (leasefilefd < 0)
        suicide("%s: (%s) Failed to create lease file '%s': %s\n",
                client_config.interface, __func__, leasefile, strerror(errno));
}

static void do_write_leasefile(struct in_addr ipnum)
{
    char ip[INET_ADDRSTRLEN];
    char out[INET_ADDRSTRLEN*2];
    if (leasefilefd < 0) {
        log_line("%s: (%s) leasefile fd < 0; no leasefile will be written\n",
                 client_config.interface, __func__);
        return;
    }
    inet_ntop(AF_INET, &ipnum, ip, sizeof ip);
    char *p = memccpy(out, ip, 0, sizeof out);
    if (!p) {
        log_line("%s: (%s) memccpy failed\n", client_config.interface, __func__);
        return;
    }
    p = memccpy(p - 1, "\n", 0, sizeof out - (size_t)(p - out - 1));
    if (!p) {
        log_line("%s: (%s) memccpy failed\n", client_config.interface, __func__);
        return;
    }
    size_t outlen = strlen(out);
    // Make sure that we're not overwriting the leasefile with an invalid
    // IP address.  This is a very minimal check.
    if (outlen < 7) return;
    if (safe_ftruncate(leasefilefd, 0)) {
        log_line("%s: (%s) Failed to truncate lease file: %s\n",
                 client_config.interface, __func__, strerror(errno));
        return;
    }
    if (lseek(leasefilefd, 0, SEEK_SET) == (off_t)-1) {
        log_line("%s: (%s) Failed to seek to start of lease file: %s\n",
                 client_config.interface, __func__, strerror(errno));
        return;
    }
    ssize_t ret = safe_write(leasefilefd, out, outlen);
    if (ret < 0 || (size_t)ret != outlen)
        log_line("%s: (%s) Failed to write ip to lease file.\n",
                 client_config.interface, __func__);
    else
        fsync(leasefilefd);
}

void write_leasefile(struct in_addr ipnum)
{
    do_write_leasefile(ipnum);
    request_scriptd_run();

    if (client_config.enable_s6_notify) {
        static char buf[] = "\n";
        safe_write(client_config.s6_notify_fd, buf, 1);
        close(client_config.s6_notify_fd);
        client_config.enable_s6_notify = false;
    }
}

