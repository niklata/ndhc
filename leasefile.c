// Copyright 2011-2018 Nicholas J. Kain <njkain at gmail dot com>
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
#include "nk/stb_sprintf.h"
#include "nk/log.h"
#include "nk/io.h"
#include "leasefile.h"
#include "ndhc.h"
#include "scriptd.h"

static int leasefilefd = -1;

static void get_leasefile_path(char *leasefile, size_t dlen, char *ifname)
{
    int splen = stbsp_snprintf(leasefile, dlen, "%s/LEASE-%s",
                               state_dir, ifname);
    if (splen < 0 || (size_t)splen > dlen)
        suicide("%s: (%s) snprintf failed; return=%d",
                client_config.interface, __func__, splen);
}

void open_leasefile(void)
{
    char leasefile[PATH_MAX];
    get_leasefile_path(leasefile, sizeof leasefile, client_config.interface);
    leasefilefd = open(leasefile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (leasefilefd < 0)
        suicide("%s: (%s) Failed to create lease file '%s': %s",
                client_config.interface, __func__, leasefile, strerror(errno));
}

static void do_write_leasefile(struct in_addr ipnum)
{
    char ip[INET_ADDRSTRLEN];
    char out[INET_ADDRSTRLEN*2];
    if (leasefilefd < 0) {
        log_line("%s: (%s) leasefile fd < 0; no leasefile will be written",
                 client_config.interface, __func__);
        return;
    }
    inet_ntop(AF_INET, &ipnum, ip, sizeof ip);
    ssize_t olen = stbsp_snprintf(out, sizeof out, "%s\n", ip);
    if (olen < 0 || (size_t)olen > sizeof ip) {
        log_line("%s: (%s) snprintf failed; return=%zd",
                 client_config.interface, __func__, olen);
        return;
    }
    if (safe_ftruncate(leasefilefd, 0)) {
        log_line("%s: (%s) Failed to truncate lease file: %s",
                 client_config.interface, __func__, strerror(errno));
        return;
    }
    if (lseek(leasefilefd, 0, SEEK_SET) == (off_t)-1) {
        log_line("%s: (%s) Failed to seek to start of lease file: %s",
                 client_config.interface, __func__, strerror(errno));
        return;
    }
    size_t outlen = strlen(out);
    ssize_t ret = safe_write(leasefilefd, out, outlen);
    if (ret < 0 || (size_t)ret != outlen)
        log_line("%s: (%s) Failed to write ip to lease file.",
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

