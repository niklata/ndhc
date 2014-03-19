/* leasefile.c - functions for writing the lease file
 *
 * Copyright (c) 2011-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#include "leasefile.h"
#include "ndhc.h"
#include "log.h"
#include "strl.h"
#include "io.h"
#include "defines.h"

static int leasefilefd = -1;

static void get_leasefile_path(char *leasefile, size_t dlen, char *ifname)
{
    int splen = snprintf(leasefile, sizeof dlen, "%s/LEASE-%s",
                         state_dir, ifname);
    if (splen < 0) {
        log_line("%s: (%s) snprintf failed; return=%d",
                 client_config.interface, __func__, splen);
        exit(EXIT_FAILURE);
    }
    if ((size_t)splen >= sizeof dlen) {
        log_line("%s: (%s) snprintf dest buffer too small %d >= %u",
                 client_config.interface, __func__, splen, sizeof dlen);
        exit(EXIT_FAILURE);
    }
}

void open_leasefile(void)
{
    char leasefile[PATH_MAX];
    get_leasefile_path(leasefile, sizeof leasefile, client_config.interface);
    leasefilefd = open(leasefile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (leasefilefd < 0) {
        log_line("%s: Failed to create lease file '%s': %s",
                 client_config.interface, leasefile, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void write_leasefile(struct in_addr ipnum)
{
    char ip[INET_ADDRSTRLEN+2];
    int ret;
    if (leasefilefd < 0)
        return;
    inet_ntop(AF_INET, &ipnum, ip, sizeof ip);
    strnkcat(ip, "\n", sizeof ip);
  retry_trunc:
    ret = ftruncate(leasefilefd, 0);
    switch (ret) {
        default: break;
        case -1:
            if (errno == EINTR)
                goto retry_trunc;
            log_warning("%s: Failed to truncate lease file: %s",
                        client_config.interface, strerror(errno));
            return;
    }
    lseek(leasefilefd, 0, SEEK_SET);
    ret = safe_write(leasefilefd, ip, strlen(ip));
    if (ret == -1)
        log_warning("%s: Failed to write ip to lease file.",
                    client_config.interface);
    else
        fsync(leasefilefd);
}

