/* leasefile.c - functions for writing the lease file
 *
 * Copyright (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
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
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "log.h"
#include "strl.h"
#include "io.h"
#include "defines.h"

static char leasefile[PATH_MAX] = "\0";
static int leasefilefd = -1;

void set_leasefile(char *lf)
{
    strlcpy(leasefile, lf, sizeof leasefile);
}

void open_leasefile()
{
    if (strlen(leasefile) > 0) {
        leasefilefd = open(leasefile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
        if (leasefilefd < 0) {
            log_line("Failed to create lease file (%s).", leasefile);
            exit(EXIT_FAILURE);
        }
    }
}

void write_leasefile(struct in_addr ipnum)
{
    char ip[INET_ADDRSTRLEN+2];
    int ret;
    if (leasefilefd < 0)
        return;
    inet_ntop(AF_INET, &ipnum, ip, sizeof ip);
    strlcat(ip, "\n", sizeof ip);
  retry_trunc:
    ret = ftruncate(leasefilefd, 0);
    switch (ret) {
        default: break;
        case -1:
            if (errno == EINTR)
                goto retry_trunc;
            log_warning("Failed to truncate lease file.");
            return;
    }
    lseek(leasefilefd, 0, SEEK_SET);
    ret = safe_write(leasefilefd, ip, strlen(ip));
    if (ret == -1)
        log_warning("Failed to write ip to lease file.");
    else
        fsync(leasefilefd);
}
