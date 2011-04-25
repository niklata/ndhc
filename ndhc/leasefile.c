/* leasefile.c - functions for writing the lease file
 * Time-stamp: <2011-04-25 01:02:26 njk>
 *
 * (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
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
            log_line("Failed to create lease file (%s)\n", leasefile);
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
            log_warning("Failed to truncate lease file.\n");
            return;
    }
    lseek(leasefilefd, 0, SEEK_SET);
    ret = safe_write(leasefilefd, ip, strlen(ip));
    if (ret == -1)
        log_warning("Failed to write ip to lease file.\n");
}
