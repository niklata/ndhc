/* chroot.c - chroots jobs and drops privs
 *
 * (c) 2005-2013 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include "defines.h"
#include "log.h"
#include "strl.h"

static char chrootd[MAX_PATH_LENGTH] = "\0";
static char chroot_modified;
static char chroot_enable = 1;

void disable_chroot(void)
{
    chroot_enable = 0;
}

int chroot_enabled(void)
{
    return chroot_enable;
}

void update_chroot(const char *path)
{
    strnkcpy(chrootd, path, sizeof chrootd);
    chroot_modified = 1;
}

int chroot_exists(void)
{
    return chroot_modified;
}

char *get_chroot(void)
{
    return chrootd;
}

void wipe_chroot(void)
{
    memset(chrootd, '\0', sizeof chrootd);
}

void imprison(const char *chroot_dir)
{
    if (chdir(chroot_dir)) {
        log_line("Failed to chdir(%s)!", chroot_dir);
        exit(EXIT_FAILURE);
    }
    if (!chroot_enable)
        return;
    if (chroot(chroot_dir)) {
        log_line("Failed to chroot(%s)!", chroot_dir);
        exit(EXIT_FAILURE);
    }
}

void drop_root(uid_t uid, gid_t gid)
{
    if (uid == 0 || gid == 0) {
        log_line("FATAL - drop_root: attempt to drop root to root?\n");
        exit(EXIT_FAILURE);
    }

    if (getgid() == 0) {
        if (setregid(gid, gid) == -1) {
            log_line("FATAL - drop_root: failed to drop real gid == root!\n");
            exit(EXIT_FAILURE);
        }
    }

    if (getuid() == 0) {
        if (setreuid(uid, uid) == -1) {
            log_line("FATAL - drop_root: failed to drop real uid == root!\n");
            exit(EXIT_FAILURE);
        }
    }

    /* be absolutely sure */
    if (getgid() == 0 || getuid() == 0) {
        log_line("FATAL - drop_root: tried to drop root, but still have root!\n");
        exit(EXIT_FAILURE);
    }
}

