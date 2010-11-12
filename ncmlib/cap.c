/* cap.c - POSIX capability support
 * Time-stamp: <2010-11-12 09:01:07 njk>
 *
 * (c) 2004-2010 Nicholas J. Kain <njkain at gmail dot com>
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
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "log.h"

void set_cap(uid_t uid, gid_t gid, char *captxt)
{
    cap_t caps;

    if (!captxt)
        suicide("FATAL - set_cap: captxt == NULL");

    if (prctl(PR_SET_KEEPCAPS, 1))
        suicide("FATAL - set_cap: prctl() failed");

    if (setgroups(0, NULL) == -1)
        suicide("FATAL - set_cap: setgroups() failed");

    if (setegid(gid) == -1 || seteuid(uid) == -1)
        suicide("FATAL - set_cap: seteuid() failed");

    caps = cap_from_text(captxt);
    if (!caps)
        suicide("FATAL - set_cap: cap_from_text() failed");

    if (cap_set_proc(caps) == -1)
        suicide("FATAL - set_cap: cap_set_proc() failed");

    cap_free(caps);
}
