/* io.c - light wrappers for POSIX i/o functions
 *
 * Copyright 2010-2018 Nicholas J. Kain <njkain at gmail dot com>
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
#include <sys/types.h>
#include <errno.h>
#include "nk/io.h"
#include <limits.h>

// POSIX says read/write/etc() with len param > SSIZE_MAX is implementation defined.
// So we avoid implementation-defined behavior with the bounding in each safe_* fn.

/* returns -1 on error, >= 0 and equal to # chars read on success */
ssize_t safe_read(int fd, char *buf, size_t len)
{
    size_t s = 0;
    if (len > SSIZE_MAX) len = SSIZE_MAX;
    while (s < len) {
        ssize_t r = read(fd, buf + s, len - s);
        if (r == 0)
            break;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            else if ((errno == EAGAIN || errno == EWOULDBLOCK) && s > 0)
                return (ssize_t)s;
            else
                return -1;
        }
        s += (size_t)r;
    }
    return (ssize_t)s;
}

/* returns -1 on error, >= 0 and equal to # chars written on success */
ssize_t safe_write(int fd, const char *buf, size_t len)
{
    size_t s = 0;
    if (len > SSIZE_MAX) len = SSIZE_MAX;
    while (s < len) {
        ssize_t r = write(fd, buf + s, len - s);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            else if ((errno == EAGAIN || errno == EWOULDBLOCK) && s > 0)
                return (ssize_t)s;
            else
                return -1;
        }
        s += (size_t)r;
    }
    return (ssize_t)s;
}

/* returns -1 on error, >= 0 and equal to # chars written on success */
ssize_t safe_sendto(int fd, const char *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen)
{
    size_t s = 0;
    if (len > SSIZE_MAX) len = SSIZE_MAX;
    while (s < len) {
        ssize_t r = sendto(fd, buf + s, len - s, flags, dest_addr, addrlen);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            else if ((errno == EAGAIN || errno == EWOULDBLOCK) && s > 0)
                return (ssize_t)s;
            else
                return -1;
        }
        s += (size_t)r;
    }
    return (ssize_t)s;
}

ssize_t safe_recv(int fd, char *buf, size_t len, int flags)
{
    size_t s = 0;
    if (len > SSIZE_MAX) len = SSIZE_MAX;
    while (s < len) {
        ssize_t r = recv(fd, buf + s, len - s, flags);
        if (r == 0)
            break;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            else if ((errno == EAGAIN || errno == EWOULDBLOCK) && s > 0)
                return (ssize_t)s;
            else
                return -1;
        }
        s += (size_t)r;
    }
    return (ssize_t)s;
}

ssize_t safe_recvmsg(int fd, struct msghdr *msg, int flags)
{
    ssize_t r;
  retry:
    r = recvmsg(fd, msg, flags);
    if (r < 0 && errno == EINTR)
        goto retry;
    return r;
}

