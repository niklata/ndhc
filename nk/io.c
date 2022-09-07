// Copyright 2010-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include "nk/io.h"

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
