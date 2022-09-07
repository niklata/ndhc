// Copyright 2010-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_IO_H_
#define NCM_IO_H_

#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>

ssize_t safe_read(int fd, char *buf, size_t len);
// Same as above, but will only call read one time.
// Meant to be used with a blocking fd where we need <= len bytes.
static inline ssize_t safe_read_once(int fd, char *buf, size_t len)
{
    if (len > SSIZE_MAX) len = SSIZE_MAX;
    ssize_t r;
    for (;;) {
        r = read(fd, buf, len);
        if (r >= 0 || errno != EINTR) break;
    }
    return r;
}

ssize_t safe_write(int fd, const char *buf, size_t len);
ssize_t safe_sendto(int fd, const char *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t safe_recv(int fd, char *buf, size_t len, int flags);
// Same as above, but will only call read one time.
// Meant to be used with a blocking fd where we need <= len bytes.
static inline ssize_t safe_recv_once(int fd, char *buf, size_t len, int flags)
{
    if (len > SSIZE_MAX) len = SSIZE_MAX;
    ssize_t r;
    for (;;) {
        r = recv(fd, buf, len, flags);
        if (r >= 0 || errno != EINTR) break;
    }
    return r;
}

static inline ssize_t safe_recvmsg(int fd, struct msghdr *msg, int flags)
{
    ssize_t r;
    for (;;) {
        r = recvmsg(fd, msg, flags);
        if (r >= 0 || errno != EINTR) break;
    }
    return r;
}
static inline int safe_ftruncate(int fd, off_t length)
{
    int r;
    for (;;) {
        r = ftruncate(fd, length);
        if (!r || errno != EINTR) break;
    }
    return r;
}

#endif

