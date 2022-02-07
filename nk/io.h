// Copyright 2010-2015 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_IO_H_
#define NCM_IO_H_

#include <sys/socket.h>

ssize_t safe_read(int fd, char *buf, size_t len);
ssize_t safe_write(int fd, const char *buf, size_t len);
ssize_t safe_sendto(int fd, const char *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t safe_recv(int fd, char *buf, size_t len, int flags);
ssize_t safe_recvmsg(int fd, struct msghdr *msg, int flags);
int safe_ftruncate(int fd, off_t length);

#endif

