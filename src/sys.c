/* sys.c - linux-specific signal and epoll functions
 *
 * Copyright (c) 2010-2017 Nicholas J. Kain <njkain at gmail dot com>
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
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include "nk/log.h"
#include "nk/io.h"
#include "ndhc.h"
#include "sys.h"

void epoll_add(int epfd, int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    if (r < 0)
        suicide("epoll_add failed %s", strerror(errno));
}

void epoll_del(int epfd, int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
    if (r < 0)
        suicide("epoll_del failed %s", strerror(errno));
}

int setup_signals_subprocess(void)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (sfd < 0)
        suicide("signalfd failed");
    return sfd;
}

void signal_dispatch_subprocess(int sfd, const char pname[static 1])
{
    struct signalfd_siginfo si;
    memset(&si, 0, sizeof si);
    ssize_t r = safe_read(sfd, (char *)&si, sizeof si);
    if (r < 0) {
        log_error("%s: %s: error reading from signalfd: %s",
                  client_config.interface, pname, strerror(errno));
        return;
    }
    if ((size_t)r < sizeof si) {
        log_error("%s: %s: short read from signalfd: %zd < %zu",
                  client_config.interface, pname, r, sizeof si);
        return;
    }
    switch (si.ssi_signo) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP: exit(EXIT_SUCCESS); break;
        default: break;
    }
}

