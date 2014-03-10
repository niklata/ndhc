/* sys.c - linux-specific signal and epoll functions
 *
 * Copyright (c) 2010-2011 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include "config.h"
#include "log.h"
#include "pidfile.h"
#include "sys.h"

char pidfile[MAX_PATH_LENGTH] = PID_FILE_DEFAULT;

void setup_signals_ndhc(struct client_state_t *cs)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");
    if (cs->signalFd >= 0) {
        epoll_del(cs, cs->signalFd);
        close(cs->signalFd);
    }
    cs->signalFd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (cs->signalFd < 0)
        suicide("signalfd failed");
    epoll_add(cs, cs->signalFd);
}

// @cs can be NULL
void background(struct client_state_t *cs)
{
    static char called;
    if (!called) {
        called = 1;  // Do not fork again.
        if (daemon(0, 0) == -1) {
            perror("fork");
            exit(EXIT_SUCCESS);
        }
        if (cs)
            setup_signals_ndhc(cs);
    }
    if (file_exists(pidfile, "w") == -1) {
        log_line("Cannot open pidfile for write!");
    } else
        write_pid(pidfile);
}

void epoll_add(struct client_state_t *cs, int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(cs->epollFd, EPOLL_CTL_ADD, fd, &ev);
    if (r == -1)
        suicide("epoll_add failed %s", strerror(errno));
}

void epoll_del(struct client_state_t *cs, int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(cs->epollFd, EPOLL_CTL_DEL, fd, &ev);
    if (r == -1)
        suicide("epoll_del failed %s", strerror(errno));
}
