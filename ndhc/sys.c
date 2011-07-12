/* sys.c - linux-specific signal and epoll functions
 * Time-stamp: <2011-03-30 23:40:33 nk>
 *
 * (c) 2010-2011 Nicholas J. Kain <njkain at gmail dot com>
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

void setup_signals(struct client_state_t *cs)
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
            setup_signals(cs);
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
