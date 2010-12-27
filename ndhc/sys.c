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
        called = 1;  /* Do not fork again. */
        if (daemon(0, 0) == -1) {
            perror("fork");
            exit(EXIT_SUCCESS);
        }
        if (cs)
            setup_signals(cs);
    }
    if (file_exists(pidfile, "w") == -1) {
        log_line("cannot open pidfile for write!");
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

