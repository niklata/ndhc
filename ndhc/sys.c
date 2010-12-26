#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include "config.h"
#include "log.h"
#include "pidfile.h"
#include "sys.h"

char pidfile[MAX_PATH_LENGTH] = PID_FILE_DEFAULT;

void background(void)
{
    static char called;
    if (!called && daemon(0, 0) == -1) {
        perror("fork");
        exit(EXIT_SUCCESS);
    }
    called = 1;  /* Do not fork again. */
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
