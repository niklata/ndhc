// Copyright 2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "nk/log.h"
#include "nk/io.h"
#include "nk/pspawn.h"
#include "scriptd.h"
#include "ndhc.h"
#include "sys.h"

extern char **environ;
bool valid_script_file = false;

// Runs the 'script_file'-specified script.  Called from ndhc process.
// Blocks until the script finishes running.
void request_scriptd_run(void)
{
    if (!valid_script_file) return;

    char nl = '\n';
    ssize_t r = safe_write(scriptdSock[0], &nl, 1);
    if (r < 0 || (size_t)r != 1)
        suicide("%s: (%s) write failed: %zd", client_config.interface,
                __func__, r);
    char buf[16];
    r = safe_recv_once(scriptdSock[0], buf, sizeof buf, 0);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0) {
        suicide("%s: (%s) recvmsg failed: %s", client_config.interface,
                __func__, strerror(errno));
    }
    if (r != 1 || buf[0] != '+')
        suicide("%s: Bad response from recv", __func__);
}

static void process_client_socket(void)
{
    static char buf[32];
    static size_t buflen;

    if (buflen == sizeof buf)
        suicide("%s: (%s) receive buffer exhausted", client_config.interface,
                __func__);

    int r = safe_recv(scriptdSock[1], buf + buflen, sizeof buf - buflen,
                      MSG_DONTWAIT);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        suicide("%s: (%s) error reading from ndhc -> scriptd socket: %s",
                client_config.interface, __func__, strerror(errno));
    }
    buflen += (size_t)r;
    if (buflen > 1 || buf[0] != '\n') exit(EXIT_SUCCESS);
    buflen = 0;

    pid_t pid;
    int ret = nk_pspawn(&pid, script_file, NULL, NULL, NULL, environ);
    if (ret) log_line("posix_spawn failed for '%s': %s\n", script_file, strerror(ret));
    int wstatus;
    ret = waitpid(pid, &wstatus, 0);
    if (ret == -1)
        suicide("%s: (%s) waitpid failed: %s", client_config.interface,
                __func__, strerror(errno));

    char c = '+';
    ssize_t rs = safe_write(scriptdSock[1], &c, 1);
    if (rs == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (rs < 0)
        suicide("%s: (%s) error writing to scriptd -> ndhc socket: %s",
                client_config.interface, __func__, strerror(errno));
}

static void do_scriptd_work(void)
{
    struct pollfd pfds[2] = {0};
    pfds[0].fd = scriptdSock[1];
    pfds[0].events = POLLIN|POLLHUP|POLLERR|POLLRDHUP;
    pfds[1].fd = scriptdStream[1];
    pfds[1].events = POLLHUP|POLLERR|POLLRDHUP;

    for (;;) {
        if (poll(pfds, 2, -1) < 0) {
            if (errno != EINTR) suicide("poll failed");
        }
        if (pfds[0].revents & POLLIN) {
            process_client_socket();
        }
        if (pfds[0].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
            suicide("scriptdSock closed unexpectedly");
        }
        if (pfds[1].revents & (POLLHUP|POLLERR|POLLRDHUP)) {
            exit(EXIT_SUCCESS);
        }
    }
}

static void signal_handler(int signo)
{
    int serrno = errno;
    if (signo == SIGINT || signo == SIGTERM) {
        _exit(EXIT_FAILURE);
    }
    errno = serrno;
}

static void setup_signals_scriptd(void)
{
    static const int ss[] = {
        SIGINT, SIGTERM, SIGKILL
    };
    sigset_t mask;
    if (sigprocmask(0, 0, &mask) < 0)
        suicide("sigprocmask failed");
    for (int i = 0; ss[i] != SIGKILL; ++i)
        if (sigdelset(&mask, ss[i]))
            suicide("sigdelset failed");
    if (sigaddset(&mask, SIGPIPE))
        suicide("sigaddset failed");
    if (sigprocmask(SIG_SETMASK, &mask, (sigset_t *)0) < 0)
        suicide("sigprocmask failed");

    struct sigaction sa = {
        .sa_handler = signal_handler,
        .sa_flags = SA_RESTART|SA_NOCLDWAIT,
    };
    if (sigemptyset(&sa.sa_mask))
        suicide("sigemptyset failed");
    for (int i = 0; ss[i] != SIGKILL; ++i)
        if (sigaction(ss[i], &sa, NULL))
            suicide("sigaction failed");
}

void scriptd_main(void)
{
    assert(valid_script_file);
    prctl(PR_SET_NAME, "ndhc: scriptd");
    umask(077);
    setup_signals_scriptd();
    fcntl(scriptdSock[1], F_SETFD, FD_CLOEXEC);
    fcntl(scriptdStream[1], F_SETFD, FD_CLOEXEC);
    do_scriptd_work();
}


