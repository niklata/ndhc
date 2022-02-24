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
#include "nk/log.h"
#include "nk/io.h"
#include "nk/exec.h"
#include "scriptd.h"
#include "ndhc.h"
#include "sys.h"

#define MAX_ENVBUF 2048
#define MAX_CENV 50

bool valid_script_file = false;

// Runs the 'script_file'-specified script.  Called from ndhc process.
void request_scriptd_run(void)
{
    if (!valid_script_file) return;

    static char buf[] = "\n";
    ssize_t r = safe_write(scriptdSock[0], buf, 1);
    if (r < 0 || (size_t)r != 1)
        suicide("%s: (%s) write failed: %zd", client_config.interface,
                __func__, r);
}

static void run_script(void)
{
    char *env[MAX_CENV];
    char envbuf[MAX_ENVBUF];
    switch ((int)fork()) {
        case 0: {
            int r = nk_generate_env(0, NULL, NULL, env, MAX_CENV, envbuf, sizeof envbuf);
            if (r < 0) {
                static const char errstr[] = "exec: failed to generate environment - ";
                safe_write(STDERR_FILENO, errstr, sizeof errstr);
                static const char errstr0[] = "(?) unknown error";
                static const char errstr1[] = "(-1) account for uid does not exist";
                static const char errstr2[] = "(-2) not enough space in envbuf";
                static const char errstr3[] = "(-3) not enough space in env";
                static const char errstr4[] = "(-4) chdir to homedir or rootdir failed";
                switch (r) {
                default: safe_write(STDERR_FILENO, errstr0, sizeof errstr0); break;
                case -1: safe_write(STDERR_FILENO, errstr1, sizeof errstr1); break;
                case -2: safe_write(STDERR_FILENO, errstr2, sizeof errstr2); break;
                case -3: safe_write(STDERR_FILENO, errstr3, sizeof errstr3); break;
                case -4: safe_write(STDERR_FILENO, errstr4, sizeof errstr4); break;
                }
                safe_write(STDERR_FILENO, "\n", 1);
                exit(EXIT_FAILURE);
            }
            nk_execute(script_file, NULL, env);
        }
        case -1: {
            static const char errstr[] = "exec: fork failed\n";
            safe_write(STDERR_FILENO, errstr, sizeof errstr);
            exit(EXIT_FAILURE);
        }
        default: break;
    }
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

    run_script();
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
    if (signo == SIGCHLD) {
        while (waitpid(-1, NULL, WNOHANG) > 0);
    } else if (signo == SIGINT || signo == SIGTERM) {
        _exit(EXIT_FAILURE);
    }
    errno = serrno;
}

static void setup_signals_scriptd(void)
{
    static const int ss[] = {
        SIGCHLD, SIGINT, SIGTERM, SIGKILL
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
    do_scriptd_work();
}


