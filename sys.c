// Copyright 2010-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include "nk/log.h"
#include "ndhc.h"
#include "sys.h"

long long IMPL_curms(const char *parent_function)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        suicide("%s: (%s) clock_gettime failed: %s",
                client_config.interface, parent_function, strerror(errno));
    }
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void setup_signals_subprocess(void)
{
    sigset_t mask;
    if (sigprocmask(0, 0, &mask) < 0)
        suicide("sigprocmask failed");
    if (sigaddset(&mask, SIGPIPE))
        suicide("sigaddset failed");
    if (sigprocmask(SIG_SETMASK, &mask, (sigset_t *)0) < 0)
        suicide("sigprocmask failed");
}

