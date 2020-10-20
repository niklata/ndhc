/* log.c - simple logging support
 *
 * Copyright 2003-2018 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdio.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include "nk/log.h"

/* global logging flags */
int gflags_quiet = 0;
int gflags_detach = 0;
int gflags_debug = 0;
char *gflags_log_name = 0;

#define log_syslog(level) do { \
    openlog(gflags_log_name, LOG_PID, LOG_DAEMON); \
    va_start(argp, format); \
    vsyslog(level | LOG_DAEMON, format, argp); \
    va_end(argp); \
    closelog(); } while(0)

#define log_stdio() do { \
    va_start(argp, format); \
    vfprintf(stderr, format, argp); \
    fprintf(stderr, "\n"); \
    va_end(argp); } while(0)

__attribute__ ((format (printf, 2, 3)))
void log_line_l(int level, const char format[static 1], ...)
{
    va_list argp;

    if (gflags_quiet)
        return;

    if (gflags_detach)
        log_syslog(level);
    else
        log_stdio();
}

__attribute__ ((format (printf, 1, 2)))
void __attribute__((noreturn)) suicide(const char format[static 1], ...)
{
    va_list argp;

    if (gflags_detach)
        log_syslog(LOG_ERR);
    else
        log_stdio();
    exit(EXIT_FAILURE);
}

#undef log_syslog
#undef log_stdio

