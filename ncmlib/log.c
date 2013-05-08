/* log.c - simple logging support
 * Time-stamp: <2010-11-12 05:19:46 njk>
 *
 * (c) 2003-2010 Nicholas J. Kain <njkain at gmail dot com>
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
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>

/* global logging flags */
int gflags_quiet = 0;
int gflags_detach = 1;
char *gflags_log_name = NULL;

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

void log_line_l(int level, const char *format, ...)
{
    va_list argp;

    if (gflags_quiet)
        return;

    if (gflags_detach)
        log_syslog(level);
    else
        log_stdio();
}

void suicide(const char *format, ...)
{
    va_list argp;

    if (gflags_quiet)
        goto out;

    if (gflags_detach)
        log_syslog(LOG_ERR);
    else {
        log_stdio();
        perror(NULL);
    }
out:
    exit(EXIT_FAILURE);
}

#undef log_syslog
#undef log_stdio

