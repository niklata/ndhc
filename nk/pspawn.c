// Copyright 2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "nk/pspawn.h"
#include "nk/io.h"

#define MAX_ARGS 256
#define MAX_ARGBUF 16384

#define NK_GEN_ARG(STRVAL, STRLEN) do { \
        size_t SL = (STRLEN); \
        if (argbuflen < SL + 1) { \
            static const char errstr[] = "nk_pspawn: argument list too long\n"; \
            safe_write(STDERR_FILENO, errstr, sizeof errstr); \
            _Exit(EXIT_FAILURE); \
        } \
        memcpy(argbuf, (STRVAL), SL); \
        argbuf[SL] = 0; \
        argv[curv] = argbuf; argv[++curv] = NULL; \
        argbuf += SL + 1; argbuflen -= SL + 1; \
    } while (0)

int nk_pspawn(pid_t *pid, const char *command,
          const posix_spawn_file_actions_t *restrict file_actions,
          const posix_spawnattr_t *restrict attrp,
          const char *args, char * const envp[])
{
    char *argv[MAX_ARGS];
    char argbuf_s[MAX_ARGBUF];
    char *argbuf = argbuf_s;
    size_t curv = 0;
    size_t argbuflen = sizeof argbuf_s;

    if (!command)
        _Exit(EXIT_SUCCESS);

    // strip the path from the command name and set argv[0]
    const char *p = strrchr(command, '/');
    {
        const char *q = p ? p + 1 : command;
        size_t ql = strlen(q);
        NK_GEN_ARG(q, ql);
    }

    if (args) {
        p = args;
        const char *q = args;
        bool atend = false;
        for (;; ++p) {
            if (*p == '\0') {
                atend = true;
            } else if (*p != ' ')
                continue;
            if (p == q) break;
            // Push an argument.
            if (q > p) {
                static const char errstr[] = "nk_execute: argument length too long\n";
                safe_write(STDERR_FILENO, errstr, sizeof errstr);
                _Exit(EXIT_FAILURE);
            }
            NK_GEN_ARG(q, (size_t)(p - q));
            q = p + 1;
            if (atend || curv >= (MAX_ARGS - 1))
                break;
        }
    }
    return posix_spawn(pid, command, file_actions, attrp, argv, envp);
}

