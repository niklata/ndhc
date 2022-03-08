// Copyright 2003-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include "nk/stb_sprintf.h"
#include "nk/exec.h"
#include "nk/io.h"

/*
 * Note that nk_generate_env is not async signal safe if chroot_path is not
 * NULL, so it should only be called after fork() in a non-multithreaded
 * process if chroot_path is ever non-NULL.
 *
 * I don't consider this to be a problem in general, since in a multithreaded process
 * it would be far better to fork off a subprocess early on before threads are
 * created and use a socketpair() to request subprocess creation from the
 * single-threaded subprocess from the multithreaded main program.
 */

#define DEFAULT_ROOT_PATH "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
#define DEFAULT_PATH "/bin:/usr/bin:/usr/local/bin"
#define MAX_ARGS 256
#define MAX_ARGBUF 16384
#define MAX_PWBUF 16384

#define NK_GEN_ENV(GEN_STR, ...) do { \
        if (env_offset >= envlen) return -3; \
        ssize_t snlen = stbsp_snprintf(envbuf, envbuflen, GEN_STR, __VA_ARGS__); \
        if (snlen < 0 || (size_t)snlen > envbuflen) return -2; \
        xe->env[env_offset++] = envbuf; envbuf += snlen; envbuflen -= (size_t)snlen; \
    } while (0)

/*
 * xe: contains generated env and backing buffer
 * uid: userid of the user account that the environment will constructed for
 * chroot_path: path where the environment will be chrooted or NULL if no chroot
 * path_var: value of the PATH variable in the environment or defaults if NULL
 *
 * returns:
 * 0 on success
 * -1 if an account for uid does not exist
 * -2 if there is not enough space in envbuf for the generated environment
 * -3 if there is not enough space in env for the generated environment
 * -4 if chdir to homedir or rootdir failed
 * -5 if oom or i/o failed
 * -6 if MAX_PWBUF is too small
 */
int nk_generate_env(struct nk_exec_env *xe, uid_t uid, const char *chroot_path, const char *path_var)
{
    char pwbuf[MAX_PWBUF];
    struct passwd pw_s, *pw;

    for (;;) {
        int r = getpwuid_r(uid, &pw_s, pwbuf, sizeof pwbuf, &pw);
        if (!r) {
            if (pw == NULL) return -1;
            break;
        } else {
            if (r == EINTR) continue;
            if (r == ERANGE) return -6;
            return -5;
        }
    }

    size_t env_offset = 0;
    size_t envlen = sizeof xe->env / sizeof xe->env[0];
    char *envbuf = xe->envbuf;
    size_t envbuflen = sizeof xe->envbuf;
    if (envlen-- < 1) return -3; // So we don't have to account for the terminal NULL

    NK_GEN_ENV("UID=%i", uid);
    NK_GEN_ENV("USER=%s", pw->pw_name);
    NK_GEN_ENV("USERNAME=%s", pw->pw_name);
    NK_GEN_ENV("LOGNAME=%s", pw->pw_name);
    NK_GEN_ENV("HOME=%s", pw->pw_dir);
    NK_GEN_ENV("SHELL=%s", pw->pw_shell);
    NK_GEN_ENV("PATH=%s", path_var ? path_var : (uid > 0 ? DEFAULT_PATH : DEFAULT_ROOT_PATH));
    NK_GEN_ENV("PWD=%s", !chroot_path ? pw->pw_dir : "/");
    if (chroot_path && chroot(chroot_path)) return -4;
    if (chdir(chroot_path ? chroot_path : "/")) return -4;

    xe->env[env_offset] = 0;
    return 0;
}

#define ERRSTR0 "exec: failed to generate environment - (?) unknown error\n"
#define ERRSTR1 "exec: failed to generate environment - (-1) account for uid does not exist\n"
#define ERRSTR2 "exec: failed to generate environment - (-2) not enough space in envbuf\n"
#define ERRSTR3 "exec: failed to generate environment - (-3) not enough space in env\n"
#define ERRSTR4 "exec: failed to generate environment - (-4) chdir to homedir or rootdir failed\n"
#define ERRSTR5 "exec: failed to generate environment - (-5) oom or i/o error\n"
#define ERRSTR6 "exec: failed to generate environment - (-6) MAX_PWBUF is too small\n"
void nk_generate_env_print_error(int err)
{
    switch (err) {
    default: safe_write(STDERR_FILENO, ERRSTR0, sizeof ERRSTR0); break;
    case -1: safe_write(STDERR_FILENO, ERRSTR1, sizeof ERRSTR1); break;
    case -2: safe_write(STDERR_FILENO, ERRSTR2, sizeof ERRSTR2); break;
    case -3: safe_write(STDERR_FILENO, ERRSTR3, sizeof ERRSTR3); break;
    case -4: safe_write(STDERR_FILENO, ERRSTR4, sizeof ERRSTR4); break;
    case -5: safe_write(STDERR_FILENO, ERRSTR5, sizeof ERRSTR5); break;
    case -6: safe_write(STDERR_FILENO, ERRSTR6, sizeof ERRSTR6); break;
    }
}
#undef ERRSTR0
#undef ERRSTR1
#undef ERRSTR2
#undef ERRSTR3
#undef ERRSTR4
#undef ERRSTR5
#undef ERRSTR6

#define NK_GEN_ARG(GEN_STR, ...) do { \
        ssize_t snlen = stbsp_snprintf(argbuf, argbuflen, GEN_STR, __VA_ARGS__); \
        if (snlen < 0 || (size_t)snlen > argbuflen) { \
            static const char errstr[] = "nk_execute: constructing argument list failed\n"; \
            safe_write(STDERR_FILENO, errstr, sizeof errstr); \
            _Exit(EXIT_FAILURE); \
        } \
        argv[curv] = argbuf; argv[++curv] = NULL; \
        argbuf += snlen; argbuflen -= (size_t)snlen; \
    } while (0)

void __attribute__((noreturn))
nk_execute(const char *command, const char *args, char * const envp[])
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
    NK_GEN_ARG("%s", p ? p + 1 : command);

    if (args) {
        p = args;
        const char *q = args;
        bool squote = false, dquote = false, atend = false;
        for (;; ++p) {
            switch (*p) {
            default: continue;
            case '\0':
                 atend = true;
                 goto endarg;
            case ' ':
                if (!squote && !dquote)
                    goto endarg;
                continue;
            case '\'':
                if (!dquote)
                    squote = !squote;
                continue;
            case '"':
                if (!squote)
                    dquote = !dquote;
                continue;
            }
endarg:
            {
                if (p == q) break;
                // Push an argument.
                if (q > p) {
                    static const char errstr[] = "nk_execute: argument length too long\n";
                    safe_write(STDERR_FILENO, errstr, sizeof errstr);
                    _Exit(EXIT_FAILURE);
                }
                NK_GEN_ARG("%.*s", (int)(p - q), q);
                q = p + 1;
                if (atend || curv >= (MAX_ARGS - 1))
                    break;
            }
        }
    }
    execve(command, argv, envp);
    {
        static const char errstr[] = "nk_execute: execve failed\n";
        safe_write(STDERR_FILENO, errstr, sizeof errstr);
        _Exit(EXIT_FAILURE);
    }
}

