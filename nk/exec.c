// Copyright 2003-2018 Nicholas J. Kain <njkain at gmail dot com>
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
#include "nk/exec.h"

#define DEFAULT_ROOT_PATH "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
#define DEFAULT_PATH "/bin:/usr/bin:/usr/local/bin"
#define MAX_ARGS 256
#define MAX_ARGBUF 4096

#define NK_GEN_ENV(GEN_STR, ...) do { \
        if (env_offset >= envlen) return -3; \
        ssize_t snlen = snprintf(envbuf, envbuflen, GEN_STR "0", __VA_ARGS__); \
        if (snlen < 0 || (size_t)snlen >= envbuflen) return -2; \
        if (snlen > 0) envbuf[snlen-1] = 0; \
        env[env_offset++] = envbuf; envbuf += snlen; envbuflen -= (size_t)snlen; \
    } while (0)

/*
 * uid: userid of the user account that the environment will constructed for
 * chroot_path: path where the environment will be chrooted or NULL if no chroot
 * path_var: value of the PATH variable in the environment or defaults if NULL
 * env: array of character pointers that will be filled in with the new environment
 * envlen: number of character pointers available in env; a terminal '0' ptr must be available
 * envbuf: character buffer that will be used for storing state associated with env
 * envbuflen: number of available characters in envbuf for use
 *
 * returns:
 * 0 on success
 * -1 if an account for uid does not exist
 * -2 if there is not enough space in envbuf for the generated environment
 * -3 if there is not enough space in env for the generated environment
 * -4 if chdir to homedir or rootdir failed
 * -5 if oom or i/o failed
 */
int nk_generate_env(uid_t uid, const char *chroot_path, const char *path_var,
                    char *env[], size_t envlen, char *envbuf, size_t envbuflen)
{
    char pw_strs[4096];
    struct passwd pw_s;
    struct passwd *pw;
    char *pw_buf = NULL;
    int ret = 0, pwr;

getpwagain0:
    pwr = getpwuid_r(uid, &pw_s, pw_strs, sizeof pw_strs, &pw);
    if (pw == NULL) {
        if (pwr == 0) { ret = -1; goto out; }
        if (pwr == EINTR) goto getpwagain0;
        if (pwr == ERANGE) {
            size_t pwlen = (sizeof pw_strs >> 1) * 3;
            for (;;) {
                if (pw_buf) free(pw_buf);
                pw_buf = malloc(pwlen);
                if (!pw_buf) { ret = -5; goto out; }
getpwagain:
                pwr = getpwuid_r(uid, &pw_s, pw_buf, pwlen, &pw);
                if (pw == NULL) {
                    if (pwr == 0) { ret = -1; goto out; }
                    if (pwr == EINTR) goto getpwagain;
                    if (pwr == ERANGE) {
                        size_t oldpwlen = pwlen;
                        pwlen = (pwlen >> 1) * 3;
                        if (pwlen > oldpwlen) continue;
                        else { // overflowed
                            ret = -5; goto out;
                        }
                    }
                    ret = -5; goto out;
                }
                break; // the pwr != 0 check below applies here
            }
        }
        ret = -5; goto out;
    }
    if (pwr != 0) { ret = -5; goto out; }

    size_t env_offset = 0;
    if (envlen-- < 1) { // So we don't have to account for the terminal NULL
        ret = -3;
        goto out;
    }

    NK_GEN_ENV("UID=%i", uid);
    NK_GEN_ENV("USER=%s", pw->pw_name);
    NK_GEN_ENV("USERNAME=%s", pw->pw_name);
    NK_GEN_ENV("LOGNAME=%s", pw->pw_name);
    NK_GEN_ENV("HOME=%s", pw->pw_dir);
    NK_GEN_ENV("SHELL=%s", pw->pw_shell);
    NK_GEN_ENV("PATH=%s", path_var ? path_var : (uid > 0 ? DEFAULT_PATH : DEFAULT_ROOT_PATH));
    NK_GEN_ENV("PWD=%s", !chroot_path ? pw->pw_dir : "/");
    if (chroot_path && chroot(chroot_path)) { ret = -4; goto out; }
    if (chdir(chroot_path ? chroot_path : "/")) { ret = -4; goto out; }

    env[env_offset] = 0;
out:
    free(pw_buf);
    return ret;
}

#define NK_GEN_ARG(GEN_STR, ...) do { \
        ssize_t snlen = snprintf(argbuf, argbuflen, GEN_STR "0", __VA_ARGS__); \
        if (snlen < 0 || (size_t)snlen >= argbuflen) { \
            static const char errstr[] = "nk_execute: constructing argument list failed\n"; \
            write(STDERR_FILENO, errstr, sizeof errstr); \
            _Exit(EXIT_FAILURE); \
        } \
        if (snlen > 0) argbuf[snlen-1] = 0; \
        argv[curv] = argbuf; argv[++curv] = (char *)0; \
        argbuf += snlen; argbuflen -= (size_t)snlen; \
    } while (0)

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif
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
                    write(STDERR_FILENO, errstr, sizeof errstr);
                    _Exit(EXIT_FAILURE);
                }
                const size_t len = (size_t)(p - q);
                NK_GEN_ARG("%.*s", (int)len, q);
                q = p + 1;
                if (atend || curv >= (MAX_ARGS - 1))
                    break;
            }
        }
    }
    execve(command, argv, envp);
    {
        static const char errstr[] = "nk_execute: execve failed\n";
        write(STDERR_FILENO, errstr, sizeof errstr);
        _Exit(EXIT_FAILURE);
    }
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

