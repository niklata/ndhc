// Copyright 2003-2016 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_EXEC_H_
#define NCM_EXEC_H_

int nk_generate_env(uid_t uid, const char *chroot_path, const char *path_var,
                    char *env[], size_t envlen, char *envbuf, size_t envbuflen);
void __attribute__((noreturn))
    nk_execute(const char *command, const char *args, char * const envp[]) ;

#endif


