// Copyright 2003-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_EXEC_H_
#define NCM_EXEC_H_

struct nk_exec_env
{
    char *env[32];
    char envbuf[4096];
};

int nk_generate_env(struct nk_exec_env *xe, uid_t uid, const char *chroot_path, const char *path_var);
void nk_generate_env_print_error(int err);
void __attribute__((noreturn))
    nk_execute(const char *command, const char *args, char * const envp[]) ;

#endif


