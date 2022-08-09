// Copyright 2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_PSPAWN_H_
#define NCM_PSPAWN_H_

#include <sys/types.h>
#include <spawn.h>

int nk_pspawn(pid_t *pid, const char *command,
          const posix_spawn_file_actions_t *file_actions,
          const posix_spawnattr_t *attrp,
          const char *args, char * const envp[]);

#endif

