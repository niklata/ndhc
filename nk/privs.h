// Copyright 2005-2014 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_PRIVS_H_
#define NCM_PRIVS_H_

#include <unistd.h>
#ifdef __linux__
#include <sys/capability.h>
#endif

void nk_set_chroot(const char *chroot_dir);
void nk_set_uidgid(uid_t uid, gid_t gid, const unsigned char *caps,
                   size_t caplen);
uid_t nk_uidgidbyname(const char *username, uid_t *uid, gid_t *gid);
gid_t nk_gidbyname(const char *groupname, gid_t *gid);

#endif

