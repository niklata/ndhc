// Copyright 2005-2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#ifdef __linux__
#include <sys/capability.h>
#include <sys/prctl.h>
#endif
#include "nk/privs.h"
#include "nk/log.h"

void nk_set_chroot(const char *chroot_dir)
{
    if (chroot(chroot_dir))
        suicide("%s: chroot('%s') failed: %s", __func__, chroot_dir,
                strerror(errno));
    if (chdir("/"))
        suicide("%s: chdir('/') failed: %s", __func__, strerror(errno));
}

#ifdef NK_USE_CAPABILITY
static size_t nk_get_capability_vinfo(uint32_t *version)
{
    struct __user_cap_header_struct hdr;
    memset(&hdr, 0, sizeof hdr);
    if (capget(&hdr, (cap_user_data_t)0) < 0) {
        if (errno != EINVAL)
            suicide("%s: capget failed: %s", __func__, strerror(errno));
    }
    switch (hdr.version) {
    case _LINUX_CAPABILITY_VERSION_1:
         *version = _LINUX_CAPABILITY_VERSION_1;
        return _LINUX_CAPABILITY_U32S_1;
    case _LINUX_CAPABILITY_VERSION_2:
         *version = _LINUX_CAPABILITY_VERSION_2;
        return _LINUX_CAPABILITY_U32S_2;
    default: log_line("%s: unknown capability version %x, using %x",
                      __func__, *version, _LINUX_CAPABILITY_VERSION_3);
    case _LINUX_CAPABILITY_VERSION_3:
         *version = _LINUX_CAPABILITY_VERSION_3;
         return _LINUX_CAPABILITY_U32S_3;
    }
}
static void nk_set_no_new_privs(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        suicide("%s: prctl failed: %s", __func__, strerror(errno));
}
static size_t nk_set_capability_prologue(const unsigned char *caps,
                                         size_t caplen,
                                         uint32_t *cversion)
{
    if (!caps || !caplen)
        return 0;
    size_t csize = nk_get_capability_vinfo(cversion);
    if (prctl(PR_SET_KEEPCAPS, 1))
        suicide("%s: prctl failed: %s", __func__, strerror(errno));
    return csize;
}
static void nk_set_capability_epilogue(const unsigned char *caps,
                                       size_t caplen, uint32_t cversion,
                                       size_t csize)
{
    if (!caps || !caplen)
        return;
    struct __user_cap_header_struct hdr = {
        .version = cversion,
        .pid = 0,
    };
    struct __user_cap_data_struct data[csize];
    uint32_t mask[csize];
    memset(mask, 0, sizeof mask);
    for (size_t i = 0; i < caplen; ++i) {
        size_t j = caps[i] / 32;
        if (j >= csize)
            suicide("%s: caps[%zu] == %d, which is >= %zu and out of range",
                    __func__, i, caps[i], csize * 32);
        mask[j] |= (uint32_t)CAP_TO_MASK(caps[i] - 32 * j);
    }
    for (size_t i = 0; i < csize; ++i) {
        data[i].effective = mask[i];
        data[i].permitted = mask[i];
        data[i].inheritable = 0;
    }
    if (capset(&hdr, (cap_user_data_t)&data) < 0)
        suicide("%s: capset failed: %s", __func__, strerror(errno));
    nk_set_no_new_privs();
}
#else
static size_t nk_set_capability_prologue(const unsigned char *caps,
                                         size_t caplen,
                                         uint32_t *cversion)
{ (void)caps; (void)caplen; (void)cversion; return 0; }
static void nk_set_capability_epilogue(const unsigned char *caps,
                                       size_t caplen, uint32_t cversion,
                                       size_t csize)
{ (void)caps; (void)caplen; (void)cversion; (void)csize; }
#endif

void nk_set_uidgid(uid_t uid, gid_t gid, const unsigned char *caps,
                   size_t caplen)
{
    uint32_t cversion = 0;
    size_t csize = nk_set_capability_prologue(caps, caplen, &cversion);
    if (setgroups(1, &gid))
        suicide("%s: setgroups failed: %s", __func__, strerror(errno));
    if (setresgid(gid, gid, gid))
        suicide("%s: setresgid failed: %s", __func__, strerror(errno));
    if (setresuid(uid, uid, uid))
        suicide("%s: setresuid failed: %s", __func__, strerror(errno));
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid))
        suicide("%s: getresuid failed: %s", __func__, strerror(errno));
    if (ruid != uid || euid != uid || suid != uid)
        suicide("%s: getresuid failed; the OS or libc is broken", __func__);
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid))
        suicide("%s: getresgid failed: %s", __func__, strerror(errno));
    if (rgid != gid || egid != gid || sgid != gid)
        suicide("%s: getresgid failed; the OS or libc is broken", __func__);
    if (uid && setreuid((uid_t)-1, 0) == 0)
        suicide("%s: OS or libc broken; able to restore privs after drop",
                __func__);
    nk_set_capability_epilogue(caps, caplen, cversion, csize);
}

uid_t nk_uidgidbyname(const char *username, uid_t *uid, gid_t *gid)
{
    if (!username)
        return (uid_t)-1;
    struct passwd *pws = getpwnam(username);
    if (!pws) {
        for (size_t i = 0; username[i]; ++i) {
            if (!isdigit(username[i]))
                return (uid_t)-1;
        }
        char *p;
        long lt = strtol(username, &p, 10);
        if (errno == ERANGE && (lt == LONG_MIN || lt == LONG_MAX))
            return (uid_t)-1;
        if (lt < 0 || lt > (long)UINT_MAX)
            return (uid_t)-1;
        if (p == username)
            return (uid_t)-1;
        pws = getpwuid((uid_t)lt);
        if (!pws)
            return (uid_t)-1;
    }
    if (gid)
        *gid = pws->pw_gid;
    if (uid)
        *uid = pws->pw_uid;
    return (uid_t)0;
}

gid_t nk_gidbyname(const char *groupname, gid_t *gid)
{
    if (!groupname)
        return (gid_t)-1;
    struct group *grp = getgrnam(groupname);
    if (!grp) {
        for (size_t i = 0; groupname[i]; ++i) {
            if (!isdigit(groupname[i]))
                return (gid_t)-1;
        }
        char *p;
        long lt = strtol(groupname, &p, 10);
        if (errno == ERANGE && (lt == LONG_MIN || lt == LONG_MAX))
            return (gid_t)-1;
        if (lt < 0 || lt > (long)UINT_MAX)
            return (gid_t)-1;
        if (p == groupname)
            return (gid_t)-1;
        grp = getgrgid((gid_t)lt);
        if (!grp)
            return (gid_t)-1;
    }
    if (gid)
        return grp->gr_gid;
    return (gid_t)0;
}

