/* seccomp.h - seccomp syscall filters for ndhc
 *
 * Copyright (c) 2012-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdbool.h>
#include "log.h"
#include "seccomp-bpf.h"

bool seccomp_enforce = false;

int enforce_seccomp_ndhc(void)
{
    if (!seccomp_enforce)
        return 0;
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(setsockopt),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(bind),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(getsockname),

        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(clock_gettime),

        // These are for 'write_leasefile()'
        ALLOW_SYSCALL(ftruncate),
        ALLOW_SYSCALL(lseek),
        ALLOW_SYSCALL(fsync),

        // These are for 'background()'
        ALLOW_SYSCALL(socketpair),
        ALLOW_SYSCALL(clone),
        ALLOW_SYSCALL(set_robust_list),
        ALLOW_SYSCALL(setsid),
        ALLOW_SYSCALL(chdir),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(dup2),
        ALLOW_SYSCALL(rt_sigprocmask),
        ALLOW_SYSCALL(signalfd4),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof filter / sizeof filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    log_line("ndhc seccomp filter installed.  Please disable seccomp if you encounter problems.");
    return 0;
}

int enforce_seccomp_ifch(void)
{
    if (!seccomp_enforce)
        return 0;
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(sendto),
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(fsync),
        ALLOW_SYSCALL(lseek),
        ALLOW_SYSCALL(truncate),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(unlink),
        ALLOW_SYSCALL(bind),
        ALLOW_SYSCALL(chmod),

        ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(clock_gettime),

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof filter / sizeof filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    log_line("ndhc-ifch seccomp filter installed.  Please disable seccomp if you encounter problems.");
    return 0;
}

