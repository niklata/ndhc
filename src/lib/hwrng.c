/* hwrng.c - access to system CRNG
 *
 * Copyright 2013-2018 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "nk/hwrng.h"
#include "nk/log.h"
#include "nk/io.h"

#ifdef NK_USE_GETRANDOM_SYSCALL
#include <sys/syscall.h>
#include <linux/random.h>
static bool nk_getrandom(char *seed, size_t len)
{
    size_t fetched = 0;
    while (fetched < len) {
        int r = syscall(SYS_getrandom, seed + fetched, len - fetched, 0);
        if (r <= 0) {
            if (r == 0) {
                // Failsafe to guard against infinite loops.
                log_warning("%s: getrandom() returned no entropy", __func__);
                return false;
            }
            if (errno == EINTR)
                continue;
            log_warning("%s: getrandom() failed: %s", __func__, strerror(errno));
            return false;
        }
        fetched += (size_t)r;
    }
    return true;
}
#else
static bool nk_getrandom(char *seed, size_t len)
{
    (void)seed;
    (void)len;
    return false;
}
#endif
static bool nk_get_rnd_clk(char *seed, size_t len)
{
    struct timespec ts;
    for (size_t i = 0; i < len; ++i) {
        int r = clock_gettime(CLOCK_REALTIME, &ts);
        if (r < 0) {
            log_warning("%s: Could not call clock_gettime(CLOCK_REALTIME): %s",
                        __func__, strerror(errno));
            return false;
        }
        char *p = (char *)&ts.tv_sec;
        char *q = (char *)&ts.tv_nsec;
        for (size_t j = 0; j < sizeof ts.tv_sec; ++j)
            seed[i] ^= p[j];
        for (size_t j = 0; j < sizeof ts.tv_nsec; ++j)
            seed[i] ^= q[j];
        // Force some scheduler jitter.
        static const struct timespec st = { .tv_sec=0, .tv_nsec=1 };
        nanosleep(&st, (struct timespec *)0);
    }
    return true;
}

static bool nk_get_urandom(char *seed, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        log_warning("%s: Could not open /dev/urandom: %s", __func__,
                    strerror(errno));
        return false;
    }
    bool ret = true;
    int r = safe_read(fd, seed, len);
    if (r < 0) {
        ret = false;
        log_warning("%s: Could not read /dev/urandom: %s",
                    __func__, strerror(errno));
    }
    close(fd);
    return ret;
}

void nk_get_hwrng(void *seed, size_t len)
{
    char *s = (char *)seed;
    if (nk_getrandom(s, len))
        return;
    if (nk_get_urandom(s, len))
        return;
    log_warning("%s: Seeding PRNG via system clock.  May be predictable.",
                __func__);
    if (nk_get_rnd_clk(s, len))
        return;
    suicide("%s: All methods to seed PRNG failed.  Exiting.", __func__);
}

