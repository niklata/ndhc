// Copyright 2013-2024 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/random.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "nk/hwrng.h"
#include "nk/log.h"
#include "nk/io.h"

static bool nk_getrandom(char *seed, size_t len)
{
    size_t fetched = 0;
    while (fetched < len) {
        size_t sz = len - fetched;
        if (sz > 256) sz = 256;
        int r = getentropy(seed + fetched, sz);
        if (r < 0) {
            log_line("%s: getrandom() failed: %s\n", __func__, strerror(errno));
            return false;
        }
        fetched += sz;
    }
    return true;
}

static bool nk_get_rnd_clk(char *seed, size_t len)
{
    struct timespec ts;
    for (size_t i = 0; i < len; ++i) {
        int r = clock_gettime(CLOCK_REALTIME, &ts);
        if (r < 0) {
            log_line("%s: Could not call clock_gettime(CLOCK_REALTIME): %s\n",
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
    int fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
    if (fd < 0) {
        log_line("%s: Could not open /dev/urandom: %s\n", __func__,
                 strerror(errno));
        return false;
    }
    bool ret = true;
    int r = safe_read(fd, seed, len);
    if (r < 0) {
        ret = false;
        log_line("%s: Could not read /dev/urandom: %s\n",
                 __func__, strerror(errno));
    }
    close(fd);
    return ret;
}

void nk_hwrng_bytes(void *seed, size_t len)
{
    char *s = (char *)seed;
    if (nk_getrandom(s, len))
        return;
    if (nk_get_urandom(s, len))
        return;
    log_line("%s: Seeding PRNG via system clock.  May be predictable.\n",
             __func__);
    if (nk_get_rnd_clk(s, len))
        return;
    suicide("%s: All methods to seed PRNG failed.  Exiting.\n", __func__);
}

