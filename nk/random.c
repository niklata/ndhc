// Copyright 2013-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdint.h>
#include "nk/hwrng.h"
#include "nk/random.h"

// GJrand64: https://gjrand.sourceforge.net

void nk_random_init(struct nk_random_state *s)
{
    nk_hwrng_bytes(s->seed, sizeof(uint64_t) * 2);
    s->seed[2] = 2000001;
    s->seed[3] = 0;
    for (size_t i = 0; i < 14; ++i) nk_random_u64(s);
}

static inline uint64_t rotl64(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

uint64_t nk_random_u64(struct nk_random_state *s)
{
    s->seed[1] += s->seed[2];
    s->seed[0] = rotl64(s->seed[0], 32);
    s->seed[2] ^= s->seed[1];
    s->seed[3] += 0x55aa96a5;
    s->seed[0] += s->seed[1];
    s->seed[2] = rotl64(s->seed[2], 23);
    s->seed[1] ^= s->seed[0];
    s->seed[0] += s->seed[2];
    s->seed[1] = rotl64(s->seed[1], 19);
    s->seed[2] += s->seed[0];
    s->seed[1] += s->seed[3];
    return s->seed[0];
}

