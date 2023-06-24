// Copyright 2013-2023 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdint.h>
#include "nk/hwrng.h"
#include "nk/random.h"

void nk_random_init(struct nk_random_state *s)
{
    nk_hwrng_bytes(s->seed, sizeof(uint64_t) * 3);
    s->seed[3] = 1;
    for (size_t i = 0; i < 12; ++i) nk_random_u64(s);
}

static inline uint64_t rotl64(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

uint64_t nk_random_u64(struct nk_random_state *s)
{
    const uint64_t t = s->seed[0] + s->seed[1] + s->seed[3]++;
    s->seed[0] = s->seed[1] ^ (s->seed[1] >> 11);
    s->seed[1] = s->seed[2] + (s->seed[2] << 3);
    s->seed[2] = rotl64(s->seed[2], 24) + t;
    return t;
}

