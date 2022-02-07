// Copyright 2013-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCMLIB_RANDOM__
#define NCMLIB_RANDOM__
#include <stdint.h>

struct nk_random_state {
    uint64_t seed[4];
};

void nk_random_init(struct nk_random_state *s);
uint64_t nk_random_u64(struct nk_random_state *s);
static inline uint32_t nk_random_u32(struct nk_random_state *s)
{
    // Discard lower bits as they have less linear complexity.
    return nk_random_u64(s) >> 32;
}

#endif

