/* random.c - non-cryptographic fast PRNG
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
#include "nk/hwrng.h"
#include "nk/random.h"

// GJrand64: https://gjrand.sourceforge.net

void nk_random_init(struct nk_random_state *s)
{
    nk_get_hwrng(s->seed, sizeof(uint64_t) * 2);
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

