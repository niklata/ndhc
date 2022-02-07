// Copyright 2016 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCMLIB_HWCRNG__
#define NCMLIB_HWCRNG__

#include <stddef.h>

void nk_get_hwrng(void *seed, size_t len);

#endif

