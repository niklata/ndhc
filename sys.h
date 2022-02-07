// Copyright 2010-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef SYS_H_
#define SYS_H_

#include "ndhc-defines.h"

static inline size_t min_size_t(size_t a, size_t b)
{
    return a < b ? a : b;
}

#define curms() IMPL_curms(__func__)
long long IMPL_curms(const char *parent_function);

void setup_signals_subprocess(void);

#endif

