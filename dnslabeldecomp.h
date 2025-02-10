// Copyright 2025 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHC_DNSLABELDECOMP_H_
#define NDHC_DNSLABELDECOMP_H_

#include <stddef.h>
#include <stdbool.h>

bool dnslabeldecomp(char *out, size_t *outlen, const char *in, size_t inlen);

#endif
