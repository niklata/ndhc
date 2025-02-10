// Copyright 2025 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHC_DNSLABELDECOMP_H_
#define NDHC_DNSLABELDECOMP_H_

#include <stddef.h>
#include <stdbool.h>

bool dnslabeldecomp(char *out, size_t *outlen, const char *in, size_t inlen);

// Hostname restrictions on a label
static inline bool validdnslabelchar(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '-';
}

// Hostname restrictions on a dotted hostname
static inline bool validdnshostchar(char c)
{
    return c == '.' || validdnslabelchar(c);
}

#endif
