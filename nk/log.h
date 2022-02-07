// Copyright 2003-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCM_LOG_H_
#define NCM_LOG_H_

#include <stdlib.h>
#include <stdio.h>

#define log_line(...) do { \
    dprintf(2, __VA_ARGS__); \
    dprintf(2, "\n"); } while (0)

#ifndef NDEBUG
#define log_debug(...) do { \
    dprintf(2, __VA_ARGS__); \
    dprintf(2, "\n"); } while (0)
#else
#define log_debug(...) do {} while (0)
#endif

#define suicide(...) do { \
    dprintf(2, __VA_ARGS__); \
    dprintf(2, "\n"); \
    exit(EXIT_FAILURE); } while (0)

#endif

