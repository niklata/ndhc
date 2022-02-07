// Copyright 2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NCMLIB_NET_CHECKSUM16_H
#define NCMLIB_NET_CHECKSUM16_H

// RFC 1071 is still a good reference.

#include <stdint.h>

// When summing ones-complement 16-bit values using a 32-bit unsigned
// representation, fold the carry bits that have spilled into the upper
// 16-bits of the 32-bit unsigned value back into the 16-bit ones-complement
// binary value.
static inline uint16_t net_checksum16_foldcarry(uint32_t v)
{
    v = (v >> 16) + (v & 0xffff);
    v += v >> 16;
    return v;
}

// Produces the correct result on little endian in the sense that
// the binary value returned, when stored to memory, will match
// the result on big endian; if the numeric value returned
// must match big endian results, then call ntohs() on the result.
static uint16_t net_checksum16(const void *buf, size_t size)
{
    const char *b = (const char *)buf;
    const char *bend = b + size;
    uint32_t sum = 0, t = 0;
    uint8_t z[4] = { 0 };
    switch (size & 3) {
    case 3: z[2] = (uint8_t)*--bend;
    case 2: z[1] = (uint8_t)*--bend;
    case 1: z[0] = (uint8_t)*--bend;
    default: break;
    }
    memcpy(&t, z, 4);
    sum += t & 0xffffu;
    sum += (t >> 16);
    for (; b < bend; b += 4) {
        memcpy(&t, b, 4);
        sum += t & 0xffffu;
        sum += (t >> 16);
    }
    return ~net_checksum16_foldcarry(sum);
}

// For two sequences of bytes A and B that return checksums CS(A) and CS(B),
// this function will calculate the checksum CS(AB) of the concatenated value
// AB given the checksums of the individual parts CS(A) and CS(B).
static inline uint16_t net_checksum16_add(uint16_t a, uint16_t b)
{
    const uint32_t A = a;
    const uint32_t B = b;
    return ~net_checksum16_foldcarry((~A & 0xffffu) + (~B & 0xffffu));
}

#endif

