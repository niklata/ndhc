#ifndef NCMLIB_NET_CHECKSUM_H
#define NCMLIB_NET_CHECKSUM_H

#include <stdint.h>

// When summing ones-complement 16-bit values using a 32-bit unsigned
// representation, fold the carry bits that have spilled into the upper
// 16-bits of the 32-bit unsigned value back into the 16-bit ones-complement
// binary value.
static inline uint16_t net_checksum161c_foldcarry(uint32_t v)
{
    v = (v >> 16) + (v & 0xffff);
    v += v >> 16;
    return v;
}

// This function is not suitable for summing buffers that are greater than
// 128k bytes in length: failure case will be incorrect checksums via
// unsigned overflow, which is a defined operation and is safe.  This limit
// should not be an issue for IPv4 or IPv6 packet, which are limited to
// at most 64k bytes.
static uint16_t net_checksum161c(const void *buf, size_t size)
{
    uint32_t sum = 0;
    int odd = size & 0x01;
    size_t i;
    size &= ~((size_t)0x01);
    size >>= 1;
    const uint8_t *b = (const uint8_t *)buf;
    for (i = 0; i < size; ++i) {
        uint16_t hi = b[i*2];
        uint16_t lo = b[i*2+1];
        sum += ntohs((lo + (hi << 8)));
    }
    if (odd) {
        uint16_t hi = b[i*2];
        uint16_t lo = 0;
        sum += ntohs((lo + (hi << 8)));
    }
    return ~net_checksum161c_foldcarry(sum);
}

// For two sequences of bytes A and B that return checksums CS(A) and CS(B),
// this function will calculate the checksum CS(AB) of the concatenated value
// AB given the checksums of the individual parts CS(A) and CS(B).
static inline uint16_t net_checksum161c_add(uint16_t a, uint16_t b)
{
    const uint32_t A = a;
    const uint32_t B = b;
    return ~net_checksum161c_foldcarry((~A & 0xffffu) + (~B & 0xffffu));
}

#endif

