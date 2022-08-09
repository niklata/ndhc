#ifndef NKLIB_NSTRCPY_H_
#define NKLIB_NSTRCPY_H_

#include <stddef.h>
#include <string.h>

// Returns pointer to end of dest string (NULL terminator) if
// src is not truncated when copying to dest.
// Otherwise, returns NULL if src is truncated or size == 0.
static inline char *nstrcpy(char *dest, size_t size, const char *src)
{
    if (!size) return NULL;
    char c;
    for (size_t i = 0; i < size; ++i, ++dest) {
        c = *src++;
        *dest = c;
        if (!c) return dest;
    }
    *(dest - 1) = 0;
    return NULL;
}

// Same semantics as above, except we append to dest.
static inline char *nstrcat(char *dest, size_t size, const char *src)
{
    size_t len = strlen(dest);
    return nstrcpy(dest + len, size - len, src);
}

// Acts as nstrcpy, but does not require src to be NULL terminated.
// That said, it will stop early if src contains a NULL terminator.
static inline char *nstrcpyl(char *dest, size_t dsize, const char *src, size_t ssize)
{
    if (!dsize) return NULL;
    char c;
    size_t i = 0, j = 0;
    for (; i < dsize && j < ssize; ++i, ++j, ++dest) {
        c = *src++;
        *dest = c;
        if (!c) return dest;
    }
    if (i == dsize) {
        *(dest - 1) = 0;
        return NULL;
    }
    // j == ssize here
    *dest = 0;
    return dest;
}

#endif

