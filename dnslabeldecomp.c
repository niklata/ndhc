// Copyright 2025 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include "dnslabeldecomp.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "nk/log.h"

enum decomp_state
{
    DS_START,
    DS_LABEL,
};

// emits a format that ifchd expects
// NOT rfc compliant; I don't support pointer compression or multiple
// domain search options being concatenated.
bool dnslabeldecomp(char *out, size_t *outlen, const char *in, size_t inlen)
{
    char buf[256];
    size_t bufn = 0;
    size_t label_size;
    size_t maxout = *outlen;
    *outlen = 0;
    enum decomp_state state = DS_START;
    size_t off = 0;
    size_t label_start = 0;
    for (;;) {
        if (state == DS_START) {
            if (off >= inlen) {
                if (*outlen > 0 && *(out-1) == ',') {
                    *(out-1) = 0;
                    *outlen -= 1;
                }
                return true;
            }
            label_start = off;
            label_size = (uint8_t)in[off++];
            if (label_size == 0) {
                // label terminal; copy to out
                if (bufn + *outlen < maxout) {
                    if (bufn < 2) return false;
                    assert(buf[bufn-1] == '.');
                    buf[bufn-1] = ',';
                    memcpy(out, buf, bufn);
                    out[bufn] = 0;
                    out += bufn;
                    *outlen += bufn;
                    bufn = 0;
                    continue;
                } else {
                    // Not enough space.  Completely fail.
                    return false;
                }
            }
            if (label_size > 63) {
                if (label_size < 192) {
                    log_line("dhcp server sent invalid dns label size\n");
                    return false;
                }
                label_size -= 192;
                label_size <<= 8;
                if (off >= inlen) return false;
                label_size += (uint8_t)in[off++];
                if (label_size >= label_start) {
                    log_line("dhcp server sent malicious dns label compression\n");
                    return false;
                }
                // XXX: For now, I'm not supporting dns label pointers.
                return false;
            }
            assert(label_size > 0);
            state = DS_LABEL;
        }
        if (state == DS_LABEL) {
            if (off >= inlen) return false;
            if (bufn >= sizeof buf) return false;
            char c = in[off++];
            if (!validdnslabelchar(c)) return false;
            buf[bufn++] = c;
            --label_size;
            if (label_size == 0) {
                if (bufn >= sizeof buf) return false;
                buf[bufn++] = '.';
                state = DS_START;
                continue;
            }
        }
    }
}

#if 0
int main()
{
    const char test0[] = { 4, 't', 'e', 's', 't', 3, 'n', 'e', 't', 0 };
    const char testgud0[] = "test.net";
    const char test1[] = { 1, 'x', 2, 's', 'u', 0, 3, 's', 'u', 'p', 1, 'z', 0 };
    const char testgud1[] = "x.su,sup.z";
    char outbuf[512];
    size_t outbufn;
    bool r;

    outbufn = sizeof outbuf;
    r = dnslabeldecomp(outbuf, &outbufn, test0, sizeof test0);
    if (!r) return 1;
    if (outbufn != 8) return 2;
    if (memcmp(outbuf, testgud0, 8)) return 3;

    outbufn = sizeof outbuf;
    r = dnslabeldecomp(outbuf, &outbufn, test1, sizeof test1);
    if (!r) return 1;
    if (outbufn != 10) return 2;
    if (memcmp(outbuf, testgud1, 10)) return 3;

    return 0;
}
#endif
