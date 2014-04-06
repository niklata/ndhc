/* duiaid.c - DUID/IAID storage and generation for clientids
 *
 * Copyright (c) 2014 Nicholas J. Kain <njkain at gmail dot com>
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include "nk/log.h"
#include "nk/random.h"
#include "nk/io.h"
#include "duiaid.h"
#include "ndhc.h"

static void get_duid_path(char *duidfile, size_t dlen)
{
    int splen = snprintf(duidfile, dlen, "%s/DUID", state_dir);
    if (splen < 0)
        suicide("%s: snprintf failed; return=%d", __func__, splen);
    if ((size_t)splen >= dlen)
        suicide("%s: snprintf dest buffer too small %d >= %u",
                __func__, splen, sizeof dlen);
}

static void get_iaid_path(char *iaidfile, size_t ilen, uint8_t *hwaddr,
                          size_t hwaddrlen)
{
    if (hwaddrlen != 6)
        suicide("%s: Hardware address length=%u != 6 bytes",
                __func__, hwaddrlen);
    int splen = snprintf
        (iaidfile, ilen,
         "%s/IAID-%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
         state_dir, hwaddr[0], hwaddr[1], hwaddr[2],
         hwaddr[3], hwaddr[4], hwaddr[5]);
    if (splen < 0)
        suicide("%s: snprintf failed; return=%d", __func__, splen);
    if ((size_t)splen >= ilen)
        suicide("%s: snprintf dest buffer too small %d >= %u",
                __func__, splen, sizeof ilen);
}

static int open_duidfile_read(void)
{
    char duidfile[PATH_MAX];
    get_duid_path(duidfile, sizeof duidfile);
    int fd = open(duidfile, O_RDONLY, 0);
    if (fd < 0) {
        log_line("Failed to open duidfile '%s' for reading: %s",
                 duidfile, strerror(errno));
    }
    return fd;
}

static int open_duidfile_write(void)
{
    char duidfile[PATH_MAX];
    get_duid_path(duidfile, sizeof duidfile);
    int fd = open(duidfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0)
        suicide("Failed to open duidfile '%s' for writing: %s",
                duidfile, strerror(errno));
    return fd;
}

static int open_iaidfile_read(uint8_t *hwaddr, size_t hwaddrlen)
{
    char iaidfile[PATH_MAX];
    get_iaid_path(iaidfile, sizeof iaidfile, hwaddr, hwaddrlen);
    int fd = open(iaidfile, O_RDONLY, 0);
    if (fd < 0) {
        log_line("Failed to open iaidfile '%s' for reading: %s",
                 iaidfile, strerror(errno));
    }
    return fd;
}

static int open_iaidfile_write(uint8_t *hwaddr, size_t hwaddrlen)
{
    char iaidfile[PATH_MAX];
    get_iaid_path(iaidfile, sizeof iaidfile, hwaddr, hwaddrlen);
    int fd = open(iaidfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0)
        suicide("Failed to open iaidfile '%s' for writing: %s",
                iaidfile, strerror(errno));
    return fd;
}

// We use DUID-UUID (RFC6355)
// It is a 16-bit type=4 in network byte order followed by a 128-byte UUID.
// RFC6355 specifies a RFC4122 UUID, but I simply use a 128-byte random
// value, as the complexity of RFC4122 UUID generation is completely
// unwarranted for DHCPv4.
static size_t generate_duid(struct nk_random_state_u32 *s, char *dest,
                            size_t dlen)
{
    const size_t tlen = sizeof(uint16_t) + 4 * sizeof(uint32_t);
    if (dlen < tlen)
        suicide("%s: dlen < %u", __func__, tlen);
    size_t off = 0;

    uint16_t typefield = htons(4);
    memcpy(dest+off, &typefield, sizeof typefield);
    off += sizeof typefield;

    for (size_t i = 0; i < 4; ++i) {
        uint32_t r32 = nk_random_u32(s);
        memcpy(dest+off, &r32, sizeof r32);
        off += sizeof r32;
    }
    return off;
}

// RFC6355 specifies the IAID as a 32-bit value that uniquely identifies
// a hardware link for a given host.
static size_t generate_iaid(struct nk_random_state_u32 *s, char *dest,
                            size_t dlen)
{
    if (dlen < sizeof(uint32_t))
        suicide("%s: dlen < %u", __func__, sizeof(uint32_t));
    size_t off = 0;

    uint32_t r32 = nk_random_u32(s);
    memcpy(dest+off, &r32, sizeof r32);
    off += sizeof r32;
    return off;
}

// Failures are all fatal.
void get_clientid(struct client_state_t *cs, struct client_config_t *cc)
{
    if (cc->clientid_len > 0)
        return;
    char iaid[sizeof cc->clientid];
    char duid[sizeof cc->clientid];
    size_t iaid_len;
    size_t duid_len;

    int fd = open_iaidfile_read(cc->arp, sizeof cc->arp);
    if (fd < 0) {
        iaid_len = generate_iaid(&cs->rnd32_state, iaid, sizeof iaid);
        fd = open_iaidfile_write(cc->arp, sizeof cc->arp);
        int r = safe_write(fd, iaid, iaid_len);
        if (r < 0 || (size_t)r != iaid_len)
            suicide("%s: (%s) failed to write generated IAID.",
                    cc->interface, __func__);
    } else {
        iaid_len = safe_read(fd, iaid, sizeof iaid);
        if (iaid_len < 0)
            suicide("%s: (%s) failed to read IAID from file",
                    cc->interface, __func__);
    }
    close(fd);

    fd = open_duidfile_read();
    if (fd < 0) {
        duid_len = generate_duid(&cs->rnd32_state, duid, sizeof duid);
        fd = open_duidfile_write();
        int r = safe_write(fd, duid, duid_len);
        if (r < 0 || (size_t)r != duid_len)
            suicide("%s: (%s) failed to write generated DUID.",
                    cc->interface, __func__);
    } else {
        duid_len = safe_read(fd, duid, sizeof duid);
        if (duid_len < 0)
            suicide("%s: (%s) failed to read DUID from file",
                    cc->interface, __func__);
    }
    close(fd);

    const uint8_t cid_type = 255;
    size_t cdl = sizeof cid_type + iaid_len + duid_len;
    if (cdl > sizeof cc->clientid)
        suicide("%s: (%s) clientid length %u > %u",
                cc->interface, __func__, cdl, sizeof cc->clientid);

    uint8_t cid_len = 0;
    memcpy(cc->clientid + cid_len, &cid_type, sizeof cid_type);
    cid_len += sizeof cid_type;
    memcpy(cc->clientid + cid_len, iaid, iaid_len);
    cid_len += iaid_len;
    memcpy(cc->clientid + cid_len, duid, duid_len);
    cid_len += duid_len;
    cc->clientid_len = cid_len;
}

