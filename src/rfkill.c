/* rfkill.c - rfkill interface and handling
 *
 * Copyright (c) 2015-2017 Nicholas J. Kain <njkain at gmail dot com>
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/rfkill.h>
#include "nk/log.h"
#include "nk/io.h"
#include "ndhc.h"
#include "rfkill.h"

int rfkill_open(bool enable_rfkill[static 1])
{
    if (!*enable_rfkill)
        return -1;
    int r = open("/dev/rfkill", O_RDONLY|O_CLOEXEC|O_NONBLOCK);
    if (r < 0) {
        *enable_rfkill = false;
        log_line("rfkill disabled: could not open /dev/rfkill: %s",
                 strerror(errno));
    }
    return r;
}

// check_idx: Does rfkidx have any meaning?
// rfkidx: Pay attention only to this radio kill switch number.
int rfkill_get(struct client_state_t cs[static 1],
               int check_idx, uint32_t rfkidx)
{
    struct rfkill_event event;
    ssize_t len = safe_read(cs->rfkillFd, (char *)&event, sizeof event);
    if (len < 0) {
        log_error("rfkill: safe_read failed: %s", strerror(errno));
        return RFK_FAIL;
    }
    if (len != RFKILL_EVENT_SIZE_V1) {
        log_error("rfkill: event has unexpected size: %d", len);
        return RFK_FAIL;
    }
    log_line("rfkill: idx[%u] type[%u] op[%u] soft[%u] hard[%u]",
             event.idx, event.type, event.op, event.soft, event.hard);
    if (check_idx && event.idx != rfkidx)
        return RFK_NONE;
    if (event.op != RFKILL_OP_CHANGE && event.op != RFKILL_OP_CHANGE_ALL)
        return RFK_NONE;
    if (event.soft || event.hard) {
        return RFK_ENABLED;
    } else {
        return RFK_DISABLED;
    }
}

