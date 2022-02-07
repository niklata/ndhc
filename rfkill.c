// Copyright 2015-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
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

int rfkill_open(bool *enable_rfkill)
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
int rfkill_get(struct client_state_t *cs, int check_idx, uint32_t rfkidx)
{
    struct rfkill_event event;
    ssize_t len = safe_read(cs->rfkillFd, (char *)&event, sizeof event);
    if (len < 0) {
        log_line("rfkill: safe_read failed: %s", strerror(errno));
        return RFK_FAIL;
    }
    if (len != RFKILL_EVENT_SIZE_V1) {
        log_line("rfkill: event has unexpected size: %zd", len);
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

