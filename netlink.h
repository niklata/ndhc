// Copyright 2011-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NK_NETLINK_H_
#define NK_NETLINK_H_

#include <stdbool.h>
#include <linux/rtnetlink.h>
#include "state.h"

enum {
    IFS_NONE = 0,
    IFS_UP,
    IFS_DOWN,
    IFS_SHUT,
    IFS_REMOVED
};

bool nl_event_carrier_wentup(int state);
int nl_event_get(struct client_state_t *cs);
int nl_getifdata(void);

#endif

