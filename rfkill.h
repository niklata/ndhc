// Copyright 2015-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHC_RFKILL_H_
#define NDHC_RFKILL_H_

enum {
    RFK_NONE = 0,
    RFK_FAIL,
    RFK_ENABLED,
    RFK_DISABLED,
};

int rfkill_open(bool *enable_rfkill);
int rfkill_get(struct client_state_t *cs, int check_idx, uint32_t rfkidx);

#endif

