// Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef IFCHANGE_H_
#define IFCHANGE_H_

#include <stdbool.h>

bool ifchange_carrier_isup(void);
int ifchange_bind(struct client_state_t *cs, struct dhcpmsg *packet);
int ifchange_deconfig(struct client_state_t *cs);

#endif
