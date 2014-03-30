/* state.h - high level DHCP state machine
 *
 * Copyright (c) 2011-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#ifndef NDHC_STATE_H_
#define NDHC_STATE_H_

#include "ndhc.h"
#include "dhcp.h"

typedef enum {
    DS_SELECTING = 0,
    DS_REQUESTING,
    DS_BOUND,
    DS_RENEWING,
    DS_REBINDING,
    DS_BOUND_GW_CHECK,
    DS_COLLISION_CHECK,
    DS_RELEASED,
    DS_NUM_STATES,
} dhcp_states_t;

void reinit_selecting(struct client_state_t *cs, int timeout);

void packet_action(struct client_state_t *cs, struct dhcpmsg *packet,
                   uint8_t msgtype);
void timeout_action(struct client_state_t *cs, long long nowts);
void force_renew_action(struct client_state_t *cs);
void force_release_action(struct client_state_t *cs);

void ifup_action(struct client_state_t *cs);
void ifnocarrier_action(struct client_state_t *cs);
void ifdown_action(struct client_state_t *cs);
long long dhcp_get_wake_ts(void);

#endif

