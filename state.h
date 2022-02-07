// Copyright 2011-2020 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHC_STATE_H_
#define NDHC_STATE_H_

#include "ndhc.h"
#include "dhcp.h"

#define COR_SUCCESS 0
#define COR_ERROR -1

int dhcp_handle(struct client_state_t *cs, long long nowts,
                bool sev_dhcp, struct dhcpmsg *dhcp_packet,
                uint8_t dhcp_msgtype, uint32_t dhcp_srcaddr, bool sev_arp,
                bool force_fingerprint, bool dhcp_timeout, bool arp_timeout);

#endif

