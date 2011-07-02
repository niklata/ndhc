#ifndef NDHC_STATE_H_
#define NDHC_STATE_H_

#include "config.h"
#include "dhcp.h"

typedef enum {
    DS_SELECTING = 0,
    DS_REQUESTING,
    DS_BOUND,
    DS_RENEWING,
    DS_REBINDING,
    DS_BOUND_GW_CHECK,
    DS_ARP_CHECK,
    DS_RELEASED,
    DS_NUM_STATES,
} dhcp_states_t;

void packet_action(struct client_state_t *cs, struct dhcpmsg *packet,
                   uint8_t *message);
void timeout_action(struct client_state_t *cs);
void force_renew_action(struct client_state_t *cs);
void force_release_action(struct client_state_t *cs);
#endif

