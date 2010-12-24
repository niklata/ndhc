#ifndef ARPPING_H_
#define ARPPING_H_

#include <stdint.h>
#include <net/if_arp.h>

#include "config.h"
#include "packet.h"

struct arpMsg {
    /* Ethernet header */
    uint8_t  h_dest[6];     /* 00 destination ether addr */
    uint8_t  h_source[6];   /* 06 source ether addr */
    uint16_t h_proto;       /* 0c packet type ID field */

    /* ARP packet */
    uint16_t htype;         /* 0e hardware type (must be ARPHRD_ETHER) */
    uint16_t ptype;         /* 10 protocol type (must be ETH_P_IP) */
    uint8_t  hlen;          /* 12 hardware address length (must be 6) */
    uint8_t  plen;          /* 13 protocol address length (must be 4) */
    uint16_t operation;     /* 14 ARP opcode */
    uint8_t  sHaddr[6];     /* 16 sender's hardware address */
    uint8_t  sInaddr[4];    /* 1c sender's IP address */
    uint8_t  tHaddr[6];     /* 20 target's hardware address */
    uint8_t  tInaddr[4];    /* 26 target's IP address */
    uint8_t  pad[18];       /* 2a pad for min. ethernet payload (60 bytes) */
};

enum {
    ARP_MSG_SIZE = 0x2a
};

void arp_check(struct client_state_t *cs, struct dhcpMessage *packet);
void arp_success(struct client_state_t *cs);
void handle_arp_response(struct client_state_t *cs);

#endif /* ARPPING_H_ */
