#ifndef CLIENTPACKET_H_
#define CLIENTPACKET_H_

#include <stdint.h>

#define DHCP_MAGIC              0x63825363

uint32_t random_xid(void);
int send_discover(uint32_t xid, uint32_t requested);
int send_selecting(uint32_t xid, uint32_t server, uint32_t requested);
int send_renew(uint32_t xid, uint32_t server, uint32_t ciaddr);
int send_renew(uint32_t xid, uint32_t server, uint32_t ciaddr);
int send_decline(uint32_t xid, uint32_t server, uint32_t requested);
int send_release(uint32_t server, uint32_t ciaddr);
int get_raw_packet(struct dhcpMessage *payload, int fd);

#endif
