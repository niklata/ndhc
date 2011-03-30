#ifndef CLIENTPACKET_H_
#define CLIENTPACKET_H_

#include <stdint.h>
#include "packet.h" // for struct dhcpMessage

#define DHCP_SERVER_PORT        67
#define DHCP_CLIENT_PORT        68
#define DHCP_MAGIC              0x63825363

enum {
    DHCPDISCOVER = 1,
    DHCPOFFER	 = 2,
    DHCPREQUEST	 = 3,
    DHCPDECLINE	 = 4,
    DHCPACK	 = 5,
    DHCPNAK	 = 6,
    DHCPRELEASE	 = 7,
    DHCPINFORM	 = 8
};

uint32_t random_xid(void);
int send_discover(uint32_t xid, uint32_t requested);
int send_selecting(uint32_t xid, uint32_t server, uint32_t requested);
int send_renew(uint32_t xid, uint32_t server, uint32_t ciaddr);
int send_renew(uint32_t xid, uint32_t server, uint32_t ciaddr);
int send_decline(uint32_t xid, uint32_t server, uint32_t requested);
int send_release(uint32_t server, uint32_t ciaddr);
int get_raw_packet(struct dhcpMessage *payload, int fd);

#endif
