#ifndef PACKET_H_
#define PACKET_H_

#include <netinet/udp.h>
#include <netinet/ip.h>

struct dhcpMessage {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t cookie;
    uint8_t options[308]; /* 312 - cookie */
};

struct ip_udp_dhcp_packet {
    struct iphdr ip;
    struct udphdr udp;
    struct dhcpMessage data;
};

struct udp_dhcp_packet {
    struct udphdr udp;
    struct dhcpMessage data;
};

enum {
	IP_UPD_DHCP_SIZE = sizeof(struct ip_udp_dhcp_packet),
	UPD_DHCP_SIZE    = sizeof(struct udp_dhcp_packet),
	DHCP_SIZE        = sizeof(struct dhcpMessage),
};

/* Let's see whether compiler understood us right */
struct BUG_bad_sizeof_struct_ip_udp_dhcp_packet {
	char c[IP_UPD_DHCP_SIZE == 576 ? 1 : -1];
};

int get_packet(struct dhcpMessage *packet, int fd);
uint16_t checksum(void *addr, int count);
int raw_packet(struct dhcpMessage *payload, uint32_t source_ip,
               int source_port, uint32_t dest_ip, int dest_port,
               unsigned char *dest_arp, int ifindex);
int kernel_packet(struct dhcpMessage *payload, uint32_t source_ip,
                  int source_port, uint32_t dest_ip, int dest_port);

#endif
