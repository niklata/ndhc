/* dhcpd.h */
#ifndef DHCPD_H_
#define DHCPD_H_

#include <netinet/ip.h>
#include <netinet/udp.h>

/*****************************************************************/
/* Do not modify below here unless you know what you are doing!! */
/*****************************************************************/

/* DHCP protocol -- see RFC 2131 */
#define SERVER_PORT             67
#define CLIENT_PORT             68

#define DHCP_OPTIONS_BUFSIZE    308

enum {
    BOOTREQUEST = 1,
    BOOTREPLY	= 2
};

#define ETH_10MB        1
#define ETH_10MB_LEN    6

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

#define BROADCAST_FLAG  0x8000

enum {
    OPTION_FIELD = 0,
    FILE_FIELD	 = 1,
    SNAME_FIELD	 = 2
};

#define MAC_BCAST_ADDR  (unsigned char *) "\xff\xff\xff\xff\xff\xff"

enum {
    OPT_CODE = 0,
    OPT_LEN  = 1,
    OPT_DATA = 2
};

struct option_set {
    unsigned char *data;
    struct option_set *next;
};

#endif
