#ifndef DHCPC_H_
#define DHCPC_H_

#include <stdint.h>

#define NUMPACKETS 3 /* number of packets to send before delay */
#define RETRY_DELAY 30 /* time in seconds to delay after sending NUMPACKETS */

enum {
	DS_NULL = 0,
	DS_INIT_SELECTING,
	DS_REQUESTING,
	DS_BOUND,
	DS_RENEWING,
	DS_REBINDING,
	DS_ARP_CHECK,
	DS_RENEW_REQUESTED,
	DS_RELEASED
};

enum {
    LM_NONE = 0,
    LM_KERNEL,
    LM_RAW
};

struct client_state_t {
    unsigned long long leaseStartTime;
    int dhcpState;
    int arpPrevState;
    int listenMode;
    int packetNum;
    int epollFd, signalFd, listenFd, arpFd;
    int timeout;
    uint32_t requestedIP, serverAddr;
    uint32_t lease, t1, t2, xid;
};

struct client_config_t {
	char foreground;		/* Do not fork */
	char quit_after_lease;		/* Quit after obtaining lease */
	char abort_if_no_lease;		/* Abort if no lease */
	char background_if_no_lease;	/* Fork to background if no lease */
	char *interface;		/* The name of the interface to use */
	unsigned char *clientid;	/* Optional client id to use */
	unsigned char *hostname;	/* Optional hostname to use */
	int ifindex;			/* Index number of the interface to use */
	unsigned char arp[6];		/* Our arp address */
};

extern struct client_config_t client_config;

#endif

