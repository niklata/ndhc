#ifndef DHCPC_H_
#define DHCPC_H_

enum {
	INIT_SELECTING,
	REQUESTING,
	BOUND,
	RENEWING,
	REBINDING,
	ARP_CHECK,
	INIT_REBOOT,
	RENEW_REQUESTED,
	RELEASED
};

struct client_config_t {
	char foreground;		/* Do not fork */
	char quit_after_lease;		/* Quit after obtaining lease */
	char abort_if_no_lease;		/* Abort if no lease */
	char background_if_no_lease;	/* Fork to background if no lease */
	char *interface;		/* The name of the interface to use */
	char *script;			/* User script to run at dhcp events */
	unsigned char *clientid;	/* Optional client id to use */
	unsigned char *hostname;	/* Optional hostname to use */
	int ifindex;			/* Index number of the interface to use */
	unsigned char arp[6];		/* Our arp address */
};

extern struct client_config_t client_config;

#endif

