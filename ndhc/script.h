#ifndef _SCRIPT_H
#define _SCRIPT_H

enum {
	SCRIPT_DECONFIG = 0,
	SCRIPT_BOUND = 1,
	SCRIPT_RENEW = 2,
	SCRIPT_NAK = 4
};

void run_script(struct dhcpMessage *packet, int mode);

#endif
