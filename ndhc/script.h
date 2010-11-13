#ifndef SCRIPT_H_
#define SCRIPT_H_

enum {
	SCRIPT_DECONFIG = 0,
	SCRIPT_BOUND = 1,
	SCRIPT_RENEW = 2,
	SCRIPT_NAK = 4
};

void run_script(struct dhcpMessage *packet, int mode);

#endif
