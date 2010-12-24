#ifndef IFCHANGE_H_
#define IFCHANGE_H_

#include "packet.h"

enum {
	IFCHANGE_DECONFIG = 0,
	IFCHANGE_BOUND = 1,
	IFCHANGE_RENEW = 2,
	IFCHANGE_NAK = 4
};

void ifchange(struct dhcpMessage *packet, int mode);

#endif
