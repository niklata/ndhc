#ifndef NK_NETLINK_H_
#define NK_NETLINK_H_

#include "config.h"

int nl_open(struct client_state_t *cs);
void nl_close(struct client_state_t *cs);
void nl_queryifstatus(int ifidx, struct client_state_t *cs);
void handle_nl_message(struct client_state_t *cs);
int nl_getifdata(const char *ifname, struct client_state_t *cs);

#endif /* NK_NETLINK_H_ */
