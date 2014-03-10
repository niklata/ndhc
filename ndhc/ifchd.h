#ifndef NJK_IFCHD_H_
#define NJK_IFCHD_H_

#include "ndhc-defines.h"

enum ifchd_states {
    STATE_NOTHING,
    STATE_IP4SET,
    STATE_IP,
    STATE_SUBNET,
    STATE_TIMEZONE,
    STATE_ROUTER,
    STATE_DNS,
    STATE_LPRSVR,
    STATE_HOSTNAME,
    STATE_DOMAIN,
    STATE_IPTTL,
    STATE_MTU,
    STATE_BROADCAST,
    STATE_NTPSVR,
    STATE_WINS
};

#include <net/if.h>
struct ifchd_client {
    /* Socket fd, current state, and idle time for connection. */
    int state;
    /* Per-connection buffer. */
    char ibuf[MAX_BUF];
    /* ' '-delimited buffers of nameservers and domains */
    char namesvrs[MAX_BUF];
    char domains[MAX_BUF];
};

extern void perform_timezone(const char *str, size_t len);
extern void perform_dns(const char *str, size_t len);
extern void perform_lprsvr(const char *str, size_t len);
extern void perform_hostname(const char *str, size_t len);
extern void perform_domain(const char *str, size_t len);
extern void perform_ipttl(const char *str, size_t len);
extern void perform_ntpsrv(const char *str, size_t len);
extern void perform_wins(const char *str, size_t len);

#endif /* NJK_IFCHD_H_ */

