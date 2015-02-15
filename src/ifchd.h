#ifndef NJK_IFCHD_H_
#define NJK_IFCHD_H_

#include <limits.h>
#include "ndhc-defines.h"

enum ifchd_states {
    STATE_NOTHING,
    STATE_IP4SET,
    STATE_TIMEZONE,
    STATE_ROUTER,
    STATE_DNS,
    STATE_LPRSVR,
    STATE_HOSTNAME,
    STATE_DOMAIN,
    STATE_IPTTL,
    STATE_MTU,
    STATE_NTPSVR,
    STATE_WINS,
    STATE_CARRIER,
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

extern struct ifchd_client cl;

extern int allow_hostname;
extern uid_t ifch_uid;
extern gid_t ifch_gid;

int perform_timezone(const char str[static 1], size_t len);
int perform_dns(const char str[static 1], size_t len);
int perform_lprsvr(const char str[static 1], size_t len);
int perform_hostname(const char str[static 1], size_t len);
int perform_domain(const char str[static 1], size_t len);
int perform_ipttl(const char str[static 1], size_t len);
int perform_ntpsrv(const char str[static 1], size_t len);
int perform_wins(const char str[static 1], size_t len);

void ifch_main(void);

#endif /* NJK_IFCHD_H_ */

