#ifndef IFCHD_DEFINES_H_
#define IFCHD_DEFINES_H_

#include "defines.h"

#define PID_FILE_DEFAULT "/var/run/ifchd.pid"
#define IFCHD_VERSION "0.9"
#define MAX_BUF 384
#define SOCK_QUEUE 2
#define CONN_TIMEOUT 60
#define MAX_IFACES 10

enum ifchd_states {
    STATE_NOTHING,
    STATE_INTERFACE,
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
    int fd;
    int state;
    int idle_time;

    /* Symbolic name of the interface associated with a connection. */
    char ifnam[IFNAMSIZ];
    /* Per-connection buffer. */
    char ibuf[MAX_BUF];
    /* ' '-delimited buffers of nameservers and domains */
    char namesvrs[MAX_BUF];
    char domains[MAX_BUF];
};

extern void perform_timezone(struct ifchd_client *cl, const char *str, size_t len);
extern void perform_dns(struct ifchd_client *cl, const char *str, size_t len);
extern void perform_lprsvr(struct ifchd_client *cl, const char *str, size_t len);
extern void perform_hostname(struct ifchd_client *cl, const char *str, size_t len);
extern void perform_domain(struct ifchd_client *cl, const char *str, size_t len);
extern void perform_ipttl(struct ifchd_client *cl, const char *str, size_t len);
extern void perform_ntpsrv(struct ifchd_client *cl, const char *str, size_t len);
extern void perform_wins(struct ifchd_client *cl, const char *str, size_t len);

#endif /* IFCHD_DEFINES_H_ */

