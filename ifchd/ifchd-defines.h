#ifndef IFCHD_DEFINES_H_
#define IFCHD_DEFINES_H_

#include "defines.h"

#define PID_FILE_DEFAULT "/var/run/ifchd.pid"
#define IFCHD_VERSION "0.9"
#define MAX_BUF 384
#define SOCK_QUEUE 2
#define CONN_TIMEOUT 60
#define MAX_IFACES 10

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

#endif /* IFCHD_DEFINES_H_ */

