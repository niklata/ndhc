#ifndef IFCHD_DEFINES_H_
#define IFCHD_DEFINES_H_

#include "defines.h"

#define PID_FILE_DEFAULT "/var/run/ifchd.pid"
#define IFCHD_VERSION "0.9"
#define MAX_BUF 1024
#define SOCK_QUEUE 2
#define CONN_TIMEOUT 60

#include <net/if.h>
#include "strlist.h"
struct ifchd_client {
    /* Socket fd, current state, and idle time for connection. */
    int fd;
    int state;
    int idle_time;
    /*
     * Per-connection pointers into the command lists.  Respectively, the
     * topmost item on the list, the current item, and the last item on the
     * list.
     */
    strlist_t *head, *curl, *last;
    /* Lists of nameservers and search domains.  Unfortunately they must be
     * per-connection, since otherwise seperate clients could race against
     * one another to write out unpredictable data.
     */
    strlist_t *namesvrs, *domains;

    /* Symbolic name of the interface associated with a connection. */
    char ifnam[IFNAMSIZ];
    /* Per-connection buffer. */
    char ibuf[MAX_BUF];
};

#endif /* IFCHD_DEFINES_H_ */

