#ifndef SYS_H_
#define SYS_H_

#include <sys/time.h>
#include "ndhc-defines.h"
#include "config.h"

static inline unsigned long long curms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

extern char pidfile[MAX_PATH_LENGTH];

void setup_signals(struct client_state_t *cs);
void background(struct client_state_t *cs);
void epoll_add(struct client_state_t *cs, int fd);
void epoll_del(struct client_state_t *cs, int fd);

#endif /* SYS_H_ */
