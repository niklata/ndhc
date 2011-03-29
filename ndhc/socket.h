#ifndef SOCKET_H_
#define SOCKET_H_

#include <stdint.h>

int set_sock_nonblock(int fd);
int listen_socket(unsigned int ip, int port, char *inf);
int raw_socket(int ifindex);

#endif
