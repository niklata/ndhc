#ifndef SOCKET_H_
#define SOCKET_H_

#include <stdint.h>

int set_sock_nonblock(int fd);
int read_interface(char *interface, int *ifindex, uint32_t *addr,
                   uint8_t *mac);
int listen_socket(unsigned int ip, int port, char *inf);
int raw_socket(int ifindex);

#endif
