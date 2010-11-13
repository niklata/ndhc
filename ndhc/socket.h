/* socket.h */
#ifndef SOCKET_H_
#define SOCKET_H_

int read_interface(char *interface, int *ifindex, uint32_t *addr, unsigned char *arp);
int listen_socket(unsigned int ip, int port, char *inf);
int raw_socket(int ifindex);

#endif
