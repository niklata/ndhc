/*
 * socket.c -- DHCP server client/server socket creation
 *
 * udhcp client/server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * Cleanup and fixes, Nicholas Kain <njk@n0sPaM.kain.us> 2004
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include "log.h"
#include "strl.h"

int read_interface(char *interface, int *ifindex, uint32_t *addr,
		unsigned char *arp)
{
	int fd, ret = -1;
	struct ifreq ifr;
	struct sockaddr_in *our_ip;

	memset(&ifr, 0, sizeof(struct ifreq));
	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		log_error("socket failed!: %s", strerror(errno));
		goto out;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strlcpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (addr) {
		if (ioctl(fd, SIOCGIFADDR, &ifr)) {
			log_error("Couldn't get IP for %s.", strerror(errno));
			goto out_fd;
		}
		our_ip = (struct sockaddr_in *) &ifr.ifr_addr;
		*addr = our_ip->sin_addr.s_addr;
		log_line("%s (our ip) = %s", ifr.ifr_name,
				 inet_ntoa(our_ip->sin_addr));
	}

	if (ioctl(fd, SIOCGIFINDEX, &ifr)) {
		log_error("SIOCGIFINDEX failed!: %s", strerror(errno));
		goto out_fd;
	}

	log_line("adapter index %d", ifr.ifr_ifindex);
	*ifindex = ifr.ifr_ifindex;

	if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		log_error("Couldn't get MAC for %s", strerror(errno));
		goto out_fd;
	}

	memcpy(arp, ifr.ifr_hwaddr.sa_data, 6);
	log_line("adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x",
			arp[0], arp[1], arp[2], arp[3], arp[4], arp[5]);
	ret = 0;
out_fd:
	close(fd);
out:
	return ret;
}

int listen_socket(unsigned int ip, int port, char *inf)
{
	struct ifreq interface;
	int fd;
	struct sockaddr_in addr;
	int n = 1;

	log_line("Opening listen socket on 0x%08x:%d %s", ip, port, inf);
	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		log_error("socket call failed: %s", strerror(errno));
		goto out;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ip;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof n) == -1)
		goto out_fd;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&n, sizeof n) == -1)
		goto out_fd;

	strlcpy(interface.ifr_ifrn.ifrn_name, inf, IFNAMSIZ);
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				(char *)&interface, sizeof interface) < 0)
		goto out_fd;
	
	if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1)
		goto out_fd;
		
	return fd;
out_fd:
	close(fd);
out:
	return -1;
}

int raw_socket(int ifindex)
{
	int fd;
	struct sockaddr_ll sock;

	log_line("Opening raw socket on ifindex %d", ifindex);
	if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
		log_error("socket call failed: %s", strerror(errno));
		goto out;
	}
	
	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_IP);
	sock.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
		log_error("bind call failed: %s", strerror(errno));
		goto out_fd;
	}

	return fd;
out_fd:
	close(fd);
out:
	return -1;
}

