/* script.c
 *
 * Functions to call the interface change daemon
 *
 * Russ Dill <Russ.Dill@asu.edu> July 2001
 * Nicholas Kain <njk@nozspamz.aerifal.cx> 2004
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

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <errno.h>

#include "options.h"
#include "dhcpd.h"
#include "dhcpc.h"
#include "packet.h"
#include "options.h"
#include "log.h"
#include "script.h"

static int snprintip(char *dest, size_t size, unsigned char *ip) {
	if (!dest) return -1;
	return snprintf(dest, size, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

static int sprintip(char *dest, size_t size, char *pre, unsigned char *ip) {
	if (!dest) return -1;
	return snprintf(dest, size, "%s%d.%d.%d.%d", pre, ip[0], ip[1], ip[2], ip[3]);
}

/* Fill dest with the text of option 'option'. */
static void fill_options(char *dest, unsigned char *option, struct dhcp_option *type_p, unsigned int maxlen)
{
	int type, optlen;
	uint16_t val_u16;
	int16_t val_s16;
	uint32_t val_u32;
	int32_t val_s32;
	int len = option[OPT_LEN - 2];
	char *odest;
	
	odest = dest;
	
	dest += snprintf(dest, maxlen, "%s=", type_p->name);

	type = type_p->flags & TYPE_MASK;
	optlen = option_lengths[type];
	for(;;) {
		switch (type) {
		case OPTION_IP_PAIR:
			dest += sprintip(dest, maxlen - (dest - odest), "", option);
			*(dest++) = '/';
			option += 4;
			optlen = 4;
		case OPTION_IP:	/* Works regardless of host byte order. */
			dest += sprintip(dest, maxlen - (dest - odest), "", option);
 			break;
		case OPTION_BOOLEAN:
			dest += snprintf(dest, maxlen - (dest - odest), *option ? "yes " : "no ");
			break;
		case OPTION_U8:
			dest += snprintf(dest, maxlen - (dest - odest), "%u ", *option);
			break;
		case OPTION_U16:
			memcpy(&val_u16, option, 2);
			dest += snprintf(dest, maxlen - (dest - odest), "%u ", ntohs(val_u16));
			break;
		case OPTION_S16:
			memcpy(&val_s16, option, 2);
			dest += snprintf(dest, maxlen - (dest - odest), "%d ", ntohs(val_s16));
			break;
		case OPTION_U32:
			memcpy(&val_u32, option, 4);
			dest += snprintf(dest, maxlen - (dest - odest), "%lu ", (unsigned long) ntohl(val_u32));
			break;
		case OPTION_S32:
			memcpy(&val_s32, option, 4);
			dest += snprintf(dest, maxlen - (dest - odest), "%ld ", (long) ntohl(val_s32));
			break;
		case OPTION_STRING:
			if ( (maxlen - (dest - odest)) < (unsigned)len) return;
			memcpy(dest, option, len);
			dest[len] = '\0';
			return;	 /* Short circuit this case */
		}
		option += optlen;
		len -= optlen;
		if (len <= 0) break;
	}
}

static int open_ifch(void) {
	int sockfd, ret;
	struct sockaddr_un address = 
	{
		.sun_family = AF_UNIX,
		.sun_path = "ifchange"
	};

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	ret = connect(sockfd, (struct sockaddr *)&address, sizeof(address));

	if (ret == -1) {
		log_line(LOG_ERR, "unable to connect to ifchd!\n");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

static void sockwrite(int fd, const void *buf, size_t count)
{
	int ret;

sockwrite_again:
	ret = write(fd, buf, count);
	if (ret == -1) {
		if (errno == EAGAIN)
			goto sockwrite_again;
		log_line(LOG_ERR, "error while writing to unix socket!\n");
		exit(EXIT_FAILURE);
	}
	if (ret < 0) ret = 0;
	if ((unsigned int)ret < strlen(buf)) {
		log_line(LOG_ERR, "incomplete write!\n");
	}
	debug(LOG_INFO, "writing: %s\n", (char *)buf);
}			

static void deconfig_if(void)
{
	int sockfd;
	char buf[256];
	
	memset(buf, '\0', sizeof buf);
	
	sockfd = open_ifch();
	
	snprintf(buf, sizeof buf, "interface:%s:",
		       client_config.interface);
	sockwrite(sockfd, buf, strlen(buf));

	snprintf(buf, sizeof buf, "ip:0.0.0.0:");
	sockwrite(sockfd, buf, strlen(buf));
	
	close(sockfd);
	exit(EXIT_SUCCESS);
}

static void translate_option(int sockfd, struct dhcpMessage *packet, int opt) {
	char buf[256], buf2[256];
	unsigned char *p;
	int i;

	if (!packet) return;

	memset(buf, '\0', sizeof(buf));
	memset(buf2, '\0', sizeof(buf2));
	
	p = get_option(packet, options[opt].code);
	fill_options(buf2, p, &options[opt], sizeof(buf2) - 1);
	snprintf(buf, sizeof buf, "%s:", buf2);
	for (i=0; i<256; i++) {
		if (buf[i] == '\0') break;
		if (buf[i] == '=') {
			buf[i] = ':';
			break;
		}
	}
	sockwrite(sockfd, buf, strlen(buf));
}

static void bound_if(struct dhcpMessage *packet)
{
	int sockfd;
	char buf[256], buf2[256];
	char ip[32];
	
	if (!packet) return;
	
	memset(buf, '\0', sizeof(buf));
	memset(ip, '\0', sizeof(ip));
	memset(buf2, '\0', sizeof(buf2));
	
	sockfd = open_ifch();

	snprintf(buf, sizeof buf, "interface:%s:", client_config.interface);
	sockwrite(sockfd, buf, strlen(buf));

	snprintip(ip, sizeof ip, (unsigned char *) &packet->yiaddr);
	snprintf(buf, sizeof buf, "ip:%s:", ip);
	sockwrite(sockfd, buf, strlen(buf));
	
	translate_option(sockfd, packet, 0);
	translate_option(sockfd, packet, 2);
	translate_option(sockfd, packet, 5);
	translate_option(sockfd, packet, 9);
	translate_option(sockfd, packet, 11);
	translate_option(sockfd, packet, 15);
	translate_option(sockfd, packet, 16);
	translate_option(sockfd, packet, 17);
	
	close(sockfd);
	exit(EXIT_SUCCESS);
}

void run_script(struct dhcpMessage *packet, int mode)
{
	int pid;
	
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
		return;
	} else if (pid == 0) {
		switch (mode) {
			case SCRIPT_DECONFIG:
				deconfig_if();
				break;
			case SCRIPT_BOUND:
				bound_if(packet);
				break;
			case SCRIPT_RENEW:
				bound_if(packet);
				break;
			case SCRIPT_NAK:
				deconfig_if();
				break;
			default:
				break;
		}
		log_line(LOG_ERR, "invalid script mode: %d\n", mode);
		exit(EXIT_FAILURE);
	}
}

