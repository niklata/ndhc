#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <errno.h>

#include "packet.h"
#include "clientpacket.h"
#include "script.h"
#include "log.h"
#include "io.h"
#include "dhcpd.h"
#include "options.h"

/* Read a packet from socket fd, return -1 on read error, -2 on packet error */
int get_packet(struct dhcpMessage *packet, int fd)
{
    int bytes;

    memset(packet, 0, DHCP_SIZE);
    bytes = safe_read(fd, (char *)packet, DHCP_SIZE);
    if (bytes == -1) {
	log_line("Read on listen socket failed: %s", strerror(errno));
	return -1;
    }

    if (ntohl(packet->cookie) != DHCP_MAGIC) {
	log_error("Packet with bad magic number, ignoring.");
	return -2;
    }
    log_line("Received a packet");

    return bytes;
}

/* Compute Internet Checksum for @count bytes beginning at location @addr. */
uint16_t checksum(void *addr, int count)
{
    register int32_t sum = 0;
    uint16_t *source = (uint16_t *)addr;

    while (count > 1)  {
	sum += *source++;
	count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0) {
	/* Make sure that the left-over byte is added correctly both
	 * with little and big endian hosts */
	uint16_t tmp = 0;
	*(uint8_t *)&tmp = *(uint8_t *)source;
	sum += tmp;
    }
    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

/* Constuct a ip/udp header for a packet, and specify the source and dest
 * hardware address */
int raw_packet(struct dhcpMessage *payload, uint32_t source_ip,
               int source_port, uint32_t dest_ip, int dest_port,
               unsigned char *dest_arp, int ifindex)
{
    struct sockaddr_ll dest;
    struct ip_udp_dhcp_packet packet;
    int fd, r = -1;
    unsigned int padding;

    if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
	log_error("raw_packet: socket failed: %s", strerror(errno));
	goto out;
    }

    memset(&dest, 0, sizeof dest);
    memset(&packet, 0, offsetof(struct ip_udp_dhcp_packet, data));
    packet.data = *payload; /* struct copy */

    dest.sll_family = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_IP);
    dest.sll_ifindex = ifindex;
    dest.sll_halen = 6;
    memcpy(dest.sll_addr, dest_arp, 6);
    if (bind(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll)) < 0) {
	log_error("raw_packet: bind failed: %s", strerror(errno));
	goto out_fd;
    }

    /* We were sending full-sized DHCP packets (zero padded),
     * but some badly configured servers were seen dropping them.
     * Apparently they drop all DHCP packets >576 *ethernet* octets big,
     * whereas they may only drop packets >576 *IP* octets big
     * (which for typical Ethernet II means 590 octets: 6+6+2 + 576).
     *
     * In order to work with those buggy servers,
     * we truncate packets after end option byte.
     */
    padding = DHCP_OPTIONS_BUFSIZE - 1 - end_option(packet.data.options);

    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.saddr = source_ip;
    packet.ip.daddr = dest_ip;
    packet.udp.source = htons(source_port);
    packet.udp.dest = htons(dest_port);
    /* size, excluding IP header: */
    packet.udp.len = htons(UPD_DHCP_SIZE - padding);
    /* for UDP checksumming, ip.len is set to UDP packet len */
    packet.ip.tot_len = packet.udp.len;
    packet.udp.check = checksum(&packet, IP_UPD_DHCP_SIZE - padding);
    /* but for sending, it is set to IP packet len */
    packet.ip.tot_len = htons(IP_UPD_DHCP_SIZE - padding);
    packet.ip.ihl = sizeof packet.ip >> 2;
    packet.ip.version = IPVERSION;
    packet.ip.ttl = IPDEFTTL;
    packet.ip.check = checksum(&packet.ip, sizeof packet.ip);

    r = safe_sendto(fd, (const char *)&packet, IP_UPD_DHCP_SIZE - padding,
		    0, (struct sockaddr *)&dest, sizeof dest);
    if (r == -1)
	log_error("raw_packet: sendto failed: %s", strerror(errno));
  out_fd:
    close(fd);
  out:
    return r;
}

/* Let the kernel do all the work for packet generation */
int kernel_packet(struct dhcpMessage *payload, uint32_t source_ip,
		  int source_port, uint32_t dest_ip, int dest_port)
{
    struct sockaddr_in client;
    int opt = 1, fd, result = -1;
    unsigned int padding;

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	goto out;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1)
	goto out_fd;

    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(source_port);
    client.sin_addr.s_addr = source_ip;

    if (bind(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
	goto out_fd;

    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(dest_port);
    client.sin_addr.s_addr = dest_ip;

    if (connect(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
	goto out_fd;

    padding = DHCP_OPTIONS_BUFSIZE - 1 - end_option(payload->options);
    result = safe_write(fd, (const char *)payload, DHCP_SIZE - padding);
    if (result == -1)
	log_error("kernel_packet: write failed: %s", strerror(errno));
  out_fd:
    close(fd);
  out:
    return result;
}

static void init_selecting_packet(struct client_state_t *cs,
                                  struct dhcpMessage *packet,
                                  unsigned char *message)
{
    unsigned char *temp = NULL;
    /* Must be a DHCPOFFER to one of our xid's */
    if (*message == DHCPOFFER) {
        if ((temp = get_option(packet, DHCP_SERVER_ID))) {
            /* Memcpy to a temp buffer to force alignment */
            memcpy(&cs->serverAddr, temp, 4);
            cs->xid = packet->xid;
            cs->requestedIP = packet->yiaddr;

            /* enter requesting state */
            cs->dhcpState = DS_REQUESTING;
            cs->timeout = 0;
            cs->packetNum = 0;
        } else {
            log_line("No server ID in message");
        }
    }
}

// from ndhc.c
void change_listen_mode(int new_mode);
void arp_check(struct dhcpMessage *packet);

static void dhcp_ack_or_nak_packet(struct client_state_t *cs,
                                   struct dhcpMessage *packet,
                                   unsigned char *message)
{
    unsigned char *temp = NULL;
    if (*message == DHCPACK) {
        if (!(temp = get_option(packet, DHCP_LEASE_TIME))) {
            log_line("No lease time received, assuming 1h.");
            cs->lease = 60 * 60;
        } else {
            /* Memcpy to a temp buffer to force alignment */
            memcpy(&cs->lease, temp, 4);
            cs->lease = ntohl(cs->lease);
            /* Enforce upper and lower bounds on lease. */
            cs->lease &= 0x0fffffff;
            if (cs->lease < RETRY_DELAY)
                cs->lease = RETRY_DELAY;
        }

        arp_check(packet);
        // Can transition from DS_ARP_CHECK to DS_BOUND or DS_INIT_SELECTING.

    } else if (*message == DHCPNAK) {
        /* return to init state */
        log_line("Received DHCP NAK.");
        run_script(packet, SCRIPT_NAK);
        if (cs->dhcpState != DS_REQUESTING)
            run_script(NULL, SCRIPT_DECONFIG);
        cs->dhcpState = DS_INIT_SELECTING;
        cs->timeout = 0;
        cs->requestedIP = 0;
        cs->packetNum = 0;
        change_listen_mode(LM_RAW);
        // XXX: this isn't rfc compliant: should be exp backoff
        sleep(3); /* avoid excessive network traffic */
    }
}

void handle_packet(struct client_state_t *cs)
{
    unsigned char *message = NULL;
    int len;
    struct dhcpMessage packet;

    if (cs->listenMode == LM_KERNEL)
        len = get_packet(&packet, cs->listenFd);
    else if (cs->listenMode == LM_RAW)
        len = get_raw_packet(&packet, cs->listenFd);
    else /* LM_NONE */
        return;

    if (len == -1 && errno != EINTR) {
        log_error("reopening socket.");
        change_listen_mode(cs->listenMode); /* just close and reopen */
    }

    if (len < 0)
        return;

    if (packet.xid != cs->xid) {
        log_line("Ignoring XID %lx (our xid is %lx).",
                 (uint32_t) packet.xid, cs->xid);
        return;
    }

    if ((message = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
        log_line("couldnt get option from packet -- ignoring");
        return;
    }

    switch (cs->dhcpState) {
        case DS_INIT_SELECTING:
            init_selecting_packet(cs, &packet, message);
            break;
        case DS_ARP_CHECK:
            /* We ignore dhcp packets for now.  This state will
             * be changed by the callback for arp ping.
             */
            break;
        case DS_RENEW_REQUESTED:
        case DS_REQUESTING:
        case DS_RENEWING:
        case DS_REBINDING:
            dhcp_ack_or_nak_packet(cs, &packet, message);
            break;
        case DS_BOUND:
        case DS_RELEASED:
        default:
            break;
    }
}
