/*
 * Shamelessly ripped off from busybox's udhcpc variant, which in turn was...
 * Mostly stolen from: dhcpcd - DHCP client daemon
 * by Yoichi Hariguchi <yoichi@fore.com>
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <sys/time.h>
#include <errno.h>
#include <poll.h>
#include "dhcpd.h"
#include "log.h"
#include "strl.h"
#include "io.h"

struct arpMsg {
    /* Ethernet header */
    uint8_t  h_dest[6];     /* 00 destination ether addr */
    uint8_t  h_source[6];   /* 06 source ether addr */
    uint16_t h_proto;       /* 0c packet type ID field */

    /* ARP packet */
    uint16_t htype;         /* 0e hardware type (must be ARPHRD_ETHER) */
    uint16_t ptype;         /* 10 protocol type (must be ETH_P_IP) */
    uint8_t  hlen;          /* 12 hardware address length (must be 6) */
    uint8_t  plen;          /* 13 protocol address length (must be 4) */
    uint16_t operation;     /* 14 ARP opcode */
    uint8_t  sHaddr[6];     /* 16 sender's hardware address */
    uint8_t  sInaddr[4];    /* 1c sender's IP address */
    uint8_t  tHaddr[6];     /* 20 target's hardware address */
    uint8_t  tInaddr[4];    /* 26 target's IP address */
    uint8_t  pad[18];       /* 2a pad for min. ethernet payload (60 bytes) */
};

enum {
    ARP_MSG_SIZE = 0x2a
};

static int safe_poll(struct pollfd *ufds, nfds_t nfds, int timeout)
{
    while (1) {
        int n = poll(ufds, nfds, timeout);
        if (n >= 0)
            return n;
        /* Make sure we inch towards completion */
        if (timeout > 0)
            timeout--;
        /* E.g. strace causes poll to return this */
        if (errno == EINTR)
            continue;
        /* Kernel is very low on memory. Retry. */
        /* I doubt many callers would handle this correctly! */
        if (errno == ENOMEM)
            continue;
        log_warning("poll error: %s", strerror(errno));
        return n;
    }
}

static unsigned long long curms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

/* Returns 1 if no reply received */
int arpping(uint32_t test_nip, const uint8_t *safe_mac, uint32_t from_ip,
            uint8_t *from_mac, const char *interface)
{
    int timeout_ms;
    struct pollfd pfd[1];
    int rv = 1;             /* "no reply received" yet */
    int opt = 1;
    struct sockaddr addr;   /* for interface name */
    struct arpMsg arp;

    pfd[0].fd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
    if (pfd[0].fd == -1) {
        log_warning("arpping: failed to create socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(pfd[0].fd, SOL_SOCKET, SO_BROADCAST,
                   &opt, sizeof opt) == -1) {
        log_warning("arpping: failed to set broadcast: %s", strerror(errno));
        goto ret;
    }

    /* send arp request */
    memset(&arp, 0, sizeof arp);
    memset(arp.h_dest, 0xff, 6);                    /* MAC DA */
    memcpy(arp.h_source, from_mac, 6);              /* MAC SA */
    arp.h_proto = htons(ETH_P_ARP);                 /* protocol type (Ethernet) */
    arp.htype = htons(ARPHRD_ETHER);                /* hardware type */
    arp.ptype = htons(ETH_P_IP);                    /* protocol type (ARP message) */
    arp.hlen = 6;                                   /* hardware address length */
    arp.plen = 4;                                   /* protocol address length */
    arp.operation = htons(ARPOP_REQUEST);           /* ARP op code */
    memcpy(arp.sHaddr, from_mac, 6);                /* source hardware address */
    memcpy(arp.sInaddr, &from_ip, sizeof from_ip); /* source IP address */
    /* tHaddr is zero-filled */                     /* target hardware address */
    memcpy(arp.tInaddr, &test_nip, sizeof test_nip);/* target IP address */

    memset(&addr, 0, sizeof addr);
    strlcpy(addr.sa_data, interface, sizeof addr.sa_data);
    if (safe_sendto(pfd[0].fd, (const char *)&arp, sizeof arp,
                    0, &addr, sizeof addr) < 0) {
        log_error("arpping: sendto failed: %s", strerror(errno));
        goto ret;
    }

    /* wait for arp reply, and check it */
    timeout_ms = 2000;
    do {
        typedef uint32_t aliased_uint32_t __attribute__((__may_alias__));
        int r;
        unsigned long long prevTime = curms();

        pfd[0].events = POLLIN;
        r = safe_poll(pfd, 1, timeout_ms);
        if (r < 0)
            break;
        if (r) {
            r = safe_read(pfd[0].fd, (char *)&arp, sizeof arp);
            if (r < 0)
                break;

            //log3("sHaddr %02x:%02x:%02x:%02x:%02x:%02x",
            //arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2],
            //arp.sHaddr[3], arp.sHaddr[4], arp.sHaddr[5]);

            if (r >= ARP_MSG_SIZE
                && arp.operation == htons(ARPOP_REPLY)
                /* don't check it: Linux doesn't return proper tHaddr (fixed in 2.6.24?) */
                /* && memcmp(arp.tHaddr, from_mac, 6) == 0 */
                && *(aliased_uint32_t*)arp.sInaddr == test_nip
                ) {
                /* if ARP source MAC matches safe_mac
                 * (which is client's MAC), then it's not a conflict
                 * (client simply already has this IP and replies to ARPs!)
                 */
                if (!safe_mac || memcmp(safe_mac, arp.sHaddr, 6) != 0)
                    rv = 0;
                break;
            }
        }
        timeout_ms -= (int)(curms() - prevTime);
    } while (timeout_ms > 0);

  ret:
    close(pfd[0].fd);
    log_line("%srp reply received for this address", rv ? "No a" : "A");
    return rv;
}
