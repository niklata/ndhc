/* sockd.c - privsep socket creation daemon
 *
 * Copyright (c) 2014 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <linux/filter.h>
#include <pwd.h>
#include <grp.h>
#include "nk/log.h"
#include "nk/io.h"
#include "nk/privilege.h"

#include "sockd.h"
#include "ndhc-defines.h"
#include "ndhc.h"
#include "dhcp.h"
#include "sys.h"
#include "seccomp.h"

static int epollfd, signalFd;
/* Slots are for signalFd and the ndhc -> ifchd socket. */
static struct epoll_event events[2];

uid_t sockd_uid = 0;
gid_t sockd_gid = 0;

// Interface to make requests of sockd.  Called from ndhc process.
int request_sockd_fd(char *buf, size_t buflen, char *response)
{
    if (!buflen)
        return -1;
    ssize_t r = safe_write(sockdSock[0], buf, buflen);
    if (r < 0 || (size_t)r != buflen)
        suicide("%s: (%s) write failed: %d", client_config.interface,
                __func__, r);

    char data[MAX_BUF], control[MAX_BUF];
    struct iovec iov = {
        .iov_base = data,
        .iov_len = sizeof data - 1,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof control
    };
    r = safe_recvmsg(sockdSock[0], &msg, 0);
    if (r == 0) {
        suicide("%s: (%s) recvmsg received EOF", client_config.interface,
                __func__);
    } else if (r < 0) {
        suicide("%s: (%s) recvmsg failed: %s", client_config.interface,
                __func__, strerror(errno));
    }
    data[iov.iov_len] = '\0';
    char repc = data[0];
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            if (response)
                *response = repc;
            else if (repc != buf[0])
                suicide("%s: (%s) expected %c sockd reply but got %c",
                        client_config.interface, __func__, buf[0], repc);
            int *fd = (int *)CMSG_DATA(cmsg);
            return *fd;
        }
    }
    suicide("%s: (%s) sockd reply did not include a fd",
            client_config.interface, __func__);
}

static int create_arp_socket(void)
{
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ARP));
    if (fd < 0) {
        log_error("%s: (%s) socket failed: %s", client_config.interface,
                  __func__, strerror(errno));
        goto out;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof opt) < 0) {
        log_error("%s: (%s) setsockopt failed: %s", client_config.interface,
                  __func__, strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
        log_error("%s: (%s) fcntl failed: %s", client_config.interface,
                  __func__, strerror(errno));
        goto out_fd;
    }
    struct sockaddr_ll saddr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ARP),
        .sll_ifindex = client_config.ifindex,
    };
    if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_ll)) < 0) {
        log_error("%s: (%s) bind failed: %s", client_config.interface,
                  __func__, strerror(errno));
        goto out_fd;
    }
    return fd;
  out_fd:
    close(fd);
  out:
    return -1;
}

// Returns fd of new udp socket bound on success, or -1 on failure.
static int create_udp_socket(uint32_t ip, uint16_t port, char *iface)
{
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) < 0) {
        log_error("%s: (%s) socket failed: %s",
                  client_config.interface, __func__, strerror(errno));
        goto out;
    }
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) < 0) {
        log_error("%s: (%s) Set reuse addr failed: %s",
                  client_config.interface, __func__, strerror(errno));
        goto out_fd;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) < 0) {
        log_error("%s: (%s) Set don't route failed: %s",
                  client_config.interface, __func__, strerror(errno));
        goto out_fd;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ssize_t sl = snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface);
    if (sl < 0 || (size_t)sl >= sizeof ifr.ifr_name) {
        log_error("%s: (%s) Set interface name failed.",
                  client_config.interface, __func__);
        goto out_fd;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0) {
        log_error("%s: (%s) Set bind to device failed: %s",
                  client_config.interface, __func__, strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
        log_error("%s: (%s) Set non-blocking failed: %s",
                  client_config.interface, __func__, strerror(errno));
        goto out_fd;
    }

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = ip,
    };
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        log_error("%s: (%s) bind failed: %s",
                  client_config.interface, __func__, strerror(errno));
        goto out_fd;
    }

    return fd;
  out_fd:
    close(fd);
  out:
    return -1;
}

static int create_raw_socket(struct sockaddr_ll *sa, bool *using_bpf,
                             const struct sock_fprog *filter_prog)
{
    int fd;
    if ((fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK,
                     htons(ETH_P_IP))) < 0) {
        log_error("create_raw_socket: socket failed: %s", strerror(errno));
        goto out;
    }

    if (using_bpf)
        *using_bpf = false;
    if (filter_prog) {
        int r = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, filter_prog,
                           sizeof *filter_prog);
        if (r >= 0) {
            int tv = 1;
            r = setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &tv, sizeof tv);
            if (r >= 0) {
                if (using_bpf)
                    *using_bpf = true;
            } else
                log_warning("%s: Failed to lock BPF for raw socket: %s",
                            client_config.interface, strerror(errno));
        } else
            log_warning("%s: Failed to set BPF for raw socket: %s",
                        client_config.interface, strerror(errno));
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof opt) < 0) {
        log_error("create_raw_socket: Failed to set don't route: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
        log_error("create_raw_socket: Set non-blocking failed: %s",
                  strerror(errno));
        goto out_fd;
    }
    if (bind(fd, (struct sockaddr *)sa, sizeof *sa) < 0) {
        log_error("create_raw_socket: bind failed: %s", strerror(errno));
        goto out_fd;
    }
    return fd;
out_fd:
    close(fd);
out:
    return -1;
}

static int create_raw_listen_socket(bool *using_bpf)
{
    static const struct sock_filter sf_dhcp[] = {
        // Verify that the packet has a valid IPv4 version nibble and
        // that no IP options are defined.
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x45, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Verify that the IP header has a protocol number indicating UDP.
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 9),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Make certain that the packet is not a fragment.  All bits in
        // the flag and fragment offset field must be set to zero except
        // for the Evil and DF bits (0,1).
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 6),
        BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x3fff, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Packet is UDP.  Advance X past the IP header.
        BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),
        // Verify that the UDP client and server ports match that of the
        // IANA-assigned DHCP ports.
        BPF_STMT(BPF_LD + BPF_W + BPF_IND, 0),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                 (DHCP_SERVER_PORT << 16) + DHCP_CLIENT_PORT, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Get the UDP length field and store it in X.
        BPF_STMT(BPF_LD + BPF_H + BPF_IND, 4),
        BPF_STMT(BPF_MISC + BPF_TAX, 0),
        // Get the IPv4 length field and store it in A and M[0].
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 2),
        BPF_STMT(BPF_ST, 0),
        // Verify that UDP length = IP length - IP header size
        BPF_STMT(BPF_ALU + BPF_SUB + BPF_K, 20),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Pass the number of octets that are specified in the IPv4 header.
        BPF_STMT(BPF_LD + BPF_MEM, 0),
        BPF_STMT(BPF_RET + BPF_A, 0),
    };
    static const struct sock_fprog sfp_dhcp = {
        .len = sizeof sf_dhcp / sizeof sf_dhcp[0],
        .filter = (struct sock_filter *)sf_dhcp,
    };
    struct sockaddr_ll sa = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = client_config.ifindex,
    };
    return create_raw_socket(&sa, using_bpf, &sfp_dhcp);
}

static int create_raw_broadcast_socket(void)
{
    struct sockaddr_ll da = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_pkttype = PACKET_BROADCAST,
        .sll_ifindex = client_config.ifindex,
        .sll_halen = 6,
    };
    memcpy(da.sll_addr, "\xff\xff\xff\xff\xff\xff", 6);
    return create_raw_socket(&da, NULL, NULL);
}

static bool arp_set_bpf_basic(int fd)
{
    static const struct sock_filter sf_arp[] = {
        // Verify that the frame has ethernet protocol type of ARP
        // and that the ARP hardware type field indicates Ethernet.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 12),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_ARP << 16) | ARPHRD_ETHER,
                 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Verify that the ARP protocol type field indicates IP, the ARP
        // hardware address length field is 6, and the ARP protocol address
        // length field is 4.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 16),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_IP << 16) | 0x0604, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Sanity tests passed, so send all possible data.
        BPF_STMT(BPF_RET + BPF_K, 0x7fffffff),
    };
    static const struct sock_fprog sfp_arp = {
        .len = sizeof sf_arp / sizeof sf_arp[0],
        .filter = (struct sock_filter *)sf_arp,
    };
    int ret = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sfp_arp,
                         sizeof sfp_arp) != -1;
    if (ret >= 0) {
        int tv = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &tv, sizeof tv);
        // Return true IIF we ATTACHed and LOCKed the filter.  If
        // we attached but failed to lock, then we still want the manual
        // checks to run just in case an attacker tries to DETACH the
        // filter.
        if (ret < 0)
            log_warning("%s: Failed to lock BPF for basic ARP socket: %s",
                        client_config.interface, strerror(errno));
        return ret >= 0;
    } else
        log_warning("%s: Failed to set BPF for basic ARP socket: %s",
                    client_config.interface, strerror(errno));
    return false;
}

static bool arp_set_bpf_defense(int fd, uint32_t client_addr,
                                uint8_t client_mac[6])
{
    uint32_t mac4b;
    uint16_t mac2b;
    memcpy(&mac4b, client_mac, 4);
    memcpy(&mac2b, client_mac + 4, 2);

    struct sock_filter sf_arp[] = {
        // Verify that the frame has ethernet protocol type of ARP
        // and that the ARP hardware type field indicates Ethernet.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 12),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_ARP << 16) | ARPHRD_ETHER,
                 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // Verify that the ARP protocol type field indicates IP, the ARP
        // hardware address length field is 6, and the ARP protocol address
        // length field is 4.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 16),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (ETH_P_IP << 16) | 0x0604, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),

        // If the ARP packet source IP does not match our IP address, then
        // it can be ignored.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 28),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, client_addr, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0),
        // If the first four bytes of the ARP packet source hardware address
        // does not equal our hardware address, then it's a conflict and should
        // be passed along.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 22),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac4b, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0x7fffffff),
        // If the last two bytes of the ARP packet source hardware address
        // do not equal our hardware address, then it's a conflict and should
        // be passed along.
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 26),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac2b, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, 0x7fffffff),
        // Packet announces our IP address and hardware address, so it requires
        // no action.
        BPF_STMT(BPF_RET + BPF_K, 0),
    };
    struct sock_fprog sfp_arp = {
        .len = sizeof sf_arp / sizeof sf_arp[0],
        .filter = (struct sock_filter *)sf_arp,
    };
    int ret = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &sfp_arp,
                         sizeof sfp_arp) != -1;
    if (ret >= 0) {
        int tv = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &tv, sizeof tv);
        // Return true IIF we ATTACHed and LOCKed the filter.  If
        // we attached but failed to lock, then we still want the manual
        // checks to run just in case an attacker tries to DETACH the
        // filter.
        if (ret < 0)
            log_warning("%s: Failed to lock BPF for defense ARP socket: %s",
                        client_config.interface, strerror(errno));
        return ret >= 0;
    } else
        log_warning("%s: Failed to set BPF for defense ARP socket: %s",
                    client_config.interface, strerror(errno));
    return false;
}

static int create_arp_defense_socket(uint32_t client_addr,
                                     uint8_t client_mac[6], bool *using_bpf)
{
    assert(using_bpf);
    int fd = create_arp_socket();
    *using_bpf = arp_set_bpf_defense(fd, client_addr, client_mac);
    return fd;
}

static int create_arp_basic_socket(bool *using_bpf)
{
    assert(using_bpf);
    int fd = create_arp_socket();
    *using_bpf = arp_set_bpf_basic(fd);
    return fd;
}

static void xfer_fd(int fd, char cmd)
{
    char control[sizeof(struct cmsghdr) + 10];
    struct iovec iov = {
        .iov_base = &cmd,
        .iov_len = 1,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof control,
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof fd);
    int *cmsg_fd = (int *)CMSG_DATA(cmsg);
    *cmsg_fd = fd;
    msg.msg_controllen = cmsg->cmsg_len;
  retry:
    if (sendmsg(sockdSock[1], &msg, 0) < 0) {
        if (errno == EINTR)
            goto retry;
        suicide("%s: (%s) sendmsg failed: %s", client_config.interface,
                __func__, strerror(errno));
    }
    close(fd);
}

static size_t execute_sockd(char *buf, size_t buflen)
{
    if (!buflen)
        return 0;

    char c = buf[0];
    switch (c) {
    case 'L': {
        bool using_bpf;
        int fd = create_raw_listen_socket(&using_bpf);
        xfer_fd(fd, using_bpf ? 'L' : 'l');
        return 1;
    }
    case 'a': {
        bool using_bpf;
        int fd = create_arp_basic_socket(&using_bpf);
        xfer_fd(fd, using_bpf ? 'A' : 'a'); return 1;
    }
    case 'd': {
        uint32_t client_addr;
        uint8_t client_mac[6];
        bool using_bpf;
        if (buflen < 1 + sizeof client_addr + 6)
            suicide("%s: (%s) 'd' does not have necessary arguments: %zu",
                      client_config.interface, __func__, buflen);
        memcpy(&client_addr, buf + 1, sizeof client_addr);
        memcpy(client_mac, buf + 1 + sizeof client_addr, 6);
        int fd = create_arp_defense_socket(client_addr, client_mac,
                                           &using_bpf);
        xfer_fd(fd, using_bpf ? 'D' : 'd');
        return 11;
    }
    case 's': xfer_fd(create_raw_broadcast_socket(), 's'); return 1;
    case 'u': {
        uint32_t client_addr;
        if (buflen < 1 + sizeof client_addr)
            suicide("%s: (%s) 'u' does not have necessary arguments: %zu",
                      client_config.interface, __func__, buflen);
        memcpy(&client_addr, buf + 1, sizeof client_addr);
        xfer_fd(create_udp_socket(client_addr, DHCP_CLIENT_PORT,
                                  client_config.interface), 'u');
        return 5;
    }
    default: suicide("%s: (%s) received invalid commands: '%c'",
                     client_config.interface, __func__, c);
    }
}

static void process_client_socket(void)
{
    static char buf[MAX_BUF];
    static size_t buflen;

    if (buflen == MAX_BUF)
        suicide("%s: (%s) receive buffer exhausted", client_config.interface,
                __func__);

    int r = safe_recv(sockdSock[1], buf + buflen, sizeof buf - buflen,
                      MSG_DONTWAIT);
    if (r == 0) {
        // Remote end hung up.
        exit(EXIT_SUCCESS);
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        suicide("%s: (%s) error reading from ndhc -> sockd socket: %s",
                client_config.interface, __func__, strerror(errno));
    }
    buflen += (size_t)r;
    buflen -= execute_sockd(buf, buflen);
}

static void do_sockd_work(void)
{
    epollfd = epoll_create1(0);
    if (epollfd < 0)
        suicide("epoll_create1 failed");

    if (enforce_seccomp_sockd())
        log_line("sockd seccomp filter cannot be installed");

    epoll_add(epollfd, sockdSock[1]);
    epoll_add(epollfd, sockdStream[1]);
    epoll_add(epollfd, signalFd);

    for (;;) {
        int r = epoll_wait(epollfd, events, 3, -1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        for (int i = 0; i < r; ++i) {
            int fd = events[i].data.fd;
            if (fd == sockdSock[1]) {
                if (events[i].events & EPOLLIN)
                    process_client_socket();
            } else if (fd == sockdStream[1]) {
                if (events[i].events & (EPOLLHUP|EPOLLERR|EPOLLRDHUP))
                    exit(EXIT_SUCCESS);
            } else if (fd == signalFd) {
                if (events[i].events & EPOLLIN)
                    signal_dispatch_subprocess(signalFd, "sockd");
            } else
                suicide("sockd: unexpected fd while performing epoll");
        }
    }
}

void sockd_main(void)
{
    prctl(PR_SET_NAME, "ndhc: sockd");
    umask(077);
    signalFd = setup_signals_subprocess();
    nk_set_chroot(chroot_dir);
    memset(chroot_dir, 0, sizeof chroot_dir);
    unsigned char keepcaps[] = { CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST,
                                 CAP_NET_RAW };
    nk_set_uidgid(sockd_uid, sockd_gid, keepcaps, sizeof keepcaps);
    do_sockd_work();
}

