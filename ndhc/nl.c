#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "log.h"
#include "nl.h"

void nl_attr_parse(const struct nlmsghdr *nlh, size_t offset,
                   nl_attr_parse_fn workfn, void *data)
{
    struct nlattr *attr;
    for (attr = (struct nlattr *)
             ((char *)nlh + NLMSG_HDRLEN + NLMSG_ALIGN(offset));
         nl_attr_ok(attr, (char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) -
                    (char *)attr);
         attr = (struct nlattr *)((char *)attr + NLMSG_ALIGN(attr->nla_len)))
    {
        int type = attr->nla_type & NLA_TYPE_MASK;
        if (workfn(attr, type, data) < 0)
            break;
    }
}

ssize_t nl_recv_buf(int fd, char *buf, size_t blen)
{
    struct sockaddr_nl addr;
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = blen,
    };
    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof addr,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    size_t ret = recvmsg(fd, &msg, 0);
    if (ret == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            log_error("nl_fill_buf: recvmsg failed: %s", strerror(errno));
        return -1;
    }
    if (msg.msg_flags & MSG_TRUNC) {
        log_error("nl_fill_buf: buffer not long enough for message");
        return -1;
    }
    if (msg.msg_namelen != sizeof addr) {
        log_error("nl_fill_buf: response was not of the same address family");
        return -1;
    }
    return ret;
}

int nl_foreach_nlmsg(char *buf, size_t blen, int portid,
                     nlmsg_foreach_fn pfn, void *fnarg)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;

    assert(pfn);
    while (NLMSG_OK(nlh, blen)) {
        // PortID should be zero for messages from the kernel.
        if (nlh->nlmsg_pid && nlh->nlmsg_pid != portid)
            continue;
        // XXX don't bother with sequence # tracking (0 = kernel, ours = ??)

        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
            pfn(nlh, fnarg);
        } else {
            switch (nlh->nlmsg_type) {
                case NLMSG_ERROR:
                    log_line("nl: received a NLMSG_ERROR: %s",
                             strerror(nlmsg_get_error(nlh)));
                    return -1;
                case NLMSG_DONE:
                    return 0;
                case NLMSG_OVERRUN:
                    log_line("nl: received a NLMSG_OVERRUN");
                case NLMSG_NOOP:
                default:
                    break;
            }
        }
        nlh = NLMSG_NEXT(nlh, blen);
    }
    return 0;
}

int nl_open(int nltype, int nlgroup, int *nlportid)
{
    int fd;
    fd = socket(AF_NETLINK, SOCK_RAW, nltype);
    if (fd == -1) {
        log_error("nl_open: socket failed: %s", strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
        log_error("nl_open: set non-blocking failed: %s", strerror(errno));
        goto err_close;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
        log_error("nl_open: set close-on-exec failed: %s", strerror(errno));
        goto err_close;
    }
    socklen_t al;
    struct sockaddr_nl nlsock = {
        .nl_family = AF_NETLINK,
        .nl_groups = nlgroup,
    };
    if (bind(fd, (struct sockaddr *)&nlsock, sizeof nlsock) == -1) {
        log_error("nl_open: bind to group failed: %s", strerror(errno));
        goto err_close;
    }
    al = sizeof nlsock;
    if (getsockname(fd, (struct sockaddr *)&nlsock, &al) == -1) {
        log_error("nl_open: getsockname failed: %s", strerror(errno));
        goto err_close;
    }
    if (al != sizeof nlsock) {
        log_error("nl_open: bound socket doesn't have right family size");
        goto err_close;
    }
    if (nlsock.nl_family != AF_NETLINK) {
        log_error("nl_open: bound socket isn't AF_NETLINK");
        goto err_close;
    }
    if (nlportid)
        *nlportid = nlsock.nl_pid;
    return fd;
  err_close:
    close(fd);
    return -1;
}

