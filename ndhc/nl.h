#ifndef NK_NL_H_
#define NK_NL_H_

// Limited netlink code.  The horrors...

#include <linux/netlink.h>
//#include <linux/rtnetlink.h>

static inline int nl_attr_ok(const struct nlattr *attr, size_t len)
{
    if (len < sizeof *attr)
        return 0;
    if (attr->nla_len < sizeof *attr)
        return 0;
    if (attr->nla_len > len)
        return 0;
    return 1;
}

static inline size_t nlattr_get_len(const struct nlattr *attr)
{
    return attr->nla_len;
}

static inline void *nlattr_get_data(const struct nlattr *attr)
{
    return (char *)attr + NLA_HDRLEN;
}

static inline void *nlmsg_get_data(const struct nlmsghdr *nlh)
{
    return (char *)nlh + NLMSG_HDRLEN;
}

static inline int nlmsg_get_error(const struct nlmsghdr *nlh)
{
    const struct nlmsgerr *err = nlmsg_get_data(nlh);
    if (nlh->nlmsg_len < sizeof(struct nlmsgerr) + NLMSG_HDRLEN)
        return EBADMSG;
    return err->error & 0x7fffffff;
}

typedef int (*nl_attr_parse_fn)(struct nlattr *attr, int type, void *data);
void nl_attr_parse(const struct nlmsghdr *nlh, size_t offset,
                   nl_attr_parse_fn workfn, void *data);

ssize_t nl_recv_buf(int fd, char *buf, size_t blen);

typedef int (*nlmsg_foreach_fn)(const struct nlmsghdr *, void *);
int nl_foreach_nlmsg(char *buf, size_t blen, int portid,
                     nlmsg_foreach_fn pfn, void *fnarg);

int nl_open(int nltype, int nlgroup, int *nlportid);

#endif /* NK_NL_H_ */
