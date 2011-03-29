#ifndef NK_NETLINK_H_
#define NK_NETLINK_H_

int nl_open();
void nl_close();
void nl_queryifstatus(int ifidx);
int nl_getifdata(const char *ifname);

#endif /* NK_NETLINK_H_ */
