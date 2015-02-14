#ifndef NDHC_SOCKD_H_
#define NDHC_SOCKD_H_

extern uid_t sockd_uid;
extern gid_t sockd_gid;
int request_sockd_fd(char buf[static 1], size_t buflen, char *response);
void sockd_main(void);

#endif /* NDHC_SOCKD_H_ */
