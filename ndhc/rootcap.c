#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <grp.h>

#include "log.h"

void set_cap(uid_t uid, gid_t gid, char *captxt)
{
    cap_t caps;

    if (!captxt) {
        log_error("FATAL - set_cap: captxt == NULL");
        exit(EXIT_FAILURE);
    }

    if (prctl(PR_SET_KEEPCAPS, 1)) {
        log_error("FATAL - set_cap: prctl() failed");
        exit(EXIT_FAILURE);
    }

    if (setgroups(0, NULL) == -1) {
            log_error("FATAL - set_cap: setgroups() failed");
            exit(EXIT_FAILURE);
    }

    if (setegid(gid) == -1 || seteuid(uid) == -1) {
            log_error("FATAL - set_cap: seteuid() failed");
            exit(EXIT_FAILURE);
    }

    caps = cap_from_text(captxt);
    if (!caps) {
        log_error("FATAL - set_cap: cap_from_text() failed");
        exit(EXIT_FAILURE);
    }

    if (cap_set_proc(caps) == -1) {
        log_error("FATAL - set_cap: cap_set_proc() failed");
        exit(EXIT_FAILURE);
    }

    cap_free(caps);
}
