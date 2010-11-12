#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <grp.h>

#include "log.h"

static void set_cap(uid_t uid, gid_t gid, char *captxt) 
{
    cap_t caps;

    if (!captxt) {
        log_line(LOG_ERR, "FATAL - set_cap: captxt == NULL\n");
        exit(EXIT_FAILURE);
    }
    
    if (prctl(PR_SET_KEEPCAPS, 1)) {
        log_line(LOG_ERR, "FATAL - set_cap: prctl() failed\n");
        exit(EXIT_FAILURE);
    }

    if (setgroups(0, NULL) == -1) {
	    log_line(LOG_ERR, "FATAL - set_cap: setgroups() failed\n");
	    exit(EXIT_FAILURE);
    }

    if (setegid(gid) == -1 || seteuid(uid) == -1) {
	    log_line(LOG_ERR, "FATAL - set_cap: seteuid() failed\n");
	    exit(EXIT_FAILURE);
    }
    
    caps = cap_from_text(captxt);
    if (!caps) {
        log_line(LOG_ERR, "FATAL - set_cap: cap_from_text() failed\n");
        exit(EXIT_FAILURE);
    }
    
    if (cap_set_proc(caps) == -1) {
        log_line(LOG_ERR, "FATAL - set_cap: cap_set_proc() failed\n");
        exit(EXIT_FAILURE);
    }
    
    cap_free(caps);
}

void drop_root(uid_t uid, gid_t gid, char *captxt) 
{
    if (!captxt) {
        log_line(LOG_ERR, "FATAL - drop_root: captxt == NULL\n");
        exit(EXIT_FAILURE);
    }

    if (uid == 0 || gid == 0) {
        log_line(LOG_ERR, "FATAL - drop_root: attempt to drop root to root?\n");
        exit(EXIT_FAILURE);
    }

    set_cap(uid, gid, captxt);

    if (setregid(gid, gid) == -1 || setreuid(uid, uid) == -1) {
        log_line(LOG_ERR, "FATAL - drop_root: failed to drop root!\n");
        exit(EXIT_FAILURE);
    }
}

