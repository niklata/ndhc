#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "ndhc-defines.h"
#include "cfg.h"
#include "arp.h"
#include "ndhc.h"
#include "ifchd.h"
#include "sockd.h"
#include "nk/log.h"
#include "nk/privilege.h"
#include "nk/copy_cmdarg.h"
#include "nk/io.h"

struct cfgparse {
   char buf[MAX_BUF];
   size_t buflen;
   int ternary; // = 0 nothing, -1 = false, +1 = true
   int cs;
};

%%{
    machine cfg_actions;
    access ccfg.;

    action clear {
        memset(&ccfg.buf, 0, sizeof ccfg.buf);
        ccfg.buflen = 0;
        ccfg.ternary = 0;
    }
    action append {
        if (ccfg.buflen < sizeof ccfg.buf - 1)
            ccfg.buf[ccfg.buflen++] = *p;
        else
            suicide("line or option is too long");
    }
    action term {
        if (ccfg.buflen < sizeof ccfg.buf)
            ccfg.buf[ccfg.buflen] = 0;
    }
    action truval { ccfg.ternary = 1; }
    action falsval { ccfg.ternary = -1; }

    action clientid { get_clientid_string(ccfg.buf, ccfg.buflen); }
    action background {
        switch (ccfg.ternary) {
        case 1:
            client_config.background_if_no_lease = true;
            gflags_detach = 1;
            break;
        case -1:
            client_config.background_if_no_lease = false;
            gflags_detach = 0;
        default:
            break;
        }
    }
    action hostname {
        copy_cmdarg(client_config.hostname, ccfg.buf,
                    sizeof client_config.hostname, "hostname");
    }
    action interface {
        copy_cmdarg(client_config.interface, ccfg.buf,
                    sizeof client_config.interface, "interface");
    }
    action now {
        switch (ccfg.ternary) {
        case 1: client_config.abort_if_no_lease = true; break;
        case -1: client_config.abort_if_no_lease = false; default: break;
        }
    }
    action quit {
        switch (ccfg.ternary) {
        case 1: client_config.quit_after_lease = true; break;
        case -1: client_config.quit_after_lease = false; default: break;
        }
    }
    action request { set_client_addr(ccfg.buf); }
    action vendorid {
        copy_cmdarg(client_config.vendor, ccfg.buf,
                    sizeof client_config.vendor, "vendorid");
    }
    action user {
        if (nk_uidgidbyname(ccfg.buf, &ndhc_uid, &ndhc_gid))
            suicide("invalid ndhc user '%s' specified", ccfg.buf);
    }
    action ifch_user {
        if (nk_uidgidbyname(ccfg.buf, &ifch_uid, &ifch_gid))
            suicide("invalid ifch user '%s' specified", ccfg.buf);
    }
    action sockd_user {
        if (nk_uidgidbyname(ccfg.buf, &sockd_uid, &sockd_gid))
            suicide("invalid sockd user '%s' specified", ccfg.buf);
    }
    action chroot {
        copy_cmdarg(chroot_dir, ccfg.buf, sizeof chroot_dir, "chroot");
    }
    action state_dir {
        copy_cmdarg(state_dir, ccfg.buf, sizeof state_dir, "state-dir");
    }
    action seccomp_enforce {
        log_line("seccomp_enforce option is deprecated; please remove it");
        log_line("In the meanwhile, it is ignored and seccomp is disabled.");
    }
    action relentless_defense {
        switch (ccfg.ternary) {
        case 1: set_arp_relentless_def(true); break;
        case -1: set_arp_relentless_def(false); default: break;
        }
    }
    action arp_probe_wait {
        int t = atoi(ccfg.buf);
        if (t >= 0)
            arp_probe_wait = t;
    }
    action arp_probe_num {
        int t = atoi(ccfg.buf);
        if (t >= 0)
            arp_probe_num = t;
    }
    action arp_probe_min {
        int t = atoi(ccfg.buf);
        arp_probe_min = t;
        if (arp_probe_min > arp_probe_max) {
            t = arp_probe_max;
            arp_probe_max = arp_probe_min;
            arp_probe_min = t;
        }
    }
    action arp_probe_max {
        int t = atoi(ccfg.buf);
        arp_probe_max = t;
        if (arp_probe_min > arp_probe_max) {
            t = arp_probe_max;
            arp_probe_max = arp_probe_min;
            arp_probe_min = t;
        }
    }
    action gw_metric {
        char *q;
        long mt = strtol(ccfg.buf, &q, 10);
        if (q == ccfg.buf)
            suicide("gw-metric arg '%s' isn't a valid number", ccfg.buf);
        if (mt > INT_MAX)
            suicide("gw-metric arg '%s' is too large", ccfg.buf);
        if (mt < 0)
            mt = 0;
        client_config.metric = (int)mt;
    }
    action resolv_conf {
        copy_cmdarg(resolv_conf_d, ccfg.buf, sizeof resolv_conf_d,
                    "resolv-conf");
    }
    action dhcp_set_hostname {
        switch (ccfg.ternary) {
        case 1: allow_hostname = 1; break;
        case -1: allow_hostname = 0; default: break;
        }
    }
    action rfkill_idx {
        uint32_t t = (uint32_t)atoi(ccfg.buf);
        client_config.rfkillIdx = t;
        client_config.enable_rfkill = true;
    }
    action version { print_version(); exit(EXIT_SUCCESS); }
    action help { show_usage(); exit(EXIT_SUCCESS); }
}%%

%%{
    machine file_cfg;
    access ccfg.;
    include cfg_actions;

    spc = [ \t];
    delim = spc* '=' spc*;
    string = [^\n]+ >clear $append %term;
    term = '\n';
    value = delim string term;
    truval = ('true'|'1') % truval;
    falsval = ('false'|'0') % falsval;
    boolval = delim (truval|falsval) term;

    blankline = term;

    clientid = 'clientid' value @clientid;
    background = 'background' boolval @background;
    hostname = 'hostname' value @hostname;
    interface = 'interface' value @interface;
    now = 'now' boolval @now;
    quit = 'quit' boolval @quit;
    request = 'request' value @request;
    vendorid = 'vendorid' value @vendorid;
    user = 'user' value @user;
    ifch_user = 'ifch-user' value @ifch_user;
    sockd_user = 'sockd-user' value @sockd_user;
    chroot = 'chroot' value @chroot;
    state_dir = 'state-dir' value @state_dir;
    seccomp_enforce = 'seccomp-enforce' boolval @seccomp_enforce;
    relentless_defense = 'relentless-defense' boolval @relentless_defense;
    arp_probe_wait = 'arp-probe-wait' value @arp_probe_wait;
    arp_probe_num = 'arp-probe-num' value @arp_probe_num;
    arp_probe_min = 'arp-probe-min' value @arp_probe_min;
    arp_probe_max = 'arp-probe-max' value @arp_probe_max;
    gw_metric = 'gw-metric' value @gw_metric;
    resolv_conf = 'resolv-conf' value @resolv_conf;
    dhcp_set_hostname = 'dhcp-set-hostname' boolval @dhcp_set_hostname;
    rfkill_idx = 'rfkill-idx' value @rfkill_idx;

    main := blankline |
        clientid | background | hostname | interface | now | quit |
        request | vendorid | user | ifch_user | sockd_user | chroot |
        state_dir | seccomp_enforce | relentless_defense | arp_probe_wait |
        arp_probe_num | arp_probe_min | arp_probe_max | gw_metric |
        resolv_conf | dhcp_set_hostname | rfkill_idx
    ;
}%%

%% write data;

static void parse_cfgfile(const char fname[static 1])
{
    bool reached_eof = false;
    struct cfgparse ccfg;
    memset(&ccfg, 0, sizeof ccfg);
    char l[MAX_BUF];
    size_t lc = 0;
    memset(l, 0, sizeof l);
    int fd = open(fname, O_RDONLY|O_CLOEXEC, 0);
    if (fd < 0)
        suicide("Unable to open config file '%s'.", fname);

    size_t linenum = 0;
    for (;;) {
        if (lc + 1 >= sizeof l) suicide("sizeof l - 1 - lc would underflow");
        ssize_t rc = safe_read(fd, l + lc, sizeof l - 1 - lc);
        if (rc < 0)
            suicide("Error reading config file '%s'.", fname);
        if (rc == 0) {
            l[lc] = '\n'; rc = 1; reached_eof = true; // Emulate a LF to terminate the line.
        }
        lc += (size_t)rc;

        size_t lstart = 0, lend = 0, consumed = 0;
        for (; lend < lc; ++lend) {
            if (l[lend] == '\n') {
                ++linenum; consumed = lend;

                size_t llen = lend - lstart;
                const char *p = l + lstart;
                const char *pe = l + lstart + llen + 1;
                %% write init;
                %% write exec;

                if (ccfg.cs == file_cfg_error)
                    suicide("error parsing config file line %zu: malformed", linenum);
                if (ccfg.cs < file_cfg_first_final)
                    suicide("error parsing config file line %zu: incomplete", linenum);
                lstart = lend + 1;
            }
        }
        if (reached_eof)
            break;
        if (!consumed && lend >= sizeof l - 1)
            suicide("Line %u in config file '%s' is too long: %u > %u.",
                    linenum, fname, lend, sizeof l - 1);

        if (consumed + 1 > lc) suicide("lc[%zu] - consumed[%zu] would underflow", lc, lend);
        if (consumed) {
            memmove(l, l + consumed + 1, lc - consumed - 1);
            lc -= consumed + 1;
        }
    }
    close(fd);
}

%%{
    machine cmd_cfg;
    access ccfg.;
    include cfg_actions;

    action cfgfile { parse_cfgfile(ccfg.buf); }
    action tbv { ccfg.ternary = 1; }

    string = [^\0]+ >clear $append %term;
    argval = 0 string 0;
    tbv = 0 % tbv;

    cfgfile = ('-c'|'--config') argval @cfgfile;
    clientid = ('-I'|'--clientid') argval @clientid;
    background = ('-b'|'--background') tbv @background;
    hostname = ('-h'|'--hostname') argval @hostname;
    interface = ('-i'|'--interface') argval @interface;
    now = ('-n'|'--now') tbv @now;
    quit = ('-q'|'--quit') tbv @quit;
    request = ('-r'|'--request') argval @request;
    vendorid = ('-V'|'--vendorid') argval @vendorid;
    user = ('-u'|'--user') argval @user;
    ifch_user = ('-U'|'--ifch-user') argval @ifch_user;
    sockd_user = ('-D'|'--sockd-user') argval @sockd_user;
    chroot = ('-C'|'--chroot') argval @chroot;
    state_dir = ('-s'|'--state-dir') argval @state_dir;
    seccomp_enforce = ('-S'|'--seccomp-enforce') tbv @seccomp_enforce;
    relentless_defense = ('-d'|'--relentless-defense') tbv @relentless_defense;
    arp_probe_wait = ('-w'|'--arp-probe-wait') argval @arp_probe_wait;
    arp_probe_num = ('-W'|'--arp-probe-num') argval @arp_probe_num;
    arp_probe_min = ('-m'|'--arp-probe-min') argval @arp_probe_min;
    arp_probe_max = ('-M'|'--arp-probe-max') argval @arp_probe_max;
    gw_metric = ('-t'|'--gw-metric') argval @gw_metric;
    resolv_conf = ('-R'|'--resolv-conf') argval @resolv_conf;
    dhcp_set_hostname = ('-H'|'--dhcp-set-hostname') tbv @dhcp_set_hostname;
    rfkill_idx = ('-K'|'--rfkill-idx') argval @rfkill_idx;
    version = ('-v'|'--version') 0 @version;
    help = ('-?'|'--help') 0 @help;

    main := (
        cfgfile | clientid | background | hostname | interface |
        now | quit | request | vendorid | user | ifch_user | sockd_user |
        chroot | state_dir | seccomp_enforce | relentless_defense |
        arp_probe_wait | arp_probe_num | arp_probe_min | arp_probe_max |
        gw_metric | resolv_conf | dhcp_set_hostname | rfkill_idx |
        version | help
    )*;
}%%

%% write data;

void parse_cmdline(int argc, char *argv[])
{
    char argb[8192];
    size_t argbl = 0;
    for (size_t i = 1; i < (size_t)argc; ++i) {
        ssize_t snl;
        if (i > 1)
            snl = snprintf(argb + argbl, sizeof argb - argbl, "%c%s",
                           0, argv[i]);
        else
            snl = snprintf(argb + argbl, sizeof argb - argbl, "%s", argv[i]);
        if (snl < 0 || (size_t)snl >= sizeof argb)
            suicide("error parsing command line option: option too long");
        argbl += (size_t)snl;
    }
    if (argbl == 0)
        return;
    struct cfgparse ccfg;
    memset(&ccfg, 0, sizeof ccfg);
    const char *p = argb;
    const char *pe = argb + argbl + 1;
    const char *eof = pe;

    %% write init;
    %% write exec;

    if (ccfg.cs == cmd_cfg_error)
        suicide("error parsing command line option: malformed");
    if (ccfg.cs >= cmd_cfg_first_final)
        return;
    suicide("error parsing command line option: incomplete");
}

