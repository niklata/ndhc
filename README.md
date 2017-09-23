# ndhc
Copyright (C) 2004-2017 Nicholas J. Kain.

See LICENSE for licensing information.  In short: Two-clause / New BSD.

## Introduction

ndhc is a multi-process, privilege-separated DHCP client.  Each subprocess
runs with the minimal necessary privileges in order to perform its task.
Currently, ndhc consists of three subprocesses: the ndhc-master,
ndhc-ifch, and ndhc-sockd.

ndhc-master communicates with DHCP servers and handles the vagaries of
the DHCP client protocol.  It runs as a non-root user inside a chroot.
ndhc runs as a normal user with no special privileges and is restricted
to a chroot that contains nothing more than a domain socket filesystem
object (if using syslog), a urandom device node, and a null device node.

ndhc-ifch handles interface change requests.  It listens on a unix
socket for such requests.  ndhc-ifch runs as a non-root user inside
a chroot, and retains only the power to configure network interfaces.
ndhc-ifch automatically forks from ndhc-master to perform its job.

ndhc-sockd plays a similar role to ndhc-ifch, but it instead has the
ability to bind to a low port, the ability to open a raw socket, and the
ability to communicate on broadcast channels.  ndhc communicates with
ndhc-sockd over a unix socket, and the file descriptors that ndhc-sockd
creates are passed back to ndhc over the unix socket.

ndhc fully implements RFC5227's address conflict detection and defense.
Great care is taken to ensure that address conflicts will be detected,
and ndhc also has extensive support for address defense.  Care is taken
to prevent unintentional ARP flooding under any circumstance.

ndhc also monitors hardware link status via netlink events and reacts
appropriately when interface carrier status changes or an interface
is explicitly deconfigured.  This functionality can be useful on wired
networks when transient carrier downtimes occur (or cables are changed),
but it is particularly useful on wireless networks.

RFC3927's IPv4 Link Local Addressing is not supported.  I have found v4
LLAs to be more of an annoyance than a help.  v6 LLAs work much better
in practice.

## Features

*Privilege-separated*.  ndhc does not run as root after initial startup,
and capabilities are divided between the subprocesses.  All processes
run in a chroot.

*Robust*.  ndhc performs no runtime heap allocations -- `malloc()` (more
specifically, `brk()`, `mmap()`, etc) is never called after initialization
(libc behavior during initialization time will vary), and ndhc never
performs recursive calls and only stack-allocates fixed-length types,
so stack depth is bounded, too.

*Active defense of IP address and IP collision avoidance*.  ndhc fully
implements RFC5227.  It is capable of both a normal level of tenacity in
defense, where it will eventually back off and request a new lease if a
peer won't relent in the case of a conflict, and of relentlessly defending
a lease forever.  In either mode, it rate-limits defense messages, so it
can't be tricked into flooding by a hostile peer or DHCP server, either.

*Small*.  Both ndhc avoids unnecessary outside dependencies and is written
in plain C.

*Fast*.  ndhc filters input using the BPF/LPF mechanism so that
uninteresting packets are dropped by the operating system before ndhc
even sees the data.  ndhc also only listens to DHCP traffic when it's
necessary.

*Flexible*.  ndhc can request particular IPs, send user-specified client
IDs, write a file that contains the current lease IP, write PID files,
etc.

*Self-contained*.  ndhc does not exec other processes, or rely on the shell.
Further, ndhc relies on no external libraries aside from the system libc.

*Aware of the hardware link status*.  If you disconnect an interface on
which ndhc is providing DHCP service, it will be aware.  When the link
status returns, ndhc will fingerprint the reconnected network and make
sure that it corresponds to the one on which it has a lease.  If the new
network is different, it will forget about the old lease and request a
new one.

## Requirements

* Linux kernel
* GNU Make or CMake
* [Ragel 6](https://www.colm.net/open-source/ragel)
* [ncmlib](https://github.com/niklata/ncmlib)

## Installation

Make sure that ncmlib is present in the ndhc source directory:
```
$ ls
CMakeLists.txt  LICENSE  Makefile  ncmlib  README  src
```
Compile and install ndhc.
* Create a build directory: `mkdir build && cd build`
* Create the makefiles: `cmake ..`
* Build ndhc: `make`
* Install the `ndhc/ndhc` executable in a normal place.  I would
  suggest `/usr/sbin` or `/usr/local/sbin`.

Time to create the jail in which ndhc will run. Become root and create new group `ndhc`.
```
$ su -
# umask 077
# groupadd ndhc
```
Create new users `dhcpifch` and `dhcp`.  The primary group of these users should be `ndhc`.
```
# useradd -d /var/lib/ndhc -s /sbin/nologin -g ndhc dhcpsockd
# useradd -d /var/lib/ndhc -s /sbin/nologin -g ndhc dhcpifch
# useradd -d /var/lib/ndhc -s /sbin/nologin -g ndhc dhcp
```
Create the state directory where DUIDs and IAIDs will be stored.
```
# mkdir /etc/ndhc
# chown root.root /etc/ndhc
# chmod 0755 /etc/ndhc
```
Create the jail directory and set its ownership properly.
```
# mkdir /var/lib/ndhc
# chown root.root /var/lib/ndhc
# chmod a+rx /var/lib/ndhc
# cd /var/lib/ndhc
# mkdir var
# mkdir var/state
# mkdir var/run
# chown -R dhcp.ndhc var
# chmod -R a+rx var
# chmod g+w var/run
```
Create a urandom device for ndhc to use within the jail.
```
# mkdir dev
# mknod dev/urandom c 1 9
# mknod dev/null c 1 3
# chown -R root.root dev
# chmod a+rx dev
# chmod a+r dev/urandom
# chmod a+rw dev/null
```
(_optional_) If you wish for logging to properly work, you will need
to properly configure your logging daemon so that it opens a domain
socket in the proper location within the jail. Since this varies
per-daemon, I cannot provide a general configuration.

At this point the jail is usable; ndhc is ready to be used.  It should
be invoked as the root user so that it can spawn its processes with the
proper permissions.  An example of invoking ndhc: `ndhc -i wan0 -u dhcp -U dhcpifch -D dhcpsockd -C /var/lib/ndhc`

If you encounter problems, I suggest running ndhc in the foreground
and examining the printed output.

I suggest running ndhc under some sort of process
supervision such as [runit](http://smarden.org/runit) or
[s6](http://www.skarnet.org/software/s6).  This will allow for reliable
functioning in the case of unforseen or unrecoverable errors.

## Behavior Notes

ndhc does not enable updates of the local `hostname` and `resolv.conf` by
default.  If you wish to enable these functions, use the `--resolve`
(`-R`) and `--hostname` (`-H`) flags.  See `ndhc --help`.

## State Storage Notes

ndhc requires a read/writable directory to store the DUID/IAID states.
By default this directory is `/etc/ndhc`.  It exists outside the
chroot.  The DUID will be stored in a single file, DUID.  The IAIDs
exist per-interface and are stored in files with names similar to
`IAID-xx:xx:xx:xx:xx:xx`, where the `xx` values are replaced by the
Ethernet hardware address of the interface.

If it is impossible to read or store the DUIDs or IAIDs, ndhc will
fail at start time before it performs any network activity or forks
any subprocesses.

If the host system lacks volatile storage, then a clientid should manually
be specified using the `-I` or `--clientid` command arguments.

## Downloads

* [GitLab](https://github.com/niklata/ndhc)
* [BitBucket](https://gitlab.com/niklata/ndhc)
* [GitHub](https://bitbucket.com/niklata/ndhc)

## Porting Notes

DHCP clients aren't naturally very portable.  It's necessary to
perform a lot of tasks that are platform-specific.  ndhc is rather
platform-dependent, and it uses many Linux-specific features.
The following list is not intended to be exhaustive:

* ndhc takes advantage of Linux capabilities so that it does not need
full root privileges.  Capabilities were a proposed POSIX feature that
was not made part of the official standard, so any implemention that
may exist will be system-dependent.

* ndhc configures network interfaces and routes.  Interface and route
configuration is entirely non-portable.

* ndhc uses netlink sockets for fetching data, setting data, and hardware
link state change notification events.

* ndhc uses the Berkeley Packet Filter / Linux Packet Filter interfaces
to drop unwanted packets in kernelspace.  This functionality is available
on most modern unix systems, but it is not standard.

* ndhc uses `epoll()` and `signalfd()`.  These are Linux-specific.

* Numerous socket options are used, and the `AF_PACKET` socket family
is used for raw sockets and ARP.  These are largely Linux-specific, too.

* ndhc can optionally use seccomp-filter to allow only a set of
whitelisted syscalls.  This functionality is Linux-specific.

