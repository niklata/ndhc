# ndhc makefile

prefix=/usr
SBINDIR=/sbin
USRSBINDIR=${prefix}/sbin
USRBINDIR=${prefix}/bin
USRSHAREDIR=${prefix}/share

# Uncomment this for extra output and to compile with debugging symbols
#DEBUG=1

#CROSS_COMPILE=arm-uclibc-
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)gcc
INSTALL = install

VER := 0.9.8


OBJS_SHARED = nstrl.o log.o options.o socket.o packet.o rootcap.o
DHCPC_OBJS = dhcpc.o clientpacket.o script.o

EXEC2 = ndhc
OBJS2 = -lcap $(DHCPC_OBJS) $(OBJS_SHARED)

BOOT_PROGRAMS = ndhc

ifdef SYSLOG
CFLAGS += -DSYSLOG
endif

CFLAGS += -W -Wall -Wstrict-prototypes -DVERSION='"$(VER)"'

ifdef DEBUG
CFLAGS += -g -DDEBUG
STRIP=true
else
CFLAGS += -Os -fomit-frame-pointer
STRIP=$(CROSS_COMPILE)strip
endif

all: $(EXEC2) 
	$(STRIP) --remove-section=.note --remove-section=.comment $(EXEC2)

$(OBJS2) $(OBJS3): *.h Makefile
$(EXEC2): Makefile

.c.o:
	$(CC) -c $(CFLAGS) $<
	
$(EXEC2): $(OBJS2)
	$(LD) $(LDFLAGS) $(OBJS2) -o $(EXEC2)

tags:
	-ctags -f tags *.[ch]
	-cscope -b

install: all

	$(INSTALL) $(BOOT_PROGRAMS) $(USRSBINDIR)
	mkdir -p $(USRSHAREDIR)/man/man8
	$(INSTALL) ndhc.8 ndhc.8 $(USRSHAREDIR)/man/man8

clean:
	-rm -f ndhc *.o core

distclean:
	-rm -f ndhc *.o tags cscope.out

