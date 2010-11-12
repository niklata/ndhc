CC = gcc -Wall -Wpointer-arith -Wstrict-prototypes
AR = ar
objects = log.o nstrl.o chroot.o pidfile.o signals.o strlist.o linux.o ifchd.o

ifchd : $(objects)
	$(CC) -lcap -o ifchd $(objects)

ifchd.o : log.h nstrl.h chroot.h pidfile.h signals.h strlist.h linux.h
	$(CC) $(CFLAGS) $(archflags) $(LDFLAGS) -c -o $@ ifchd.c

linux.o: log.h strlist.h
chroot.o: log.h
pidfile.o: log.h
signals.o: log.h
strlist.o:
nstrl.o:
log.o :

install: ifchd
	-install -s -m 755 ifchd /usr/sbin/ifchd
tags:
	-ctags -f tags *.[ch]
	-cscope -b
clean:
	-rm -f *.o ifchd
distclean:
	-rm -f *.o ifchd tags cscope.out

