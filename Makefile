NDHC_SRCS = $(sort arp.c dhcp.c ifchange.c ifchd-parse.c leasefile.c netlink.c options.c scriptd.c state.c cfg.c duiaid.c ifchd.c ifset.c ndhc.c nl.c rfkill.c sockd.c sys.c nk/hwrng.c nk/io.c nk/privs.c nk/pspawn.c nk/random.c ifchd-parse.c cfg.c)
NDHC_OBJS = $(NDHC_SRCS:.c=.o)
NDHC_DEP = $(NDHC_SRCS:.c=.d)
INCL = -iquote .

CFLAGS = -MMD -Os -flto -s -DNDEBUG -std=gnu99 -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wunused-const-variable=0 -Wcast-qual -Wsign-conversion -D_GNU_SOURCE -Wno-discarded-qualifiers -Wstrict-overflow=5
CPPFLAGS += $(INCL)

all: ragel ndhc

ndhc: $(NDHC_OBJS)
	$(CC) $(CFLAGS) $(INCL) -o $@ $^

-include $(NDHC_DEP)

clean:
	rm -f $(NDHC_OBJS) $(NDHC_DEP) ndhc

cleanragel:
	rm -f ifchd-parse.c cfg.c

ifchd-parse.c: ifchd-parse.rl
	ragel -G2 -o ifchd-parse.c ifchd-parse.rl

cfg.c: cfg.rl
	ragel -F0 -o cfg.c cfg.rl

ragel: ifchd-parse.c cfg.c

.PHONY: all clean cleanragel

