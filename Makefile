NDHC_SRCS = $(sort $(wildcard *.c) $(wildcard nk/*.c) ifchd-parse.c cfg.c)
NDHC_OBJS = $(NDHC_SRCS:.c=.o)
NDHC_DEP = $(NDHC_SRCS:.c=.d)
INCL = -I.

CFLAGS = -MMD -O2 -s -std=gnu99 -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wunused-const-variable=0 -Wcast-qual -Wsign-conversion -D_GNU_SOURCE -Wno-discarded-qualifiers -Wstrict-overflow=5
CPPFLAGS += $(INCL)

all: ragel ndhc

ndhc: $(NDHC_OBJS)
	$(CC) $(CFLAGS) $(INCL) -o $@ $^

-include $(NDHC_DEP)

clean:
	rm -f $(NDHC_OBJS) $(NDHC_DEP) ndhc

cleanragel:
	rm -f ifchd-parse.c cfg.c

ifchd-parse.c:
	ragel -G2 -o ifchd-parse.c ifchd-parse.rl

cfg.c:
	ragel -T0 -o cfg.c cfg.rl

ragel: ifchd-parse.c cfg.c

.PHONY: all clean cleanragel

