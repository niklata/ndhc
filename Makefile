NDHC_SRCS = $(sort $(wildcard *.c) $(wildcard nk/*.c) ifchd-parse.c cfg.c)
NDHC_OBJS = $(NDHC_SRCS:.c=.o)
NDHC_DEP = $(NDHC_SRCS:.c=.d)
INCL = -I.

CC ?= gcc
CFLAGS = -MMD -O2 -s -std=gnu99 -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wunused-const-variable=0 -Wcast-qual -Wsign-conversion -D_GNU_SOURCE -DNK_USE_CAPABILITY -Wno-discarded-qualifiers

-include $(NDHC_DEP)

all: ragel ndhc

clean:
	rm -f $(NDHC_OBJS) $(NDHC_DEP) ndhc

cleanragel:
	rm -f ifchd-parse.c cfg.c

ifchd-parse.c:
	ragel -G2 -o ifchd-parse.c ifchd-parse.rl

cfg.c:
	ragel -G2 -o cfg.c cfg.rl

ragel: ifchd-parse.c cfg.c

%.o: %.c
	$(CC) $(CFLAGS) $(INCL) -c -o $@ $^

ndhc: $(NDHC_OBJS)
	$(CC) $(CFLAGS) $(INCL) -o $@ $^

.PHONY: all clean cleanragel

