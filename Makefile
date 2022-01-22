# This is a pretty basic makefile.  I generally use CMake, so this is mostly
# for distros that want to avoid build dependencies.  Produced exes will be
# at './build/ndhc'.

NCM_SRCS = $(sort $(wildcard src/lib/*.c))
NDHC_SRCS = $(sort $(wildcard src/*.c))
NCM_OBJS = $(NCM_SRCS:.c=.o)
NDHC_OBJS = $(NDHC_SRCS:.c=.o)
NDHC_INC = -I./src
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/objs

CC = gcc
AR = ar
CFLAGS = -O2 -s -std=gnu99 -pedantic -Wall -Wextra -Wimplicit-fallthrough=0 -Wformat=2 -Wformat-nonliteral -Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes -Wunused-const-variable=0 -Wcast-qual -Wsign-conversion -D_GNU_SOURCE -DNK_USE_CAPABILITY -Wno-discarded-qualifiers
# Not required for glibc >= 2.17.
# The CMake build script will perform detection, but this Makefile is simple.
#LINK_LIBS = -lrt

all: makedir ifchd-parse.o cfg.o ndhc

clean:
	rm -Rf $(BUILD_DIR)

makedir:
	mkdir -p $(BUILD_DIR) $(OBJ_DIR)/src $(OBJ_DIR)/src/lib

ifchd-parse.o:
	ragel -G2 -o $(BUILD_DIR)/ifchd-parse.c src/ifchd-parse.rl
	$(CC) $(CFLAGS) $(NDHC_INC) -c -o $(OBJ_DIR)/src/$@ $(BUILD_DIR)/ifchd-parse.c

cfg.o:
	ragel -G2 -o $(BUILD_DIR)/cfg.c src/cfg.rl
	$(CC) $(CFLAGS) $(NDHC_INC) -c -o $(OBJ_DIR)/src/$@ $(BUILD_DIR)/cfg.c

%.o: %.c
	$(CC) $(CFLAGS) $(NDHC_INC) -c -o $(OBJ_DIR)/$@ $<

ndhc: $(NCM_OBJS) $(NDHC_OBJS) ifchd-parse.o cfg.o
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(subst src/,$(OBJ_DIR)/src/,$(NDHC_OBJS)) $(subst src/lib/,$(OBJ_DIR)/src/lib/,$(NCM_OBJS)) $(BUILD_DIR)/objs/src/ifchd-parse.o $(BUILD_DIR)/objs/src/cfg.o $(LINK_LIBS)

.PHONY: all clean

