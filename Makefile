# This is a pretty basic makefile.  I generally use CMake, so this is mostly
# for distros that want to avoid build dependencies.  Produced exes will be
# at './build/ndhc'.

NCM_SRCS = $(sort $(wildcard ncmlib/*.c))
NDHC_SRCS = $(sort $(wildcard ndhc/*.c))
NCM_OBJS = $(NCM_SRCS:.c=.o)
NDHC_OBJS = $(NDHC_SRCS:.c=.o)
NCM_INC = -I./ncmlib
NDHC_INC = -I./ndhc
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/objs

CC = gcc
AR = ar
RANLIB = ranlib
CFLAGS = -O2 -s -std=gnu99 -pedantic -Wall -D_GNU_SOURCE -DHAVE_CLEARENV -DLINUX

all: makedir ifchd-parse.o ncmlib.a ndhc

clean:
	rm -Rf $(BUILD_DIR)

makedir:
	mkdir -p $(BUILD_DIR) $(OBJ_DIR)/ndhc $(OBJ_DIR)/ncmlib

ifchd-parse.o:
	ragel -G2 -o $(BUILD_DIR)/ifchd-parse.c ndhc/ifchd-parse.rl
	$(CC) $(CFLAGS) $(NCM_INC) $(NDHC_INC) -c -o $(OBJ_DIR)/ndhc/$@ $(BUILD_DIR)/ifchd-parse.c

%.o: %.c
	$(CC) $(CFLAGS) $(NCM_INC) -c -o $(OBJ_DIR)/$@ $<

ncmlib.a: $(NCM_OBJS)
	$(AR) rc $(BUILD_DIR)/$@ $(subst ncmlib/,$(OBJ_DIR)/ncmlib/,$(NCM_OBJS))
	$(RANLIB) $(BUILD_DIR)/$@

ndhc: $(NDHC_OBJS) ifchd-parse.o
	$(CC) $(CFLAGS) $(NCM_INC) -o $(BUILD_DIR)/$@ $(subst ndhc/,$(OBJ_DIR)/ndhc/,$(NDHC_OBJS)) $(BUILD_DIR)/ncmlib.a $(BUILD_DIR)/objs/ndhc/ifchd-parse.o -lcap -lrt

.PHONY: all clean

