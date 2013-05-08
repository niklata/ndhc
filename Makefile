# This is a pretty basic makefile.  I generally use CMake, so this is mostly
# for distros that want to avoid build dependencies.  Produced exes will be
# at './build/ndhc' and './build/ifchd'.

NCM_SRCS = $(sort $(wildcard ncmlib/*.c))
IFCHD_SRCS = $(sort $(wildcard ifchd/*.c))
NDHC_SRCS = $(sort $(wildcard ndhc/*.c))
NCM_OBJS = $(NCM_SRCS:.c=.o)
IFCHD_OBJS = $(IFCHD_SRCS:.c=.o)
NDHC_OBJS = $(NDHC_SRCS:.c=.o)
NCM_INC = -I./ncmlib
IFCH_INC = -I./ifchd
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/objs

CC = gcc
AR = ar
RANLIB = ranlib
CFLAGS = -O2 -s -std=gnu99 -pedantic -Wall -D_GNU_SOURCE -DHAVE_CLEARENV -DLINUX

all: makedir ifchd-parse.o ncmlib.a ifchd ndhc

clean:
	rm -Rf $(BUILD_DIR)

makedir:
	mkdir -p $(BUILD_DIR) $(OBJ_DIR)/ndhc $(OBJ_DIR)/ifchd $(OBJ_DIR)/ncmlib

ifchd-parse.o:
	ragel -G2 -o $(BUILD_DIR)/ifchd-parse.c ifchd/ifchd-parse.rl
	$(CC) $(CFLAGS) $(IFCH_INC) $(NCM_INC) -c -o $(OBJ_DIR)/ifchd/$@ $(BUILD_DIR)/ifchd-parse.c

%.o: %.c
	$(CC) $(CFLAGS) $(IFCH_INC) $(NCM_INC) -c -o $(OBJ_DIR)/$@ $<

ncmlib.a: $(NCM_OBJS)
	$(AR) rc $(BUILD_DIR)/$@ $(subst ncmlib/,$(OBJ_DIR)/ncmlib/,$(NCM_OBJS))
	$(RANLIB) $(BUILD_DIR)/$@

ifchd: $(IFCHD_OBJS) ifchd-parse.o
	$(CC) $(CFLAGS) $(NCM_INC) -o $(BUILD_DIR)/$@ $(subst ifchd/,$(OBJ_DIR)/ifchd/,$(IFCHD_OBJS)) $(BUILD_DIR)/objs/ifchd/ifchd-parse.o $(BUILD_DIR)/ncmlib.a -lcap

ndhc: $(NDHC_OBJS)
	$(CC) $(CFLAGS) $(IFCH_INC) $(NCM_INC) -o $(BUILD_DIR)/$@ $(subst ndhc/,$(OBJ_DIR)/ndhc/,$(NDHC_OBJS)) $(BUILD_DIR)/ncmlib.a -lcap -lrt

.PHONY: all clean

