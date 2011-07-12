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
BUILD_DIR = build
OBJ_DIR = objs

CC = gcc
AR = ar
RANLIB = ranlib
CFLAGS = -O2 -s -std=gnu99 -pedantic -Wall -D_GNU_SOURCE -DHAVE_CLEARENV -DLINUX

all: makedir ncmlib.a ifchd ndhc

clean:
	rm -Rf $(OBJ_DIR) $(BUILD_DIR)

makedir:
	mkdir -p $(OBJ_DIR)/ndhc $(OBJ_DIR)/ifchd $(OBJ_DIR)/ncmlib $(BUILD_DIR)

%.o: %.c
	$(CC) $(CFLAGS) $(NCM_INC) -c -o $(OBJ_DIR)/$@ $<

ncmlib.a: $(NCM_OBJS)
	$(AR) rc $(BUILD_DIR)/$@ $(subst ncmlib/,$(OBJ_DIR)/ncmlib/,$(NCM_OBJS))
	$(RANLIB) $(BUILD_DIR)/$@

ifchd: $(IFCHD_OBJS)
	$(CC) $(CFLAGS) $(NCM_INC) -o $(BUILD_DIR)/$@ $(subst ifchd/,$(OBJ_DIR)/ifchd/,$(IFCHD_OBJS)) $(BUILD_DIR)/ncmlib.a -lcap 

ndhc: $(NDHC_OBJS)
	$(CC) $(CFLAGS) $(NCM_INC) -o $(BUILD_DIR)/$@ $(subst ndhc/,$(OBJ_DIR)/ndhc/,$(NDHC_OBJS)) $(BUILD_DIR)/ncmlib.a -lcap

.PHONY: all clean

