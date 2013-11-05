# CC=/usr/bin/cc
# AS=/usr/bin/as

TARGET=anemu
DARM=../darm-v7


# Debugging
CFLAGS+=-g -fno-omit-frame-pointer
CFLAGS+=-O2
# ARM specific
CFLAGS+=-mtune=cortex-a9 -marm
# Inline functions
# CFLAGS+=-finline-functions
# Show all warnings
CFLAGS+=-Wall
CFLAGS+=-fPIC
# Includes
CFLAGS+=-I$(DARM)

# Android
ifdef ANDROID
CC=arm-eabi-gcc
AS=arm-eabi-as
LD=arm-eabi-ld
AR=arm-eabi-ar
RANLIB=arm-eabi-ranlib

BIONIC=${ANDROID}/android-4.2.2_r1/bionic/
# ANDROID_PRODUCT_OUT=$(ANDROID)/out/target/product/maguro

CFLAGS+=-I$(BIONIC)/libc/include
CFLAGS+=-I$(BIONIC)/libc/arch-arm/include
CFLAGS+=-I$(BIONIC)/libc/kernel/common
CFLAGS+=-I$(BIONIC)/libc/kernel/arch-arm

CFLAGS+=-nostdlib
CFLAGS+=-DANDROID

LDFLAGS+=-L$(ANDROID_PRODUCT_OUT)/system/lib
# LDFLAGS+=-Wl,-rpath-link=$(ANDROID_PRODUCT_OUT)/system/lib
endif

# Custom defines
CFLAGS+=-DHAVE_SETRLIMIT
LDFLAGS+=-L$(DARM)
# LDFLAGS+=$(DARM)/libdarm.a
LDFLAGS+=-ldarm
# clock_gettime
LDFLAGS+=-lrt
# shared libs: pthread
LDFLAGS+=-lpthread
LDFLAGS+=-L.

C=$(wildcard *.c)
EXCLUDES=rasm.c
C:=$(filter-out $(EXCLUDES),$(C))
SRCS=$(C)
O=$(C:.c=.o)

LIBS=libanemu.a libanemu.so
TEST_BIN=tests/matrix tests/zlib

.PHONY: all run clean

default: lib $(TEST_BIN)

lib: $(LIBS)

%.o: %.c
  # $(MAKE) -C $(DARM)
	$(CC) $(CFLAGS) -o $@ -c $^ $(LDFLAGS)

%.a: $(O)
	$(AR) cr $@ $^

%.so: $(O)
	$(CC) -shared $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.dis: %
	objdump -d $^ > $^.dis
#	objdump -dSsClwt $^ > $^.dis

%: %.c
	$(CC) $(CFLAGS) -o $@ $^ -I. -Itests $(LDFLAGS) -L. -lanemu -lz

test: lib $(TEST_BIN)
	./tests/matrix 0 128

clean:
	rm -f $(LIBS) $(wildcard *.o) $(TEST_BIN)
