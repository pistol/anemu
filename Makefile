# CC=/usr/bin/cc
# AS=/usr/bin/as

TARGET=anemu
DARM=../darm-v7


# Debugging
CFLAGS=-gdwarf-2 -g3 -O0
# ARM specific
CFLAGS+=-march=armv7-a -mcpu=cortex-a9 -marm -mfloat-abi=softfp
# Inline functions
CFLAGS+=-finline-functions
# Show all warnings
CFLAGS+=-Wall
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
# R2 libs
# CFLAGS+=`pkg-config --libs --cflags r_asm`

# CFLAGS+=-lr_asm
# CFLAGS+=-I$(RADARE)/libr/include

# LDFLAGS+=-L/usr/local/lib
# LDFLAGS+=-lr_asm
LDFLAGS+=-L$(DARM)
# LDFLAGS+=$(DARM)/libdarm.a
LDFLAGS+=-ldarm

# Debug Symbols
# ASFLAGS=-g3
# ARM specific
ASFLAGS+=-march=armv7-a -mcpu=cortex-a9
# Assembly + Source listing
# ASFLAGS+=-alh

C=$(wildcard *.c)
S=$(wildcard *.S)
SRCS=$(C) $(S)
O=$(C:.c=.o) $(S:.S=.o)

.PHONY: all run clean

all: $(TARGET).dis

run: all
	./$(TARGET)

$(TARGET): $(O)
	@echo "Objects: $+"
	$(MAKE) -C $(DARM)
	$(CC) $+ $(LDFLAGS) -o $@

# %.o: %.c
# 	@echo "C files: $(C)"
# 	$(CC) $(CFLAGS) -c $< -o $@

# %.o: %.s
# 	@echo "S files: $(S)"
# 	$(AS) $(ASFLAGS) $< -o $@

%.dis: %
	objdump -d $^ > $^.dis
#	objdump -dSsClwt $^ > $^.dis

clean:
	rm -f $(TARGET) $(wildcard *.o) $(TARGET).s $(TARGET).dis
