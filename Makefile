CC=/usr/bin/cc
AS=/usr/bin/as

TARGET=anemu

# Debugging
CFLAGS=-gdwarf-2 -g3 -O0
# ARM specific
CFLAGS+=-march=armv7-a -mcpu=cortex-a9 -marm
# Show all warnings
CFLAGS+=-Wall
# Includes
CFLAGS+=-I.
# Custom defines
CFLAGS+=-DHAVE_RLIMIT
# R2 libs
CFLAGS+=`pkg-config --libs --cflags r_asm`

# CFLAGS+=-l r_asm
# CFLAGS+=-I$(RADARE)/libr/include

LDFLAGS+=-L/usr/local/lib
LDFLAGS+=-lr_asm

ASFLAGS=--gdwarf-2 -g3 -march=armv7-a -mcpu=cortex-a9
# Assembly + Source listing
# ASFLAGS+=-alh

# .PHONY: all clean

C=$(wildcard *.c)
S=$(wildcard *.S)
SRCS=$(C) $(S)
O=$(SRCS:=.o)

.PHONY: all run clean

all: $(TARGET).dis

run: all
	./$(TARGET)

$(TARGET): $(O)
	$(CC) $+ $(LDFLAGS) -o $@

%.c.o: $(C)
	$(CC) $(CFLAGS) -c $< -o $@

%.S.o: $(S)
	$(AS) $(ASFLAGS) $< -o $@

%.dis: %
	objdump -dSsClwt $^ > $^.dis

clean:
	rm -f $(TARGET) $(wildcard *.o) $(TARGET).s $(TARGET).dis
