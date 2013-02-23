CC=/usr/bin/cc
AS=/usr/bin/as

TARGET=anemu
DARM=../darm-v7

# Debugging
CFLAGS=-gdwarf-2 -g3 -O0
# ARM specific
CFLAGS+=-march=armv7-a -mcpu=cortex-a9 -marm
# Inline functions
CFLAGS+=-finline-functions
# Show all warnings
CFLAGS+=-Wall
# Includes
CFLAGS+=-I$(DARM)
# Custom defines
CFLAGS+=-DHAVE_SETRLIMIT
# R2 libs
CFLAGS+=`pkg-config --libs --cflags r_asm`

# CFLAGS+=-l r_asm
# CFLAGS+=-I$(RADARE)/libr/include

# LDFLAGS+=-L/usr/local/lib
LDFLAGS+=-lr_asm
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
