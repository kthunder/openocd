# SPDX-License-Identifier: GPL-2.0-or-later
# export PATH=$PATH:/home/konglei/openOCD/Xuantie-900-gcc-elf-newlib-x86_64-V3.0.1/bin

BIN2C = ../../../../src/helper/bin2char.sh

CROSS_COMPILE ?= ~/openOCD/Xuantie-900-gcc-elf-newlib-x86_64-V3.0.1/bin/riscv64-unknown-elf-

CC=$(CROSS_COMPILE)gcc
OBJCOPY=$(CROSS_COMPILE)objcopy
OBJDUMP=$(CROSS_COMPILE)objdump

CFLAGS = -mcpu=e902m -static -nostartfiles -nostdlib -O3 -fPIC
LDLAGS = -nostdlib -Wl,--nmagic

all: cw2245.inc

.PHONY: clean

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.inc: %.bin
	$(BIN2C) < $< > $@

%.elf:
	cp /mnt/c/Users/Administrator/Desktop/cw_fls_algo/build/cw_fls_algo.elf $@
# %.elf: %.c
# 	$(CC) $(CFLAGS) $(LDLAGS) -T linker.ld $< -o $@ -Wl,-Map,cw2245.map

%.lst: %.elf
	$(OBJDUMP) -ds $< > $@

%.bin: %.elf
	$(OBJCOPY) -Obinary $< $@


clean:
	-rm -f *.elf *.lst *.bin *.inc *.o

