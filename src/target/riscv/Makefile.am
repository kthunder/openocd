# SPDX-License-Identifier: GPL-2.0-or-later

%C%_libriscv_la_LIBADD =
%C%_libriscv_la_CPPFLAGS = $(AM_CPPFLAGS)

riscv_013_CPPFLAGS = $(LIBCKLINK_CFLAGS)
riscv_013_LIBADD = $(LIBCKLINK_LIBS)

noinst_LTLIBRARIES += %D%/libriscv.la
%C%_libriscv_la_SOURCES = \
       %D%/asm.h \
       %D%/batch.h \
       %D%/debug_defines.h \
       %D%/encoding.h \
       %D%/gdb_regs.h \
       %D%/opcodes.h \
       %D%/program.h \
       %D%/riscv.h \
       %D%/batch.c \
       %D%/program.c \
       %D%/riscv-011.c \
       %D%/riscv-013.c \
       %D%/riscv.c \
       %D%/riscv_semihosting.c

%C%_libriscv_la_CPPFLAGS += $(riscv_013_CPPFLAGS)
%C%_libriscv_la_LIBADD += $(riscv_013_LIBADD)