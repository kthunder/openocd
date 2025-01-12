# SPDX-License-Identifier: GPL-2.0-or-later

noinst_LTLIBRARIES += %D%/libjtag.la

%C%_libjtag_la_LIBADD =
%C%_libjtag_la_CPPFLAGS = $(AM_CPPFLAGS)

if HLADAPTER
include %D%/hla/Makefile.am
%C%_libjtag_la_LIBADD += $(top_builddir)/%D%/hla/libocdhla.la
endif

include %D%/drivers/Makefile.am
%C%_libjtag_la_LIBADD += $(top_builddir)/%D%/drivers/libocdjtagdrivers.la

core_CPPFLAGS = $(LIBCKLINK_CFLAGS)
core_LIBADD = $(LIBCKLINK_LIBS)

%C%_libjtag_la_SOURCES = \
	%D%/adapter.c \
	%D%/adapter.h \
	%D%/commands.c \
	%D%/core.c \
	%D%/interface.c \
	%D%/interfaces.c \
	%D%/tcl.c \
	%D%/swim.c \
	%D%/commands.h \
	%D%/interface.h \
	%D%/interfaces.h \
	%D%/minidriver.h \
	%D%/jtag.h \
	%D%/swd.h \
	%D%/swim.h \
	%D%/tcl.h

STARTUP_TCL_SRCS += %D%/startup.tcl

%C%_libjtag_la_CPPFLAGS += $(core_CPPFLAGS)
%C%_libjtag_la_LIBADD += $(core_LIBADD)
