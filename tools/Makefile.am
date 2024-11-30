bin_SCRIPTS = enigma2.sh
lib_LTLIBRARIES = libopen.la libOPD.la
AM_CFLAGS = -DLIBC_SO=\"$(base_libdir)/libc.so.6\"

libopen_la_SOURCES = libopen.c
libopen_la_LIBADD = @LIBDL_LIBS@
libOPD_la_SOURCES = libOPD.c
libOPD_la_LIBADD = @LIBDL_LIBS@
EXTRA_DIST = enigma2.sh.in tools/libOPD.c

