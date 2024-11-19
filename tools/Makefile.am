bin_SCRIPTS = enigma2.sh
lib_LTLIBRARIES = libopen.la libexclude_machine.la

AM_CFLAGS = -DLIBC_SO=\"$(base_libdir)/libc.so.6\"

libopen_la_SOURCES = libopen.c
libopen_la_LIBADD = @LIBDL_LIBS@

libexclude_machine_la_SOURCES = exclude_machine.c
libexclude_machine_la_LIBADD = @LIBDL_LIBS@

EXTRA_DIST = enigma2.sh.in tools/exclude_machine.c


