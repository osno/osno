# bin_SCRIPTS e le librerie da compilare
bin_SCRIPTS = enigma2.sh
lib_LTLIBRARIES = libopen.la libOPD.la  # Cambiato OPD.la in libOPD.la

# Aggiungi flag di compilazione (se necessario)
AM_CFLAGS = -DLIBC_SO=\"$(base_libdir)/libc.so.6\"

# Sorgenti della libreria libopen
libopen_la_SOURCES = libopen.c
libopen_la_LIBADD = @LIBDL_LIBS@

# Sorgenti della libreria libOPD
libOPD_la_SOURCES = OPD.c  # Cambiato OPD_la_SOURCES in libOPD_la_SOURCES
libOPD_la_LIBADD = @LIBDL_LIBS@  # Cambiato OPD_la_LIBADD in libOPD_la_LIBADD

# Aggiungi altri file necessari
EXTRA_DIST = enigma2.sh.in tools/OPD.c

