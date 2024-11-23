# bin_SCRIPTS e le librerie da compilare
bin_SCRIPTS = enigma2.sh
lib_LTLIBRARIES = libopen.la OPD.la

# Aggiungi flag di compilazione (se necessario)
AM_CFLAGS = -DLIBC_SO=\"$(base_libdir)/libc.so.6\"

# Sorgenti della libreria libopen
libopen_la_SOURCES = libopen.c
libopen_la_LIBADD = @LIBDL_LIBS@

# Sorgenti della libreria OPD
OPD_la_SOURCES = OPD.c
OPD_la_LIBADD = @LIBDL_LIBS@

# Aggiungi altri file necessari
EXTRA_DIST = enigma2.sh.in tools/OPD.c



