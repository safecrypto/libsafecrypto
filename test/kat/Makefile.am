if HAVE_CHECK

AM_CPPFLAGS             += -I$(top_srcdir)/include -I$(top_srcdir)/src

clean-local:
	rm -f sc_debug.log
	rm -f sc_debug.log.old


TESTS                    = kat_hash_drbg

noinst_PROGRAMS               = $(TESTS)


kat_hash_drbg_SOURCES             = kat_hash_drbg.c \
                                        $(top_srcdir)/include/safecrypto.h
kat_hash_drbg_LDADD               = $(top_builddir)/libs/libsafecrypto.la -lm
kat_hash_drbg_LDFLAGS             = -static

endif HAVE_CHECK
