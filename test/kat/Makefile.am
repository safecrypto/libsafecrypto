if HAVE_CHECK

AM_CPPFLAGS             += -I$(top_srcdir)/include -I$(top_srcdir)/src

clean-local:
	rm -f sc_debug.log
	rm -f sc_debug.log.old


TESTS                    = kat_hash_drbg
if WITH_ECDH_KEM
TESTS                   += kat_ecdh_secp256r1
endif WITH_ECDH_KEM

noinst_PROGRAMS               = $(TESTS)


kat_hash_drbg_SOURCES             = kat_hash_drbg.c \
                                        $(top_srcdir)/include/safecrypto.h
kat_hash_drbg_LDADD               = $(top_builddir)/libs/libsafecrypto.la -lm
kat_hash_drbg_LDFLAGS             = -static

if WITH_ECDH_KEM
kat_ecdh_secp256r1_SOURCES        = kat_ecdh_secp256r1.c \
                                        $(top_srcdir)/include/safecrypto.h
kat_ecdh_secp256r1_LDADD          = $(top_builddir)/libs/libsafecrypto.la -lm
kat_ecdh_secp256r1_LDFLAGS        = -static
endif WITH_ECDH_KEM

endif HAVE_CHECK
