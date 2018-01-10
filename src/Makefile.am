
###############################################################################
#                          CONVENIENCE LIBRARIES
###############################################################################

SUBDIRS                  = schemes utils . unit


###############################################################################
#                      TOP-LEVEL: SAFEcrypto LIBRARY
###############################################################################

# API header files for installation (installed in /usr/local/include/safecrypto)
pkginclude_HEADERS = ../include/safecrypto.h ../include/safecrypto_types.h

# Obtain the configure invocation command
CMD  := $(shell $(top_srcdir)/config.status --config)
CMD2 := $(subst $\',,$(CMD))

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src/utils/crypto \
                           -DCONFIGURE_INVOCATION='"$(CMD2)"'

# The SAFEcrypto library target
lib_LTLIBRARIES          = $(top_builddir)/libs/libsafecrypto.la

# Top-level source code
__top_builddir__libs_libsafecrypto_la_SOURCES = \
                           ../include/safecrypto.h \
                           ../include/safecrypto_types.h \
                           safecrypto.c \
                           safecrypto_version.h \
                           safecrypto_ake.c \
                           safecrypto_check.h \
                           safecrypto_check.c \
                           safecrypto_private.h \
                           safecrypto_private.c \
                           safecrypto_debug.h \
                           safecrypto_debug.c \
                           safecrypto_error.h \
                           safecrypto_error.c \
                           safecrypto_timer.h \
                           safecrypto_timer.c

DEFAULT_LIBS             = schemes/helloworld/libhelloworld.la \
                           utils/arith/libarith.la \
                           utils/crypto/libcrypto.la \
                           utils/sampling/libsampling.la \
                           utils/entropy/libentropy.la \
                           utils/third_party/lib_3rd_party.la

OPTIONAL_LIBS            =

if WITH_MULTITHREADING
OPTIONAL_LIBS           += utils/threading/libthreading.la
endif WITH_MULTITHREADING

if WITH_BLISS_B_SIG
OPTIONAL_LIBS           += schemes/sig/bliss_b/libblissb.la
endif WITH_BLISS_B_SIG

if WITH_RING_TESLA_SIG
OPTIONAL_LIBS           += schemes/sig/ring_tesla/libringtesla.la
endif WITH_RING_TESLA_SIG
if WITH_RLWE_ENC
OPTIONAL_LIBS           += schemes/enc/rlwe_enc/librlweenc.la
endif WITH_RLWE_ENC
if WITH_ENS_KEM
OPTIONAL_LIBS           += schemes/kem/ens/libenskem.la
endif WITH_ENS_KEM
if WITH_KYBER_ENC
OPTIONAL_LIBS           += schemes/enc/kyber/libkyberenc.la
endif WITH_KYBER_ENC

if WITH_DILITHIUM_SIG
OPTIONAL_LIBS           += schemes/sig/dilithium/libdilithium.la
else
if WITH_DILITHIUM_G_SIG
OPTIONAL_LIBS           += schemes/sig/dilithium/libdilithium.la
endif WITH_DILITHIUM_G_SIG
endif !WITH_DILITHIUM_SIG

if WITH_KYBER_KEM
OPTIONAL_LIBS           += schemes/kem/kyber/libkyberkem.la
endif WITH_KYBER_KEM

if BUILD_DLP_ENS_SIG
OPTIONAL_LIBS           += schemes/sig/ens_dlp/libensdlpsig.la
endif BUILD_DLP_ENS_SIG

if WITH_DLP_IBE
OPTIONAL_LIBS           += schemes/ibe/dlp/libibe.la
endif WITH_DLP_IBE

OPTIONAL_LIBS           += schemes/dh/ecdh/libecdh.la

# Add references to algorithm libraries here
__top_builddir__libs_libsafecrypto_la_LIBADD  = $(DEFAULT_LIBS) $(OPTIONAL_LIBS)

# Linker flags include the library interface version
if WITH_MULTITHREADING
__top_builddir__libs_libsafecrypto_la_LDFLAGS = \
    -no-undefined \
    -version-info $(libsc_la_version_info) -lpthread -lm
else !WITH_MULTITHREADING
__top_builddir__libs_libsafecrypto_la_LDFLAGS = \
    -no-undefined \
    -version-info $(libsc_la_version_info) -lm
endif !WITH_MULTITHREADING
