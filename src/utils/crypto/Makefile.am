ACLOCAL_AMFLAGS = -I m4 -I /usr/share/aclocal

SUBDIRS     = . unit

###############################################################################
#                      SAFEcrypto Third Party TOOLBOX
###############################################################################

# C preprocessor flags
AM_CPPFLAGS              += -I$(top_srcdir) \
                            -DECRYPT_API="ecrypt-sync.h"

# Convenience libraries
noinst_LTLIBRARIES        = libcrypto.la lib_3rd_crypto.la lib_3rd_isaac.la
if HAVE_64BIT
lib_3rd_isaac_la_SOURCES  = isaac/isaac64.c \
                            isaac/isaac64.h \
                            isaac/standard.h
else
lib_3rd_isaac_la_SOURCES  = isaac/rand.c \
                            isaac/rand.h \
                            isaac/standard.h
endif
lib_3rd_isaac_la_LIBADD   = 

if CONSTRAINED_SYSTEM
lib_3rd_crypto_la_SOURCES = aes/aes.h \
                            aes/aescrypt.c \
                            aes/aeskey.c \
                            aes/aes_modes.c \
                            aes/aes_ni.c \
                            aes/aes_ni.h \
                            aes/aesopt.h \
                            aes/aestab.c \
                            aes/aestab.h \
                            aes/aes_via_ace.h \
                            salsa/salsa20.c \
                            salsa/salsa20.h \
                            sha3/fips202.c \
                            sha3/fips202.h \
                            sha3/tinysha3.c \
                            sha3/tinysha3.h \
                            sha3/sha3.c \
                            sha3/sha3.h
else
lib_3rd_crypto_la_SOURCES = aes/aes.h \
                            aes/aescrypt.c \
                            aes/aeskey.c \
                            aes/aes_modes.c \
                            aes/aes_ni.c \
                            aes/aes_ni.h \
                            aes/aesopt.h \
                            aes/aestab.c \
                            aes/aestab.h \
                            aes/aes_via_ace.h \
                            aes/brg_endian.h \
                            aes/brg_types.h \
                            aes256ctr/crypto_stream_aes256ctr.c \
                            aes256ctr/crypto_stream_aes256ctr.h \
                            blake2/blake2b-ref.c \
                            blake2/blake2xb-ref.c \
                            blake2/blake2-impl.h \
                            blake2/blake2.h \
                            blake2/blake2_safecrypto.c \
                            blake2/blake2_safecrypto.h \
                            chacha/chacha20.c \
                            chacha/chacha20.h \
                            mersenne_twister/mt19937ar.c \
                            mersenne_twister/mt19937ar.h \
                            salsa/salsa20.c \
                            salsa/salsa20.h \
                            sha3/fips202.c \
                            sha3/fips202.h \
                            sha3/tinysha3.c \
                            sha3/tinysha3.h \
                            sha2/sha2.c \
                            sha2/sha2.h \
                            sha2/brg_endian.h \
                            sha2/brg_types.h \
                            sha2/sha2_safecrypto.c \
                            sha2/sha2_safecrypto.h \
                            whirlpool/whirlpool.c \
                            whirlpool/whirlpool.h
endif

lib_3rd_crypto_la_LIBADD  = lib_3rd_isaac.la


###############################################################################
#                      SAFEcrypto Cryptographic TOOLBOX
###############################################################################

# C preprocessor flags
AM_CPPFLAGS              += -I$(top_srcdir)/include \
                            -I$(top_srcdir)/src \
                            -DSHA3_UNROLLED

# Convenience library
if CONSTRAINED_SYSTEM
libcrypto_la_SOURCES      = prng_types.c \
                            prng_types.h \
                            hash.c \
                            hash.h \
                            xof.c \
                            xof.h \
                            prng.c \
                            prng.h \
                            prng_get_func.c \
                            prng_get_func.h \
                            ctr_drbg.c \
                            ctr_drbg.h
else
libcrypto_la_SOURCES      = prng_types.c \
                            prng_types.h \
                            hash.c \
                            hash.h \
                            xof.c \
                            xof.h \
                            prng.c \
                            prng.h \
                            prng_get_func.c \
                            prng_get_func.h \
                            aes_ctr_stream.c \
                            aes_ctr_stream.h \
                            hash_drbg.c \
                            hash_drbg.h \
                            kiss.c \
                            kiss.h \
                            chacha20_csprng.c \
                            chacha20_csprng.h \
                            salsa20_csprng.c \
                            salsa20_csprng.h \
                            isaac_csprng.c \
                            isaac_csprng.h \
                            ctr_drbg.c \
                            ctr_drbg.h
endif

# Add any link library dependencies
libcrypto_la_LIBADD       = lib_3rd_crypto.la
