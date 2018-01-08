
###############################################################################
#                      SAFEcrypto Arithmetic TOOLBOX
###############################################################################

# C preprocessor flags
AM_CPPFLAGS              += -I$(top_srcdir)/src \
                            -I$(top_srcdir)/include \
                            -I$(top_srcdir)/src/utils/third_party/libtommath-develop

# Convenience library
noinst_LTLIBRARIES        = libarith.la
libarith_la_SOURCES       = arith.c \
                            arith.h \
                            sc_math.c \
                            sc_math.h \
                            poly_16.c \
                            poly_16.h \
                            poly_32.c \
                            poly_32.h \
                            poly_z2.c \
                            poly_z2.h \
                            vectors.c \
                            vectors.h \
                            roots_of_unity.c \
                            roots_of_unity.h \
                            ntt.c \
                            ntt.h \
                            ntt_barrett.c \
                            ntt_barrett.h \
                            ntt_fp.c \
                            ntt_fp.h \
                            ntt_reference.c \
                            ntt_reference.h \
                            ntt_7681.c \
                            ntt_7681.h \
                            ntt_8380417.c \
                            ntt_8380417.h \
                            limb.c \
                            limb.h \
                            limb_base.c \
                            limb_base.h \
                            sc_mp.c \
                            sc_mp.h
#                            ntt_barrett_rev.c \
#                            ntt_barrett_rev.h \
#                            ntt_fp_rev.c \
#                            ntt_fp_rev.h \
#                            ntt_reference_rev.c \
#                            ntt_reference_rev.h \
#                            ntt_7681_rev.c \
#                            ntt_7681_rev.h \
#                            ntt_8380417_rev.c \
#                            ntt_8380417_rev.h

if WITH_AVX2
libarith_la_SOURCES      += ntt_avx.c \
                            ntt_avx.h
#                            ntt_avx_rev.c \
#                            ntt_avx_rev.h
endif WITH_AVX2

if WITH_ARITH_MLWE
libarith_la_SOURCES      += module_lwe.c \
                            module_lwe.h
endif WITH_ARITH_MLWE

if WITH_ARITH_INTEGER_MP
libarith_la_SOURCES      += next_prime.c \
                            next_prime.h \
                            poly_fft.c \
                            poly_fft.h \
                            poly_limb.c \
                            poly_limb.h \
                            sc_mpz.c \
                            sc_mpz.h \
                            sc_poly_mpz.c \
                            sc_poly_mpz.h
endif WITH_ARITH_INTEGER_MP

if WITH_ARITH_FLOAT_MP
libarith_la_SOURCES      += sc_mpf.c \
                            sc_mpf.h \
                            sc_mpf128.c \
                            sc_mpf128.h
endif WITH_ARITH_FLOAT_MP

if WITH_ARITH_NATURAL_MP
libarith_la_SOURCES      += sc_mpn.c \
                            sc_mpn.h
endif WITH_ARITH_NATURAL_MP

if WITH_ARITH_GPV
libarith_la_SOURCES      += gpv.c \
                            gpv.h
endif WITH_ARITH_GPV

if !USE_RUNTIME_NTT_TABLES
libarith_la_SOURCES      += ntt_tables.c \
                            ntt_tables.h
endif

# Add any link library dependencies
libarith_la_LIBADD        =
if WITH_MPFR
libarith_la_LIBADD       += -lmpfr
endif WITH_MPFR
if WITH_GMP
libarith_la_LIBADD       += -lgmp
endif WITH_GMP

