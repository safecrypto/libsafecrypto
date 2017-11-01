
SUBDIRS                  = . crypto


if HAVE_CHECK
TESTS                        = unit_safecrypto_debug \
                               unit_safecrypto_error \
                               unit_safecrypto \
                               unit_ntt \
                               unit_poly_z2 \
                               unit_poly_32 \
                               unit_poly_16 \
                               unit_vectors \
                               unit_entropy \
                               unit_packer \
                               unit_exp_golomb \
                               unit_huffman \
                               unit_sampling \
                               unit_sc_math


if WITH_MULTITHREADING
TESTS                       += unit_threadpool \
                               unit_pipe
endif WITH_MULTITHREADING

if WITH_BLISS_B_SIG
TESTS                       += unit_bliss_b
endif WITH_BLISS_B_SIG
if WITH_RING_TESLA_SIG
TESTS                       += unit_ring_tesla
endif WITH_RING_TESLA_SIG
if WITH_RLWE_ENC
TESTS                       += unit_rlwe_enc
endif WITH_RLWE_ENC
if WITH_ENS_KEM
TESTS                       += unit_ens_kem
endif WITH_ENS_KEM
if BUILD_DILITHIUM
TESTS                       += unit_dilithium
endif BUILD_DILITHIUM

if WITH_ARITH_MLWE
TESTS                       += unit_module_lwe
endif WITH_ARITH_MLWE

if WITH_ARITH_INTEGER_MP
TESTS                       += unit_sc_mpz \
                               unit_sc_poly_mpz \
                               unit_poly_limb \
                               unit_poly_fft \
                               unit_limb
endif WITH_ARITH_INTEGER_MP

if WITH_ARITH_FLOAT_MP
TESTS                       += unit_sc_mpf
endif WITH_ARITH_FLOAT_MP

if WITH_ARITH_NATURAL_MP
TESTS                       += unit_sc_mp
endif WITH_ARITH_NATURAL_MP

if WITH_ARITH_GPV
TESTS                       += unit_gpv
endif WITH_ARITH_GPV

else
TESTS =
endif

noinst_PROGRAMS                = $(TESTS)

unit_sc_math_SOURCES           = unit_sc_math.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_sc_math_CFLAGS            = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_sc_math_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_sc_math_LDADD             = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_sampling_SOURCES          = unit_sampling.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_sampling_CFLAGS           = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_sampling_LDFLAGS          = -pthread
endif WITH_MULTITHREADING
unit_sampling_LDADD            = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_entropy_SOURCES           = unit_entropy.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_entropy_CFLAGS            = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_entropy_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_entropy_LDADD             = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_packer_SOURCES            = unit_packer.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_packer_CFLAGS             = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_packer_LDFLAGS            = -pthread
endif WITH_MULTITHREADING
unit_packer_LDADD              = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

#unit_bac_SOURCES               = unit_bac.c \
#                                 $(top_srcdir)/src/safecrypto_debug.h
#unit_bac_CFLAGS                = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CHECK_CFLAGS@
#unit_bac_LDFLAGS               = -pthread
#unit_bac_LDADD                 = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_exp_golomb_SOURCES        = unit_exp_golomb.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_exp_golomb_CFLAGS         = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_exp_golomb_LDFLAGS        = -pthread
endif WITH_MULTITHREADING
unit_exp_golomb_LDADD          = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_huffman_SOURCES           = unit_huffman.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_huffman_CFLAGS            = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_huffman_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_huffman_LDADD             = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_ntt_SOURCES               = unit_ntt.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_ntt_CFLAGS                = -I$(top_srcdir)/src -I$(top_srcdir)/include @CFLAGS_AVX2@ -I$(top_srcdir)/src/utils/crypto @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_ntt_LDFLAGS               = -pthread
endif WITH_MULTITHREADING
unit_ntt_LDADD                 = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@


if WITH_ARITH_GPV
unit_gpv_SOURCES               = unit_gpv.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_gpv_CFLAGS                = -I$(top_srcdir)/src -I$(top_srcdir)/include @CFLAGS_AVX2@ -I$(top_srcdir)/src/utils/crypto @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_gpv_LDFLAGS               = -pthread
endif WITH_MULTITHREADING
unit_gpv_LDADD                 = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@
endif WITH_ARITH_GPV

if WITH_ARITH_MLWE
unit_module_lwe_SOURCES        = unit_module_lwe.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_module_lwe_CFLAGS         = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
unit_module_lwe_LDFLAGS        =
if WITH_MULTITHREADING
unit_module_lwe_LDFLAGS       += -pthread
endif WITH_MULTITHREADING
if WITH_GMP
unit_module_lwe_LDFLAGS       += -lgmp
endif
unit_module_lwe_LDADD          = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@
endif WITH_ARITH_MLWE

if WITH_ARITH_NATURAL_MP
unit_sc_mp_SOURCES             = unit_sc_mp.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_sc_mp_CFLAGS              = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
unit_sc_mp_LDFLAGS             =
if WITH_MULTITHREADING
unit_sc_mp_LDFLAGS            += -pthread
endif WITH_MULTITHREADING
if WITH_MPFR
unit_sc_mp_LDFLAGS            += -lmpfr
endif
if WITH_GMP
unit_sc_mp_LDFLAGS            += -lgmp
endif
unit_sc_mp_LDADD               = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@
endif WITH_ARITH_NATURAL_MP

if WITH_ARITH_FLOAT_MP
unit_sc_mpf_SOURCES            = unit_sc_mpf.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_sc_mpf_CFLAGS             = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
unit_sc_mpf_LDFLAGS            =
if WITH_MULTITHREADING
unit_sc_mpf_LDFLAGS           += -pthread
endif WITH_MULTITHREADING
if WITH_MPFR
unit_sc_mpf_LDFLAGS           += -lmpfr
endif
if WITH_GMP
unit_sc_mpf_LDFLAGS           += -lgmp
endif
unit_sc_mpf_LDADD              = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@
endif WITH_ARITH_FLOAT_MP

if WITH_ARITH_INTEGER_MP
unit_sc_mpz_SOURCES            = unit_sc_mpz.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_sc_mpz_CFLAGS             = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
unit_sc_mpz_LDFLAGS            =
if WITH_MULTITHREADING
unit_sc_mpz_LDFLAGS           += -pthread
endif WITH_MULTITHREADING
if WITH_GMP
unit_sc_mpz_LDFLAGS           += -lgmp
endif
unit_sc_mpz_LDADD              = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_sc_poly_mpz_SOURCES       = unit_sc_poly_mpz.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_sc_poly_mpz_CFLAGS        = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
unit_sc_poly_mpz_LDFLAGS       =
if WITH_MULTITHREADING
unit_sc_poly_mpz_LDFLAGS      += -pthread
endif WITH_MULTITHREADING
if WITH_GMP
unit_sc_poly_mpz_LDFLAGS      += -lgmp
endif
unit_sc_poly_mpz_LDADD         = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_limb_SOURCES              = unit_limb.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_limb_CFLAGS               = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
unit_limb_LDFLAGS              =
if WITH_MULTITHREADING
unit_limb_LDFLAGS             += -pthread
endif WITH_MULTITHREADING
if WITH_GMP
unit_limb_LDFLAGS             += -lgmp
endif
unit_limb_LDADD                = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_poly_limb_SOURCES         = unit_poly_limb.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_poly_limb_CFLAGS          = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
unit_poly_limb_LDFLAGS         =
if WITH_MULTITHREADING
unit_poly_limb_LDFLAGS        += -pthread
endif WITH_MULTITHREADING
if WITH_GMP
unit_poly_limb_LDFLAGS        += -lgmp
endif
unit_poly_limb_LDADD           = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_poly_fft_SOURCES          = unit_poly_fft.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_poly_fft_CFLAGS           = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_poly_fft_LDFLAGS          = -pthread
endif WITH_MULTITHREADING
unit_poly_fft_LDADD            = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@
endif WITH_ARITH_INTEGER_MP

unit_poly_z2_SOURCES           = unit_poly_z2.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_poly_z2_CFLAGS            = -I$(top_srcdir)/src -I$(top_srcdir)/include @CFLAGS_AVX2@ -I$(top_srcdir)/src/utils/crypto @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_poly_z2_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_poly_z2_LDADD             = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_poly_32_SOURCES           = unit_poly_32.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_poly_32_CFLAGS            = -I$(top_srcdir)/src -I$(top_srcdir)/include @CFLAGS_AVX2@ -I$(top_srcdir)/src/utils/crypto @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_poly_32_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_poly_32_LDADD             = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_poly_16_SOURCES           = unit_poly_16.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_poly_16_CFLAGS            = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_poly_16_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_poly_16_LDADD             = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_vectors_SOURCES           = unit_vectors.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_vectors_CFLAGS            = -I$(top_srcdir)/src -I$(top_srcdir)/include @CFLAGS_AVX2@ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_vectors_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_vectors_LDADD             = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

if WITH_MULTITHREADING
unit_threadpool_SOURCES        = unit_threadpool.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_threadpool_CFLAGS         = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
unit_threadpool_LDFLAGS        = -pthread
unit_threadpool_LDADD          = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_pipe_SOURCES              = unit_pipe.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_pipe_CFLAGS               = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
unit_pipe_LDFLAGS              = -pthread
unit_pipe_LDADD                = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@
endif WITH_MULTITHREADING

unit_safecrypto_debug_SOURCES  = unit_safecrypto_debug.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_safecrypto_debug_CFLAGS   = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
unit_safecrypto_debug_LDFLAGS  =
if WITH_MULTITHREADING
unit_safecrypto_debug_LDFLAGS += -pthread
endif WITH_MULTITHREADING
if WITH_MPFR
unit_safecrypto_debug_LDFLAGS += -lmpfr
endif
if WITH_GMP
unit_safecrypto_debug_LDFLAGS += -lgmp
endif
unit_safecrypto_debug_LDADD    = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_safecrypto_error_SOURCES  = unit_safecrypto_error.c \
                                 $(top_srcdir)/src/safecrypto_error.h
unit_safecrypto_error_CFLAGS   = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
unit_safecrypto_error_LDFLAGS  =
if WITH_MULTITHREADING
unit_safecrypto_error_LDFLAGS += -pthread
endif WITH_MULTITHREADING
if WITH_MPFR
unit_safecrypto_error_LDFLAGS += -lmpfr
endif
if WITH_GMP
unit_safecrypto_error_LDFLAGS += -lgmp
endif
unit_safecrypto_error_LDADD    = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

unit_safecrypto_SOURCES        = unit_safecrypto.c \
                                 $(top_srcdir)/include/safecrypto.h
unit_safecrypto_CFLAGS         = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
unit_safecrypto_LDFLAGS        =
if WITH_MULTITHREADING
unit_safecrypto_LDFLAGS       += -pthread
endif WITH_MULTITHREADING
if WITH_MPFR
unit_safecrypto_LDFLAGS       += -lmpfr
endif
if WITH_GMP
unit_safecrypto_LDFLAGS       += -lgmp
endif
unit_safecrypto_LDADD          = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

###############################################################################
#                          BLISS-B SIGNATURE SCHEME
###############################################################################
if WITH_BLISS_B_SIG

unit_bliss_b_SOURCES    = unit_bliss_b.c
unit_bliss_b_CFLAGS     = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_bliss_b_LDFLAGS    = -pthread
endif WITH_MULTITHREADING
unit_bliss_b_LDADD      = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

endif WITH_BLISS_B_SIG

###############################################################################
#                         RING-TESLA SIGNATURE SCHEME
###############################################################################
if WITH_RING_TESLA_SIG

unit_ring_tesla_SOURCES = unit_ring_tesla.c
unit_ring_tesla_CFLAGS  = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_ring_tesla_LDFLAGS = -pthread
endif WITH_MULTITHREADING
unit_ring_tesla_LDADD   = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

endif WITH_RING_TESLA_SIG

###############################################################################
#                         RING-LWE ENCRYPTION SCHEME
###############################################################################
if WITH_RLWE_ENC

unit_rlwe_enc_SOURCES   = unit_rlwe_enc.c
unit_rlwe_enc_CFLAGS    = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_rlwe_enc_LDFLAGS   = -pthread
endif WITH_MULTITHREADING
unit_rlwe_enc_LDADD     = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

endif WITH_RLWE_ENC

###############################################################################
#         "THE WHOLE IS LESS THAN THE SUM OF ITS PARTS" KEM SCHEME
###############################################################################
if WITH_ENS_KEM

unit_ens_kem_SOURCES    = unit_ens_kem.c
unit_ens_kem_CFLAGS     = -I$(top_srcdir)/src -I$(top_srcdir)/include @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_ens_kem_LDFLAGS    = -pthread
endif WITH_MULTITHREADING
unit_ens_kem_LDADD      = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

endif WITH_ENS_KEM

###############################################################################
#                         DILITHIUM SIGNATURE SCHEME
###############################################################################
if BUILD_DILITHIUM

unit_dilithium_SOURCES         = unit_dilithium.c \
                                 $(top_srcdir)/src/safecrypto_debug.h
unit_dilithium_CFLAGS          = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_srcdir)/src/utils/crypto @CFLAGS_AVX2@ @CHECK_CFLAGS@
unit_dilithium_LDFLAGS         =
if WITH_MULTITHREADING
unit_dilithium_LDFLAGS        += -pthread
endif WITH_MULTITHREADING
if WITH_GMP
unit_dilithium_LDFLAGS        += -lgmp
endif
unit_dilithium_LDADD           = $(top_builddir)/libs/libsafecrypto.la @CHECK_LIBS@

endif BUILD_DILITHIUM
