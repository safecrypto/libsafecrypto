if HAVE_CHECK

@VALGRIND_CHECK_RULES@

AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src \
                           -I$(top_srcdir)/src/utils/crypto

clean-local:
	rm -f gaussian_dist.dat
	rm -f sc_debug.log
	rm -f sc_debug.log.old


TESTS                    = func_safecrypto \
                           func_hash_comparison \
                           func_xof_comparison \
                           func_samplers \
                           func_csprng \
                           func_sc_math \
                           func_ntt \
                           func_alg_2way_ake \
                           func_alg_2way_ake_huffman

#                           func_signatures_schemes

if WITH_MULTITHREADING
TESTS                   += func_threading
endif WITH_MULTITHREADING

if WITH_ARITH_MP
TESTS                   += func_poly_limb_mul \
                           func_poly_limb_divrem_mod \
                           func_poly_mpi_mul
endif WITH_ARITH_MP

if WITH_BLISS_B_SIG
TESTS                   += func_alg_bliss_b \
                           func_alg_bliss_b_huffman
endif WITH_BLISS_B_SIG

if WITH_RING_TESLA_SIG
TESTS                   += func_alg_ring_tesla \
                           func_alg_ring_tesla_huffman
endif WITH_RING_TESLA_SIG

if WITH_RLWE_ENC
TESTS                   += func_alg_rlwe_enc \
                           func_alg_rlwe_enc_huffman
endif WITH_RLWE_ENC

if WITH_ENS_KEM
TESTS                   += func_alg_ens_kem \
                           func_alg_ens_kem_huffman
endif WITH_ENS_KEM

if WITH_KYBER_KEM
TESTS                   += func_alg_kyber_kem \
                           func_alg_kyber_kem_huffman
endif WITH_KYBER_KEM

if WITH_KYBER_ENC
TESTS                   += func_alg_kyber_enc \
                           func_alg_kyber_enc_huffman
endif WITH_KYBER_ENC

if WITH_ENS_SIG
TESTS                   += func_alg_ens_sig \
                           func_alg_ens_sig_recovery \
                           func_alg_ens_sig_huffman \
                           func_alg_ens_sig_recovery_huffman
endif WITH_ENS_SIG

if WITH_DLP_IBE
TESTS                   += func_alg_dlp_ibe \
                           func_alg_dlp_ibe_huffman \
                           func_ibe_test
endif WITH_DLP_IBE

if WITH_DLP_SIG
TESTS                   += func_alg_dlp_sig \
                           func_alg_dlp_sig_recovery \
                           func_alg_dlp_sig_huffman \
                           func_alg_dlp_sig_recovery_huffman
endif WITH_DLP_SIG

if BUILD_DILITHIUM
TESTS                   += func_alg_dilithium \
                           func_alg_dilithium_g \
                           func_alg_dilithium_huffman \
                           func_alg_dilithium_g_huffman
endif BUILD_DILITHIUM

noinst_PROGRAMS          = $(TESTS)


if WITH_DLP_IBE
func_ibe_test_SOURCES                = func_ibe_test.c \
                                       $(top_srcdir)/include/safecrypto.h
func_ibe_test_LDADD                  = $(top_builddir)/libs/libsafecrypto.la
func_ibe_test_LDFLAGS                = -static
endif

if WITH_ENS_SIG
func_alg_ens_sig_SOURCES             = func_alg_ens_sig.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_ens_sig_LDADD               = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ens_sig_LDFLAGS             = -static

func_alg_ens_sig_huffman_SOURCES     = func_alg_ens_sig.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_ens_sig_huffman_LDADD       = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ens_sig_huffman_CFLAGS      = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_ens_sig_huffman_LDFLAGS     = -static

func_alg_ens_sig_recovery_SOURCES    = func_alg_ens_sig_recovery.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_ens_sig_recovery_LDADD      = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ens_sig_recovery_LDFLAGS    = -static

func_alg_ens_sig_recovery_huffman_SOURCES = func_alg_ens_sig_recovery.c \
                                            $(top_srcdir)/include/safecrypto.h
func_alg_ens_sig_recovery_huffman_LDADD   = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ens_sig_recovery_huffman_CFLAGS  = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_ens_sig_recovery_huffman_LDFLAGS = -static
endif

func_alg_2way_ake_SOURCES            = func_alg_2way_ake.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_2way_ake_LDADD              = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_2way_ake_LDFLAGS            = -static

func_alg_2way_ake_huffman_SOURCES    = func_alg_2way_ake.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_2way_ake_huffman_LDADD      = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_2way_ake_huffman_CFLAGS     = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_2way_ake_huffman_LDFLAGS    = -static

if WITH_DLP_IBE
func_alg_dlp_ibe_SOURCES             = func_alg_dlp_ibe.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dlp_ibe_LDADD               = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dlp_ibe_LDFLAGS             = -static

func_alg_dlp_ibe_huffman_SOURCES     = func_alg_dlp_ibe.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dlp_ibe_huffman_LDADD       = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dlp_ibe_huffman_CFLAGS      = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_dlp_ibe_huffman_LDFLAGS     = -static
endif

if WITH_DLP_SIG
func_alg_dlp_sig_SOURCES             = func_alg_dlp_sig.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dlp_sig_LDADD               = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dlp_sig_LDFLAGS             = -static

func_alg_dlp_sig_huffman_SOURCES     = func_alg_dlp_sig.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dlp_sig_huffman_LDADD       = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dlp_sig_huffman_CFLAGS      = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_dlp_sig_huffman_LDFLAGS     = -static

func_alg_dlp_sig_recovery_SOURCES    = func_alg_dlp_sig_recovery.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dlp_sig_recovery_LDADD      = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dlp_sig_recovery_LDFLAGS    = -static

func_alg_dlp_sig_recovery_huffman_SOURCES = func_alg_dlp_sig_recovery.c \
                                            $(top_srcdir)/include/safecrypto.h
func_alg_dlp_sig_recovery_huffman_LDADD   = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dlp_sig_recovery_huffman_CFLAGS  = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_dlp_sig_recovery_huffman_LDFLAGS = -static
endif

if WITH_DILITHIUM_SIG
func_alg_dilithium_SOURCES           = func_alg_dilithium.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dilithium_LDADD             = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dilithium_CFLAGS            = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_dilithium_LDFLAGS           = -static

func_alg_dilithium_huffman_SOURCES   = func_alg_dilithium.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dilithium_huffman_LDADD     = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dilithium_huffman_CFLAGS    = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_dilithium_huffman_LDFLAGS   = -static

func_alg_dilithium_g_SOURCES         = func_alg_dilithium_g.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_dilithium_g_LDADD           = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dilithium_g_LDFLAGS         = -static

func_alg_dilithium_g_huffman_SOURCES = func_alg_dilithium_g.c \
                                      $(top_srcdir)/include/safecrypto.h
func_alg_dilithium_g_huffman_LDADD   = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_dilithium_g_huffman_CFLAGS  = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_dilithium_g_huffman_LDFLAGS = -static
endif

if WITH_KYBER_KEM
func_alg_kyber_kem_SOURCES           = func_alg_kyber_kem.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_kyber_kem_LDADD             = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_kyber_kem_LDFLAGS           = -static

func_alg_kyber_kem_huffman_SOURCES   = func_alg_kyber_kem.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_kyber_kem_huffman_LDADD     = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_kyber_kem_huffman_CFLAGS    = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_kyber_kem_huffman_LDFLAGS   = -static
endif

if WITH_KYBER_ENC
func_alg_kyber_enc_SOURCES           = func_alg_kyber_enc.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_kyber_enc_LDADD             = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_kyber_enc_LDFLAGS           = -static

func_alg_kyber_enc_huffman_SOURCES   = func_alg_kyber_enc.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_kyber_enc_huffman_LDADD     = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_kyber_enc_huffman_CFLAGS    = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_kyber_enc_huffman_LDFLAGS   = -static
endif

if WITH_ARITH_MP
func_poly_limb_mul_SOURCES           = func_poly_limb_mul.c \
                                       $(top_srcdir)/include/safecrypto.h
func_poly_limb_mul_LDADD             = $(top_builddir)/libs/libsafecrypto.la -lm
func_poly_limb_mul_LDFLAGS           = -static

func_poly_limb_divrem_mod_SOURCES    = func_poly_limb_divrem_mod.c \
                                       $(top_srcdir)/include/safecrypto.h
func_poly_limb_divrem_mod_LDADD      = $(top_builddir)/libs/libsafecrypto.la -lm
func_poly_limb_divrem_mod_LDFLAGS    = -static

func_poly_mpi_mul_SOURCES            = func_poly_mpi_mul.c \
                                        $(top_srcdir)/include/safecrypto.h
func_poly_mpi_mul_LDADD              = $(top_builddir)/libs/libsafecrypto.la -lm
func_poly_mpi_mul_LDFLAGS            = -static
endif


func_safecrypto_SOURCES              = func_safecrypto.c \
                                       $(top_srcdir)/include/safecrypto.h
func_safecrypto_LDADD                = $(top_builddir)/libs/libsafecrypto.la

if WITH_BLISS_B_SIG
func_alg_bliss_b_SOURCES             = func_alg_bliss_b.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_bliss_b_LDADD               = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_bliss_b_LDFLAGS             = -static

func_alg_bliss_b_huffman_SOURCES     = func_alg_bliss_b.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_bliss_b_huffman_LDADD       = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_bliss_b_huffman_CFLAGS      = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_bliss_b_huffman_LDFLAGS     = -static
endif WITH_BLISS_B_SIG

if WITH_RING_TESLA_SIG
func_alg_ring_tesla_SOURCES          = func_alg_ring_tesla.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_ring_tesla_LDADD            = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ring_tesla_LDFLAGS          = -static

func_alg_ring_tesla_huffman_SOURCES  = func_alg_ring_tesla.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_ring_tesla_huffman_LDADD    = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ring_tesla_huffman_CFLAGS   = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_ring_tesla_huffman_LDFLAGS  = -static
endif WITH_RING_TESLA_SIG

func_hash_comparison_SOURCES         = func_hash_comparison.c \
                                           $(top_srcdir)/include/safecrypto.h
func_hash_comparison_LDADD           = $(top_builddir)/libs/libsafecrypto.la -lm
func_hash_comparison_LDFLAGS         = -static

func_xof_comparison_SOURCES          = func_xof_comparison.c \
                                           $(top_srcdir)/include/safecrypto.h
func_xof_comparison_LDADD            = $(top_builddir)/libs/libsafecrypto.la -lm
func_xof_comparison_LDFLAGS          = -static

func_samplers_SOURCES                = func_samplers.c \
                                           $(top_srcdir)/include/safecrypto.h
func_samplers_LDADD                  = $(top_builddir)/libs/libsafecrypto.la -lm
func_samplers_LDFLAGS                = -static

func_csprng_SOURCES                  = func_csprng.c \
                                           $(top_srcdir)/include/safecrypto.h
func_csprng_LDADD                    = $(top_builddir)/libs/libsafecrypto.la -lm
func_csprng_LDFLAGS                  = -static

func_sc_math_SOURCES                 = func_sc_math.c \
                                           $(top_srcdir)/include/safecrypto.h
func_sc_math_LDADD                   = $(top_builddir)/libs/libsafecrypto.la -lm
func_sc_math_LDFLAGS                 = -static

func_ntt_SOURCES                     = func_ntt.c \
                                       $(top_srcdir)/include/safecrypto.h
func_ntt_LDADD                       = $(top_builddir)/libs/libsafecrypto.la -lm
func_ntt_LDFLAGS                     = -static

func_threading_SOURCES               = func_threading.c \
                                       $(top_srcdir)/include/safecrypto.h
func_threading_LDADD                 = $(top_builddir)/libs/libsafecrypto.la -lm
func_threading_LDFLAGS               = -static

if WITH_RLWE_ENC
func_alg_rlwe_enc_SOURCES            = func_alg_rlwe_enc.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_rlwe_enc_LDADD              = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_rlwe_enc_LDFLAGS            = -static

func_alg_rlwe_enc_huffman_SOURCES    = func_alg_rlwe_enc.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_rlwe_enc_huffman_LDADD      = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_rlwe_enc_huffman_CFLAGS     = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_rlwe_enc_huffman_LDFLAGS    = -static
endif WITH_RLWE_ENC

if WITH_ENS_KEM
func_alg_ens_kem_SOURCES             = func_alg_ens_kem.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_ens_kem_LDADD               = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ens_kem_LDFLAGS             = -static

func_alg_ens_kem_huffman_SOURCES     = func_alg_ens_kem.c \
                                       $(top_srcdir)/include/safecrypto.h
func_alg_ens_kem_huffman_LDADD       = $(top_builddir)/libs/libsafecrypto.la -lm
func_alg_ens_enc_huffman_CFLAGS      = -DUSE_HUFFMAN_STATIC_ENTROPY
func_alg_ens_kem_huffman_LDFLAGS     = -static
endif WITH_ENS_KEM

#func_signatures_schemes_SOURCES      = func_signatures_schemes.c \
#                                       $(top_srcdir)/include/safecrypto.h
#func_signatures_schemes_LDADD        =  $(top_builddir)/libs/libsafecrypto.la -lm
#func_signatures_schemes_LDFLAGS      = -static

endif
