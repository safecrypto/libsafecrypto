/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#include "bliss_b.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/arith/arith.h"
#include "utils/arith/sc_math.h"
#include "utils/entropy/packer.h"
#include "utils/entropy/entropy.h"
#include "utils/sampling/sampling.h"
#ifdef HAVE_MULTITHREADING
#include "utils/threading/threading.h"
#include "utils/threading/threadpool.h"
#endif

#include "hash.h"
#include "prng.h"

#include "bliss_params.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif

#define BLISS_NUM_PRIV_RING_POLY    2
#define BLISS_NUM_PUB_RING_POLY     2


#define PTR_ALIGN(p,a,l)   (((size_t)((p) + (a) - 1) >> (size_t)(l)) << (size_t)(l))


/// A preprocessor macro for barrett reduction:
///     r = x - q*((x*m) >> k)
///     if (q < r) r -= q
#define BARRETT_REDUCTION(r,x,k,m,q) \
    {SINT64 t, c; \
    t = ((SINT64)(x) * (m)) >> (k); \
    c = (x) - t * (q); \
    if ((q) <= c) \
        c -= (q); \
    r = (SINT32) c;}


#ifdef HAVE_MULTITHREADING

sc_threadpool_t *threadpool = NULL;

static UINT32 refcount[3] = {0};


void * keygen_g_producer_worker(void *p)
{
    safecrypto_t *sc = (safecrypto_t*) p;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->bliss->ntt;

    UINT16 n = sc->bliss->params->n;
    const UINT16 *nz = sc->bliss->params->nz;
    const SINT16 *w = sc->bliss->params->w;

    SINT32 data[1024];
    SINT32 *g = data;
    SINT32 *t = data + n;

    // Generate a random private-key polynomial g
    sc_poly->uniform_32(sc->prng_ctx[1], g, n, nz, 2);
    sc_poly->mul_32_scalar(g, n, 2);
    sc_poly->add_32_scalar(g, n, 1);
    sc_ntt->fwd_ntt_32_16(t, ntt, g, w);

    pipe_push(sc->bliss->pipe_producer_a, data, 2*n);

    refcount[0]++;

    return NULL;
}

void * keygen_f_producer_worker(void *p)
{
    safecrypto_t *sc = (safecrypto_t*) p;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->bliss->ntt;

    UINT16 n = sc->bliss->params->n;
    const UINT16 *nz = sc->bliss->params->nz;
    const SINT16 *w = sc->bliss->params->w;

    SINT32 data[1024];
    SINT32 *f = data;
    SINT32 *u = data + n;

restart:
    sc->stats.keygen_num_trials++;

    // Generate a random polynomial f
    sc_poly->uniform_32(sc->prng_ctx[2], f, n, nz, 2);

    // Create NTT(f)
    sc_ntt->fwd_ntt_32_16(u, ntt, f, w);

    // Attempt to invert NTT(f)
    if (SC_FUNC_FAILURE == sc_ntt->invert_32(u, ntt, n)) {
        goto restart;
    }

    // Success, write the two polynomials to the data pipeline
    pipe_push(sc->bliss->pipe_producer_b, data, 2*n);

    refcount[1]++;

    return NULL;
}

static void round_and_drop(SINT32 *u, SINT32 *v, SINT16 *z,
    UINT16 d, UINT16 q, ntt_params_t *ntt_2q, ntt_params_t *ntt_p);

void * sign_1_worker(void *s)
{
    safecrypto_t *sc = (safecrypto_t*) s;

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    utils_sampling_t *sc_gauss = sc->bliss->sc_gauss_1;
    ntt_params_t *ntt = &sc->bliss->ntt;

    UINT16 n = sc->bliss->params->n;
    const SINT16 *w = sc->bliss->params->w;

    static SINT32 data[3*512];
    SINT32 *t = data;
    SINT32 *u = data + n;
    SINT32 *v = data + 2 * n;

    get_vector_32(sc_gauss, t, n, 0);
    get_vector_32(sc_gauss, u, n, 0);

    sc_ntt->fwd_ntt_32_16(v, ntt, t, w);
    pipe_push(sc->bliss->pipe_producer_c, t, 3*n);

    refcount[2]++;

    return NULL;
}

#endif // HAVE_MULTITHREADING


SINT32 bliss_b_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    FLOAT sig;

    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 1, 2, 3, 0, 0, 0)) {
        return SC_FUNC_FAILURE;
    }
    sc->stats.param_set = set;

    // Precomputation for entropy coding
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_pub_key.entropy_coder    = NULL;
    sc->coding_priv_key.type            = SC_ENTROPY_NONE;
    sc->coding_priv_key.entropy_coder   = NULL;
    sc->coding_signature.type           =
        (flags[0] & SC_FLAG_0_ENTROPY_BAC)?            SC_ENTROPY_BAC :
        (flags[0] & SC_FLAG_0_ENTROPY_BAC_RLE)?        SC_ENTROPY_BAC_RLE :
        (flags[0] & SC_FLAG_0_ENTROPY_STRONGSWAN)?     SC_ENTROPY_STRONGSWAN :
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN_STATIC)? SC_ENTROPY_HUFFMAN_STATIC :
                                                       SC_ENTROPY_NONE;
    sc->coding_signature.entropy_coder  = NULL;
    sc->blinding =
        (flags[0] & SC_FLAG_0_SAMPLE_BLINDING)? BLINDING_SAMPLES :
                                                NORMAL_SAMPLES;
    sc->sampling_precision =
        ((flags[0] & SC_FLAG_0_SAMPLE_PREC_MASK) == SC_FLAG_0_SAMPLE_32BIT)?  SAMPLING_32BIT :
        ((flags[0] & SC_FLAG_0_SAMPLE_PREC_MASK) == SC_FLAG_0_SAMPLE_64BIT)?  SAMPLING_64BIT :
        ((flags[0] & SC_FLAG_0_SAMPLE_PREC_MASK) == SC_FLAG_0_SAMPLE_128BIT)? SAMPLING_128BIT :
        ((flags[0] & SC_FLAG_0_SAMPLE_PREC_MASK) == SC_FLAG_0_SAMPLE_192BIT)? SAMPLING_192BIT :
        ((flags[0] & SC_FLAG_0_SAMPLE_PREC_MASK) == SC_FLAG_0_SAMPLE_256BIT)? SAMPLING_256BIT :
                                                                              SAMPLING_64BIT;
    sc->sampling =
#ifdef HAVE_BAC_GAUSSIAN_SAMPLING
        (flags[0] & SC_FLAG_0_SAMPLE_BAC)?       BAC_GAUSSIAN_SAMPLING :
#endif
#ifdef HAVE_HUFFMAN_GAUSSIAN_SAMPLING
        (flags[0] & SC_FLAG_0_SAMPLE_HUFFMAN)?   HUFFMAN_GAUSSIAN_SAMPLING :
#endif
#ifdef HAVE_KNUTH_YAO_GAUSSIAN_SAMPLING
        (flags[0] & SC_FLAG_0_SAMPLE_KNUTH_YAO)? KNUTH_YAO_GAUSSIAN_SAMPLING :
#endif
#ifdef HAVE_CDF_GAUSSIAN_SAMPLING
        (flags[0] & SC_FLAG_0_SAMPLE_CDF)?       CDF_GAUSSIAN_SAMPLING :
#endif
#ifdef HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
        (flags[0] & SC_FLAG_0_SAMPLE_ZIGGURAT)?  ZIGGURAT_GAUSSIAN_SAMPLING :
#endif
#ifdef HAVE_BERNOULLI_GAUSSIAN_SAMPLING
        (flags[0] & SC_FLAG_0_SAMPLE_BERNOULLI)? BERNOULLI_GAUSSIAN_SAMPLING :
#endif
#ifdef HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
                                                 ZIGGURAT_GAUSSIAN_SAMPLING;
#else
                                                 CDF_GAUSSIAN_SAMPLING;
#endif

    // Allocate memory for BLISS configuration
    sc->bliss = SC_MALLOC(sizeof(bliss_cfg_t));
    if (NULL == sc->bliss) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified BLISS-B parameter set
    switch (set)
    {
        case 0:  sc->bliss->params = &param_bliss_b_0;
                 sc->bliss->entropy = sc->coding_signature.type;
                 break;
        case 1:  sc->bliss->params = &param_bliss_b_1;
                 sc->bliss->entropy = sc->coding_signature.type;
                 break;
        case 2:  sc->bliss->params = &param_bliss_b_2;
                 sc->bliss->entropy = sc->coding_signature.type;
                 break;
        case 3:  sc->bliss->params = &param_bliss_b_3;
                 sc->bliss->entropy =sc->coding_signature.type;
                 break;
        case 4:  sc->bliss->params = &param_bliss_b_4;
                 sc->bliss->entropy = sc->coding_signature.type;
                 break;
        default: SC_FREE(sc->bliss, sizeof(bliss_cfg_t));
                 return SC_FUNC_FAILURE;
    }

    // Obtain parameters for the selected parameter set
    UINT16 n = sc->bliss->params->n;
    UINT16 p = sc->bliss->params->p;
    UINT16 kappa = sc->bliss->params->kappa;

    // Initialise the reduction scheme
    sc->bliss->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_BARRETT)?   SC_NTT_BARRETT :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->bliss->ntt, n, sc->bliss->params->q);
    init_reduce(&sc->bliss->ntt_p, n, p);
    init_reduce(&sc->bliss->ntt_2q, n, 2 * sc->bliss->params->q);

    // Create pointers for the arithmetic functions used by BLISS
    sc->sc_ntt = utils_arith_ntt(sc->bliss->ntt_optimisation);
    sc->sc_poly = utils_arith_poly();
    sc->sc_vec = utils_arith_vectors();

    // Configure the hashing algorithm to be used for the BLISS-B oracle.
    // If none are defined the default hash defined by the parameter set is used.
    SINT32 hash_length = 0;
    switch (flags[0] & SC_FLAG_0_HASH_LENGTH_MASK)
    {
        case SC_FLAG_0_HASH_LENGTH_512: hash_length = 512; break;
        case SC_FLAG_0_HASH_LENGTH_384: hash_length = 384; break;
        case SC_FLAG_0_HASH_LENGTH_256: hash_length = 256; break;
        case SC_FLAG_0_HASH_LENGTH_224: hash_length = 224; break;
        default:;
    }
    switch (flags[0] & SC_FLAG_0_HASH_FUNCTION_MASK)
    {
        case SC_FLAG_0_HASH_BLAKE2:
        {
            sc->bliss->oracle_hash = (512 == hash_length)? SC_HASH_BLAKE2_512 :
                                     (384 == hash_length)? SC_HASH_BLAKE2_384 :
                                     (256 == hash_length)? SC_HASH_BLAKE2_256 :
                                                           SC_HASH_BLAKE2_224;
        } break;
        case SC_FLAG_0_HASH_SHA2:
        {
            sc->bliss->oracle_hash = (512 == hash_length)? SC_HASH_SHA2_512 :
                                     (384 == hash_length)? SC_HASH_SHA2_384 :
                                     (256 == hash_length)? SC_HASH_SHA2_256 :
                                                           SC_HASH_SHA2_224;
        } break;
        case SC_FLAG_0_HASH_SHA3:
        {
            sc->bliss->oracle_hash = (512 == hash_length)? SC_HASH_SHA3_512 :
                                     (384 == hash_length)? SC_HASH_SHA3_384 :
                                     (256 == hash_length)? SC_HASH_SHA3_256 :
                                                           SC_HASH_SHA3_224;
        } break;
        case SC_FLAG_0_HASH_WHIRLPOOL:
        {
            sc->bliss->oracle_hash = SC_HASH_WHIRLPOOL_512;
        } break;
        case SC_FLAG_0_HASH_FUNCTION_DEFAULT:
        default:
        {
            sc->bliss->oracle_hash = sc->bliss->params->oracle_hash;
        }
    }

    // Create the hash to be used by the random oracle
    sc->hash = utils_crypto_hash_create(sc->bliss->oracle_hash);
    if (NULL == sc->hash) {
        return SC_FUNC_FAILURE;
    }

    // Retrieve the Gaussian Sampler standard deviation
    sig = sc->bliss->params->sig;

    // Initialise the random distribution sampler
    sc->sc_gauss = create_sampler(sc->sampling,
        sc->sampling_precision, sc->blinding, n, SAMPLING_DISABLE_BOOTSTRAP,
        sc->prng_ctx[0], 13.42f, sig);
    if (NULL == sc->sc_gauss) {
        utils_crypto_hash_destroy(sc->hash);
        SC_FREE(sc->bliss, sizeof(bliss_cfg_t));
        return SC_FUNC_FAILURE;
    }

#ifdef HAVE_MULTITHREADING
    sc->bliss->sc_gauss_1 = create_sampler(sc->sampling,
        sc->sampling_precision, sc->blinding, n, SAMPLING_DISABLE_BOOTSTRAP,
        sc->prng_ctx[3], 13.42f, sig);
    if (NULL == sc->bliss->sc_gauss_1) {
        utils_crypto_hash_destroy(sc->hash);
        destroy_sampler(&sc->sc_gauss);
        SC_FREE(sc->bliss, sizeof(bliss_cfg_t));
        return SC_FUNC_FAILURE;
    }
#endif

#ifdef USE_RUNTIME_NTT_TABLES
    // Dynamically allocate memory for the necessary NTT tables
    SINT16 *temp = (SINT16*) SC_MALLOC(sizeof(SINT16) * 4 * n);
    sc->bliss->params->w     = temp;
    sc->bliss->params->w_rev = temp + n;
    sc->bliss->params->r     = temp + 2*n;
    sc->bliss->params->r_rev = temp + 3*n;
    roots_of_unity_s16(sc->bliss->params->w, sc->bliss->params->r,
        n, sc->bliss->params->q, 0);
#endif

    // Dynamically allocate memory for temporary storage
    sc->temp_size = (6 * n + kappa) * sizeof(SINT32);
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            utils_crypto_hash_destroy(sc->hash);
            destroy_sampler(&sc->sc_gauss);
#ifdef HAVE_MULTITHREADING
            destroy_sampler(&sc->bliss->sc_gauss_1);
#endif
            SC_FREE(sc->bliss, sizeof(bliss_cfg_t));
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT32) * 4 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

#ifdef HAVE_MULTITHREADING
    // Create a threadpool and messaging IPC
    refcount[0] = 0;
    refcount[1] = 0;
    refcount[2] = 0;
    sc->bliss->mt_enable = flags[0] & SC_FLAG_0_THREADING_MASK;
    sc->bliss->pool_keygen = threadpool_create(2, 2);
    sc->bliss->pool_sign   = threadpool_create(1, 2);
    if (sc->bliss->mt_enable & SC_FLAG_0_THREADING_KEYGEN) {
        sc->bliss->pipe_a = pipe_create(sizeof(SINT32), 2*n);
        sc->bliss->pipe_b = pipe_create(sizeof(SINT32), 2*n);
        sc->bliss->pipe_producer_a = pipe_producer_create(sc->bliss->pipe_a);
        sc->bliss->pipe_producer_b = pipe_producer_create(sc->bliss->pipe_b);
        sc->bliss->pipe_consumer_a = pipe_consumer_create(sc->bliss->pipe_a);
        sc->bliss->pipe_consumer_b = pipe_consumer_create(sc->bliss->pipe_b);

        threadpool_add(sc->bliss->pool_keygen, keygen_g_producer_worker, (void*)sc);
        threadpool_add(sc->bliss->pool_keygen, keygen_f_producer_worker, (void*)sc);
    }
    if (sc->bliss->mt_enable & SC_FLAG_0_THREADING_ENC_SIGN) {
        sc->bliss->pipe_c = pipe_create(sizeof(SINT32), 3*n);
        sc->bliss->pipe_producer_c = pipe_producer_create(sc->bliss->pipe_c);
        sc->bliss->pipe_consumer_c = pipe_consumer_create(sc->bliss->pipe_c);

        threadpool_add(sc->bliss->pool_sign, sign_1_worker, (void*)sc);
    }
#endif

    return SC_FUNC_SUCCESS;
}

SINT32 bliss_b_destroy(safecrypto_t *sc)
{
    UINT16 n, kappa;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->bliss->params->n;
    kappa = sc->bliss->params->kappa;

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->bliss->params->w, sizeof(SINT16) * 4 * n);
#endif

    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

    // Free resources associated with the Gaussian sampler
    destroy_sampler(&sc->sc_gauss);

    // Free all resources associated with key-pair and signature
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, BLISS_NUM_PRIV_RING_POLY * n * sizeof(SINT16));
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, BLISS_NUM_PUB_RING_POLY * n * sizeof(SINT16));
        sc->pubkey->len = 0;
    }

#ifdef HAVE_MULTITHREADING
    destroy_sampler(&sc->bliss->sc_gauss_1);

    threadpool_destroy(sc->bliss->pool_keygen, THREADPOOL_GRACEFUL_EXIT);
    threadpool_destroy(sc->bliss->pool_sign, THREADPOOL_GRACEFUL_EXIT);

    if (sc->bliss->mt_enable & SC_FLAG_0_THREADING_KEYGEN) {
        pipe_destroy(sc->bliss->pipe_a);
        pipe_destroy(sc->bliss->pipe_b);
        pipe_producer_destroy(sc->bliss->pipe_producer_a);
        pipe_producer_destroy(sc->bliss->pipe_producer_b);
        pipe_consumer_destroy(sc->bliss->pipe_consumer_a);
        pipe_consumer_destroy(sc->bliss->pipe_consumer_b);
    }
    if (sc->bliss->mt_enable & SC_FLAG_0_THREADING_ENC_SIGN) {
        pipe_destroy(sc->bliss->pipe_c);
        pipe_producer_destroy(sc->bliss->pipe_producer_c);
        pipe_consumer_destroy(sc->bliss->pipe_consumer_c);
    }
#endif

    if (sc->bliss) {
        utils_crypto_hash_destroy(sc->hash);
        SC_FREE(sc->bliss, sizeof(bliss_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "BLISS-B algorithm destroyed");

    return SC_FUNC_SUCCESS;
}

#ifndef DISABLE_SIGNATURES_SERVER

static SINT32 keygen_params(safecrypto_t *sc, UINT16 *n, UINT16 *n_bits, UINT16 *q,
    const UINT16 **nz, const SINT16 **w, const SINT16 **w_inv, const SINT16 **r)
{
    *n = sc->bliss->params->n;
    *n_bits = sc->bliss->params->n_bits;
    *q = sc->bliss->params->q;
    *nz = sc->bliss->params->nz;
    *w = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->w_rev : sc->bliss->params->w;
    *w_inv = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->w_inv : sc->bliss->params->w;
    *r = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->r_inv : sc->bliss->params->r;

    return SC_FUNC_SUCCESS;
}

#endif

static SINT32 signature_params(safecrypto_t *sc, UINT16 *n, UINT16 *n_bits, UINT16 *q,
    UINT16 *p, UINT16 *d, UINT16 *kappa, FLOAT *sig, FLOAT *m, UINT16 *entropy,
    UINT16 *z1_bits, UINT16 *z2_bits,
    const SINT16 **w, const SINT16 **w_inv, const SINT16 **r)
{
    *n = sc->bliss->params->n;
    *n_bits = sc->bliss->params->n_bits;
    *q = sc->bliss->params->q;
    *p = sc->bliss->params->p;
    *d = sc->bliss->params->d;
    *kappa = sc->bliss->params->kappa;
    *sig = sc->bliss->params->sig;
    *m = sc->bliss->params->m;
    *entropy = sc->bliss->entropy;
    *z1_bits = sc->bliss->params->z1_bits;
    *z2_bits = sc->bliss->params->z2_bits;
    *w = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->w_rev : sc->bliss->params->w;
    *w_inv = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->w_inv : sc->bliss->params->w;
    *r = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->r_inv : sc->bliss->params->r;

    return SC_FUNC_SUCCESS;
}

#ifndef DISABLE_SIGNATURES_CLIENT

static SINT32 verification_params(safecrypto_t *sc, UINT16 *b_inf, UINT32 *b_l2)
{
    *b_inf = sc->bliss->params->b_inf;
    *b_l2 = sc->bliss->params->b_l2;

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_CLIENT

static SINT32 oracle(safecrypto_t *sc, SINT32 *c_idx, UINT16 kappa,
    const void *m, size_t m_len,
    const SINT16 *w, UINT16 n, UINT16 mask)
{
    size_t i;
    SINT32 idx, r, idx_i;
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    UINT8 md[64], t[64], *fl;
#else
    UINT8 md[64], t[2], *fl;
#endif

    if (NULL == sc || NULL == c_idx || NULL == m || NULL == w) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (0 == m_len || 0 == n) {
        SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS);
        return SC_FUNC_FAILURE;
    }

    idx_i = 0;
    fl = (UINT8 *)(sc->temp + 4 * n); // NOTE: This memory is re-used

    // All fl elements must be reset to 0
    SC_MEMZERO(fl, n);

    for (r = 0; r < 65536; r++) {

        hash_init(sc->hash);
        hash_update(sc->hash, m, m_len);

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
        size_t j;
        for (i = 0; i < n; i+=32) {
            for (j = 0; j < 32; j++) {
                t[2*j  ] = w[i+j] >> 8;
                t[2*j+1] = w[i+j] & 0xFF;
            }
            hash_update(sc->hash, t, 64);
        }
#else
        SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "hash w", (UINT8*)w, 2*n);
        hash_update(sc->hash, (UINT8*) w, 2*n);
#endif

        t[0] = r >> 8;
        t[1] = r & 0xFF;
        hash_update(sc->hash, t, 2);
        hash_final(sc->hash, md);

        SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "oracle() md", md, 64);

        for (i = 0; i < sc->hash->length; i += 2) {
            idx = ((((UINT16) md[i]) << 8) + ((UINT16) md[i + 1])) & mask;
            if (0 == fl[idx]) {
                c_idx[idx_i++] = idx;
                if (idx_i == kappa) {
                    return SC_FUNC_SUCCESS;
                }
                fl[idx] = 1;
            }
        }
    }

    SC_LOG_ERROR(sc, SC_ERROR);
    return SC_FUNC_FAILURE;
}

static SINT32 greedy_sc(safecrypto_t *sc, const SINT16 *f, const SINT16 *g, SINT32 n,
    const SINT32 *c_idx, SINT32 kappa, SINT32 *x, SINT32 *y)
{
    SINT32 j, k;

    if (NULL == f || NULL == g || NULL == c_idx || NULL == x || NULL == y) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (kappa <= 0 || n <= 0) {
        SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS);
        return SC_FUNC_FAILURE;
    }

    // This loop can be automatically vectorised
    for (j = 0; j < n; j++) {
        x[j] = 0;
        y[j] = 0;
    }

    // All inner loops can be automatically vectorised
    for (k = 0; k < kappa; k++) {

        SINT32 i = c_idx[k];
        SINT32 sgn = 0;

        for (j=0; j<n-i; j++) {
            sgn += f[j] * x[i + j] + g[j] * y[i + j];
        }
        for (j=n-i; j<n; j++) {
            sgn -= f[j] * x[i + j - n] + g[j] * y[i + j - n];
        }

        if (sgn > 0) {
            for (j=0; j<n-i; j++) {
                x[i + j] -= f[j];
                y[i + j] -= g[j];
            }
            for (j=n-i; j<n; j++) {
                x[i + j - n] += f[j];
                y[i + j - n] += g[j];
            }
        }
        else {
            for (j=0; j<n-i; j++) {
                x[i + j] += f[j];
                y[i + j] += g[j];
            }
            for (j=n-i; j<n; j++) {
                x[i + j - n] -= f[j];
                y[i + j - n] -= g[j];
            }
        }
    }

    return SC_FUNC_SUCCESS;
}

static void round_and_drop(SINT32 *u, SINT32 *v, SINT16 *z,
    UINT16 d, UINT16 q, ntt_params_t *ntt_2q, ntt_params_t *ntt_p)
{
    SINT32 i;
    SINT32 two_pow_dm1 = 1 << (d - 1);
    UINT16 n     = ntt_2q->n;
    UINT16 p     = ntt_p->u.ntt32.q;

    SINT32 k_2q  = ntt_2q->u.ntt32.k;
    SINT32 m_2q  = ntt_2q->u.ntt32.m;
    SINT32 k_p   = ntt_p->u.ntt32.k;
    SINT32 m_p   = ntt_p->u.ntt32.m;
    SINT32 two_q = 2 * q;

    for (i=n; i--;) {
        SINT32 tmp = v[i];
        tmp += (tmp & 1) * q;      // If odd add the modulo operator
        BARRETT_REDUCTION(tmp, tmp + u[i], k_2q, m_2q, two_q);
        tmp += (tmp < 0) * two_q;  // Ensure the value is positive
        v[i] = tmp;
        BARRETT_REDUCTION(z[i], (tmp + two_pow_dm1) >> d, k_p, m_p, p);
    }
}

SINT32 bliss_b_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->bliss->params->n;
    q_bits = sc->bliss->params->q_bits;

    // BLISS is unusual as it requires the public key for both sign and verify
    // operations, therefore our implementation maintains two public keys - one is
    // used for verification only and is overwritten by this function.
    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(BLISS_NUM_PUB_RING_POLY * n * sizeof(SINT16));
        if (NULL == sc->pubkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    sc->coding_pub_key.type = SC_ENTROPY_NONE;

    // Create a bit packer to extract the public key from the buffer
    SINT16 *pubkey = ((SINT16 *) sc->pubkey->key) + n;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, key, key_len, NULL, 0);
#if !defined(BLISS_ENABLE_NTT_TRANSMISSION) || defined(BLISS_USE_SPARSE_MULTIPLIER)
    {
        const SINT16 *w = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->w_rev : sc->bliss->params->w;
        const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
        ntt_params_t *ntt = &sc->bliss->ntt;
        SINT32 *t = sc->temp;
        size_t i;

        entropy_poly_decode_32(packer, n, t, q_bits,
            UNSIGNED_COEFF, sc->coding_pub_key.type);

        // Convert to the NTT domain
        sc_ntt->fwd_ntt_32_16(t, ntt, t, w);
        sc_ntt->normalize_32(t, n, ntt);
        for (i=0; i<n; i++) {
            pubkey[i] = t[i];
        }
        SC_MEMZERO(t, n * sizeof(SINT32));
    }
#else
    entropy_poly_decode_16(packer, n, pubkey, q_bits,
        UNSIGNED_COEFF, sc->coding_pub_key.type);
#endif
    utils_entropy.pack_destroy(&packer);
    sc->pubkey->len = n;

    return SC_FUNC_SUCCESS;
}

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 bliss_b_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 bliss_b_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, nz2;
    SINT32 *f, *g;
    const SINT16 *w;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->bliss->ntt;

    n = sc->bliss->params->n;
    nz2 = sc->bliss->params->nz[0];

    f = sc->temp;
    if (NULL == f) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    g = f + n;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 2 * n * sizeof(SINT16));
    }
    sc->privkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
    if (NULL == sc->privkey->key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Extract the parameter set ID
    SINT32 s_bits;

    if (nz2 > 0) {
        s_bits = 3;
    }
    else {
        s_bits = 2;
    }

    // Create a bit packer to extract the private key polynomials f and g from the buffer
    SINT16 *privkey = (SINT16 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        2 * n * s_bits, key, key_len, NULL, 0);
    entropy_poly_decode_16(packer, n, privkey, s_bits,
        SIGNED_COEFF, sc->coding_priv_key.type);
    entropy_poly_decode_16(packer, n, privkey + n, s_bits,
        SIGNED_COEFF, sc->coding_priv_key.type);
    for (i=0; i<(size_t)n; i++) {
        privkey[n+i] <<= 1;
    }
    privkey[n]++;
    utils_entropy.pack_destroy(&packer);

    sc->privkey->len = 2 * n;

    // Now create a public key for use with signatures ...
    for (i=n; i--;) {
        f[i] = privkey[i];
        g[i] = privkey[i + n];
    }

    w = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->w_rev : sc->bliss->params->w;

    // Obtain NTT(g) and NTT(f)
    sc_ntt->fwd_ntt_32_16(g, ntt, g, w);
    sc_ntt->fwd_ntt_32_16(f, ntt, f, w);

    // Attempt to invert NTT(f)
    if (SC_FUNC_FAILURE == sc_ntt->invert_32(f, ntt, n)) {
        SC_LOG_ERROR(sc, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // a = (2g+1)/f and f is invertible, so calculate ...
    sc_ntt->mul_32_pointwise(g, ntt, g, f);

    // Normalize a
    sc_ntt->normalize_32(g, n, ntt);

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(BLISS_NUM_PUB_RING_POLY * n * sizeof(SINT16));
        if (NULL == sc->pubkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    SINT16 *pubkey = (SINT16 *) sc->pubkey->key;
    for (i=n; i--;) {
        pubkey[i] = g[i];
    }

    SC_MEMZERO(f, 2 * n * sizeof(SINT16));

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_CLIENT

#ifdef DISABLE_SIGNATURES_SERVER

SINT32 bliss_b_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 bliss_b_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 bliss_b_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->bliss->params->n;
    q_bits = sc->bliss->params->q_bits;

    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += n * q_bits;

    sc->coding_pub_key.type = SC_ENTROPY_NONE;

    // Create a bit packer to compress the public key
    SINT16 *pubkey = (SINT16 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
#if !defined(BLISS_ENABLE_NTT_TRANSMISSION) || defined(BLISS_USE_SPARSE_MULTIPLIER)
    {
        size_t i;
        SINT32 *t;
        const SINT16 *w_inv = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->w_inv : sc->bliss->params->w;
        const SINT16 *r     = (sc->bliss->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->bliss->params->r_inv : sc->bliss->params->r;
        const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
        ntt_params_t *ntt = &sc->bliss->ntt;

        // Convert from the NTT domain
        t = sc->temp;
        for (i=0; i<n; i++) {
            t[i] = pubkey[i];
        }
        sc_ntt->inv_ntt_32_16(t, ntt, t, w_inv, r);
        sc_ntt->normalize_32(t, n, ntt);
        entropy_poly_encode_32(packer, n, t, q_bits,
            UNSIGNED_COEFF, sc->coding_pub_key.type,
            &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);
        SC_MEMZERO(t, n * sizeof(SINT32));
    }
#else
    entropy_poly_encode_16(packer, n, pubkey, q_bits,
        UNSIGNED_COEFF, sc->coding_pub_key.type,
        &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);
#endif

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

SINT32 bliss_b_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT16 n, nz2;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n = sc->bliss->params->n;
    nz2 = sc->bliss->params->nz[0];

    // Determine the number of bits in each symbol
    SINT32 s_bits = (nz2 > 0)? 3 : 2;

    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += n * s_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][1].bits += n * s_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][2].bits += 2 * n * s_bits;

    // Create a bit packer to compress the private key polynomials f and g
    SINT16 *privkey = (SINT16 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        2 * n * s_bits, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_16(packer, n, privkey, s_bits,
        SIGNED_COEFF, sc->coding_priv_key.type,
        &sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);
    sc->temp[0]--;
    for (i=0; i<n; i++) {
        sc->temp[i] = privkey[n+i] >> 1;
    }
    entropy_poly_encode_32(packer, n, sc->temp, s_bits,
        SIGNED_COEFF, sc->coding_priv_key.type,
        &sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded);

    // Extract the buffer with the polynomial g and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded += *key_len * 8;

    SC_MEMZERO(sc->temp, n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_SERVER

static SINT32 check_norms(safecrypto_t *sc, SINT32 *t, SINT16 *z, UINT16 n, UINT16 d)
{
    const utils_arith_vec_t *sc_vec = utils_arith_vectors();

    SINT32 b_inf = sc->bliss->params->b_inf;
    SINT32 b_l2 = sc->bliss->params->b_l2;
    SINT32 max;

    SC_PRINT_DEBUG(sc, "Check norms\n");

    // Compute norms
    max = sc_vec->absmax_32(t, n);
    SC_PRINT_DEBUG(sc, "Absolute max of vector t[%d] > b_inf[%d]\n",
        max, b_inf);
    if (max > b_inf) {
        return SC_FUNC_FAILURE;
    }

    max = sc_vec->absmax_16(z, n);
    SC_PRINT_DEBUG(sc, "Absolute max of vector z = [%d (%d << %d)] > b_inf[%d]\n",
        max << d, max, d, b_inf);
    if ((max << d) > b_inf) {
        return SC_FUNC_FAILURE;
    }

    SINT32 norm_t = sc_vec->scalar_32(t, t, n);
    SINT32 norm_z = sc_vec->scalar_16(z, z, n);
    SC_PRINT_DEBUG(sc, "norm(t)[%d] + (norm(z)[%d] << 2d[%d]) > b_l2[%d]\n", norm_t, norm_z, 2*d, b_l2);
    if (norm_t + (norm_z << (2 * d)) > b_l2) {
        return SC_FUNC_FAILURE;
    }

    return SC_FUNC_SUCCESS;
}

static void signature_gen(SINT32 *u, SINT32 *v, SINT16 *z,
    UINT16 q, UINT16 d, UINT16 p, UINT16 n)
{
    size_t i;
    SINT32 tmp;
    SINT32 k = 30;
    SINT32 m = (1 << k) / q;
    SINT32 q2 = 2 * q;
    SINT32 p2 = p >> 1;

    // z[i] = (z[i] - (v[i] - u[i])) mod p
    // i.e. z2 <- (ud - (u - z2)d) mod p
    for (i=n; i--;) {
        tmp = v[i] - u[i];

        // Normalize
        tmp += (tmp < 0) * q2;
        tmp -= (tmp >= q2) * q2;

        // Barrett reduction used to perform the modulo p operation
        tmp = ((tmp + (1 << (d - 1))) >> d); // uz
        tmp = tmp - ((tmp * m) >> k) * p;
        tmp -= (p <= tmp) * p;

        // Normalize in range
        tmp = z[i] - tmp;
        tmp += (tmp <= -p2) * p;
        tmp -= (tmp > p2) * p;
        z[i] = tmp;
    }
}


#ifdef DISABLE_SIGNATURES_SERVER

SINT32 bliss_b_keygen(safecrypto_t *sc)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 bliss_b_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 bliss_b_keygen(safecrypto_t *sc)
{
    SINT32 i, iter;
    SINT32 *t, *u;
    SINT32 *f, *g, *a;
    UINT16 n, n_bits, q;
    const UINT16 *nz;
    const SINT16 *w, *w_inv, *r;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "BLISS-B KeyGen\n");

    // Obtain all of the parameters required for key pair generation
    keygen_params(sc, &n, &n_bits, &q, &nz, &w, &w_inv, &r);

    // Allocate temporary memory
    t = sc->temp;
    if (NULL == t) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    u = t + n;
    f = t + 2 * n;
    g = t + 3 * n;
    a = t + 4 * n;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->bliss->ntt;

    sc->stats.keygen_num++;
#ifdef HAVE_MULTITHREADING
    if (sc->bliss->mt_enable & SC_FLAG_0_THREADING_KEYGEN) {
        pipe_pull(sc->bliss->pipe_consumer_a, g, n);
        pipe_pull(sc->bliss->pipe_consumer_a, t, n);
        pipe_pull(sc->bliss->pipe_consumer_b, f, n);
        pipe_pull(sc->bliss->pipe_consumer_b, u, n);
        refcount[0]--;
        refcount[1]--;
        threadpool_add(sc->bliss->pool_keygen, keygen_g_producer_worker, (void*)sc);
        threadpool_add(sc->bliss->pool_keygen, keygen_f_producer_worker, (void*)sc);
    }
    else
#endif
    {
        // Generate a random private-key polynomial g
        sc_poly->uniform_32(sc->prng_ctx[0], g, n, nz, 2);
        sc_poly->mul_32_scalar(g, n, 2);
        sc_poly->add_32_scalar(g, n, 1);
        sc_ntt->fwd_ntt_32_16(t, ntt, g, w);
        sc_ntt->normalize_32(t, n, ntt);

        // Trial to find an invertible f
        iter = 0;

restart:
        iter++;

        // Generate a random polynomial f
        sc_poly->uniform_32(sc->prng_ctx[0], f, n, nz, 2);

        // Obtain NTT(f)
        sc_ntt->fwd_ntt_32_16(u, ntt, f, w);

        // Attempt to invert NTT(f)
        if (SC_FUNC_FAILURE == sc_ntt->invert_32(u, ntt, n)) {
            goto restart;
        }

        SC_PRINT_DEBUG(sc, "Inversion after %d attempts\n", iter);
        sc->stats.keygen_num_trials++;
    }

    // a = (2g+1)/f and f is invertible, so calculate ...
    sc_ntt->mul_32_pointwise(a, ntt, t, u);

    // Normalize a
    sc_ntt->normalize_32(a, n, ntt);

    SC_PRINT_DEBUG(sc, "Memory allocation for keys\n");

    // Allocate key pair memory
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(BLISS_NUM_PUB_RING_POLY * n * sizeof(SINT16));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, BLISS_NUM_PRIV_RING_POLY * n * sizeof(SINT16));
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    // Store the key pair in the SAFEcrypto structure for future use
    SINT16 *key = (SINT16*) sc->privkey->key;
    for (i=BLISS_NUM_PRIV_RING_POLY*n; i--;) {
        key[i] = f[i]; // NOTE: f and g are contiguous
    }
    key = (SINT16*) sc->pubkey->key;
#ifdef BLISS_USE_SPARSE_MULTIPLIER
    for (i=n; i--;) {
        key[i] = a[i];
    }
    sc_ntt->inv_ntt_32_16(a, ntt, a, w_inv, r);
    for (i=n; i--;) {
        key[n+i] = a[i];
    }
#else
    for (i=n; i--;) {
        key[i] = a[i];
        key[n+i] = a[i];
    }
#endif
    sc->privkey->len = 2 * n;
    sc->pubkey->len = n;

    SC_PRINT_DEBUG(sc, "Print keys\n");
    SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 16);

    // Clear the temporary memory used for generation
    SC_MEMZERO(t, 5 * n * sizeof(SINT32));
    return SC_FUNC_SUCCESS;

finish_free:
    SC_MEMZERO(t, 5 * n * sizeof(SINT32));
    return SC_FUNC_FAILURE;
}

SINT32 bliss_b_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
    SINT32 i, iter;
    SINT32 *t, *u, *v, *x, *y;
    SINT16 *a, *f, *g, *z;
    UINT16 n, n_bits, q, p, d, kappa, entropy, z1_bits, z2_bits;
    FLOAT sig, reject_m;
    const SINT16 *w, *w_inv, *r;
    SINT32 *c_idx = NULL;
    DOUBLE thresh_d, inv_sig2, reject_r;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_ERROR(sc, "Initialising BLISS-B signature variables\n");

    // Obtain all of the parameters required for key pair generation
    signature_params(sc, &n, &n_bits, &q, &p, &d, &kappa, &sig, &reject_m,
        &entropy, &z1_bits, &z2_bits, &w, &w_inv, &r);

    inv_sig2 = 1.0 / ((DOUBLE) sig * sig);

    // Generate a mask for modulo n operations
    SINT32 mask = (1 << n_bits) - 1;

    // Ensure that the entropy coders are initialized
    sc->coding_signature.type = (sc_entropy_type_e) entropy;

    // Allocate temporary memory
    t = sc->temp;
    if (NULL == t) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    u = t + n;
    v = t + 2 * n;
    x = t + 3 * n;
    y = t + 4 * n; // NOTE: Also used for oracle intermediate array
    c_idx = t + 5 * n;
#if 1
    z = (SINT16 *)PTR_ALIGN((SINT16 *)(c_idx + kappa), 16, 4);
#else
    z = (SINT16 *) (c_idx + kappa);
#endif
    a = (SINT16 *) sc->pubkey->key;
    f = (SINT16 *) sc->privkey->key;
    g = (SINT16 *) (sc->privkey->key + n * sizeof(SINT16));

    // Check for an uninitialised key pair
    if (NULL == a || NULL == f || NULL == g) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_vec_t *sc_vec = sc->sc_vec;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    utils_sampling_t* sc_gauss = sc->sc_gauss;
    ntt_params_t *ntt    = &sc->bliss->ntt;
    ntt_params_t *ntt_p  = &sc->bliss->ntt_p;
    ntt_params_t *ntt_2q = &sc->bliss->ntt_2q;

    SC_PRINT_DEBUG(sc, "Invertible f trial\n");

    // Trial to find small random polynomials within security bounds
    for (iter=0; iter<99999; iter++) {

        // Increase the number of attempted signature generations
        sc->stats.sig_num_trials++;

        SC_PRINT_DEBUG(sc, "Gaussian sampling ...\n");

#ifdef HAVE_MULTITHREADING
        if (sc->bliss->mt_enable & SC_FLAG_0_THREADING_ENC_SIGN) {
            refcount[2]--;
            threadpool_add(sc->bliss->pool_sign, sign_1_worker, (void*)sc);
            //pipe_pull(sc->bliss->pipe_consumer_c, t, 3*n);
            pipe_pull(sc->bliss->pipe_consumer_c, t, n);
            pipe_pull(sc->bliss->pipe_consumer_c, u, n);
            pipe_pull(sc->bliss->pipe_consumer_c, v, n);
            //pipe_pull(sc->bliss->pipe_consumer_c, z, n);
        }
        else
#endif
        {
            // Generate polynomials with a specified distribution
            // Every other attempt we simply swap the two polynomials for a
            // 20% performance improvement.
            if (iter & 0x1) {
                SINT32 *temp = t;
                t = u;
                u = temp;
            }
            else {
                get_vector_32(sc_gauss, t, n, 0);
                get_vector_32(sc_gauss, u, n, 0);
            }
            SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t", t, n);
            SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "u", u, n);

            sc_ntt->fwd_ntt_32_16(v, ntt, t, w);
        }

        SC_PRINT_DEBUG(sc, "At: v = t * a\n");
        //sc_ntt->fwd_ntt_32_16(v, ntt, t, w);
        sc_ntt->mul_32_pointwise_16(v, ntt, v, a);
        sc_ntt->inv_ntt_32_16(v, ntt, v, w_inv, r);

        // Round and drop, i.e. At + u mod 2q
        SC_PRINT_DEBUG(sc, "Round and drop\n");
        round_and_drop(u, v, z, d, q, ntt_2q, ntt_p);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v", v, n);
        SC_PRINT_1D_INT16(sc, SC_LEVEL_DEBUG, "z", z, n);

        // Create the c index set
        SC_PRINT_DEBUG(sc, "Oracle and Greedy SC\n");
        SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, m_len);
        if (SC_FUNC_FAILURE == oracle(sc, c_idx, kappa, m, m_len, z, n, mask)) {
            continue;
        }
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "c_idx", c_idx, kappa);
        if (SC_FUNC_FAILURE == greedy_sc(sc, f, g, n, c_idx, kappa, x, y)) {
            continue;
        }
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "x", x, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "y", y, n);

        // Add or subtract
        SC_PRINT_DEBUG(sc, "Add or subtract\n");
        if (prng_bit(sc->prng_ctx[0])) {
            sc_poly->sub_single_32(t, n, x);   // i.e. z1
            sc_poly->sub_single_32(u, n, y);   // i.e. z2
        } else {
            sc_poly->add_single_32(t, n, x);   // i.e. z1
            sc_poly->add_single_32(u, n, y);   // i.e. z2
        }

        // Rejection arithmetic
        SINT32 scalar_num = sc_vec->scalar_32(x, x, n) + sc_vec->scalar_32(y, y, n);
        SINT32 scalar_den = sc_vec->scalar_32(t, x, n) + sc_vec->scalar_32(u, y, n);
        SC_PRINT_DEBUG(sc, "scalar_num = %d\n", scalar_num);
        SC_PRINT_DEBUG(sc, "scalar_den = %d\n", scalar_den);
        thresh_d = 1.0 / (reject_m  *
            exp(-0.5 * inv_sig2 * scalar_num) * cosh(inv_sig2 * scalar_den));

        // A random variable (0 < reject_r < 1) must be greater than thresh_d
        // to retry signature generation
        reject_r = prng_double(sc->prng_ctx[0]);
        SC_PRINT_DEBUG(sc, "Rejection: %3.6f > %3.6f\n", reject_r, thresh_d);
        if (reject_r > thresh_d)
            continue;

        SC_PRINT_DEBUG(sc, "Signature generation\n");
        SC_PRINT_1D_INT16(sc, SC_LEVEL_DEBUG, "z", z, n);

        // Generate signature as z2 <- (ud - (u-z2)d) mod p
        signature_gen(u, v, z, q, d, p, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t", t, n);
        SC_PRINT_1D_INT16(sc, SC_LEVEL_DEBUG, "z", z, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Oracle", c_idx, kappa);

        // Compute and check norms
        if (SC_FUNC_FAILURE == check_norms(sc, t, z, n, d)) {
            continue;
        }

        // Create a bit packer to compress the signature polynomials
        SC_PRINT_DEBUG(sc, "Signature compression\n");
        sc_packer_t *packer;
        packer = utils_entropy.pack_create(sc, &sc->coding_signature,
            n * (z1_bits + z2_bits) + kappa * n_bits, NULL, 0, sigret, siglen);
        if (NULL == packer) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            break;
        }
        entropy_poly_encode_32(packer, n, t, z1_bits,
            SIGNED_COEFF, sc->coding_signature.type,
            &sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded);
        entropy_poly_encode_16(packer, n, z, z2_bits,
            SIGNED_COEFF, sc->coding_signature.type,
            &sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded);
        for (i=0; i<kappa; i++) {
            utils_entropy.pack_encode(packer, c_idx[i], n_bits);
        }
        utils_entropy.pack_get_buffer(packer, sigret, siglen);
        utils_entropy.pack_destroy(&packer);

        sc->stats.sig_num++;
        sc->stats.components[SC_STAT_SIGNATURE][0].bits += n * z1_bits;
        sc->stats.components[SC_STAT_SIGNATURE][1].bits += n * z2_bits;
        sc->stats.components[SC_STAT_SIGNATURE][2].bits += kappa * n_bits;
        sc->stats.components[SC_STAT_SIGNATURE][3].bits += n * (z1_bits + z2_bits) + kappa * n_bits;
        sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded += kappa * n_bits;
        sc->stats.components[SC_STAT_SIGNATURE][3].bits_coded += *siglen * 8;

        SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Compressed signature", *sigret, *siglen);

        SC_MEMZERO(sc->temp, ( 6 * n + kappa ) * sizeof(SINT32));
        return SC_FUNC_SUCCESS;
    }

    if (0 == *siglen) {
        SC_FREE(*sigret, (2 * n + kappa) * sizeof(SINT32));
    }
    SC_MEMZERO(sc->temp, ( 6 * n + kappa ) * sizeof(SINT32));
    return SC_FUNC_FAILURE;
}

#endif // DISABLE_SIGNATURES_SERVER

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 bliss_b_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

#ifdef BLISS_USE_SPARSE_MULTIPLIER
static void sparse_mul_mod_ring(SINT32 *r, const SINT16 *a, const SINT32 *b_sparse, size_t n, ntt_params_t *ntt)
{
    size_t j, k;
    SINT32 sparse[2*n] SC_DEFAULT_ALIGNED;

    // Reset the output to zero
    for (j=2*n; j--;) {
        sparse[j] = 0;
    }

    // Accumulate the a coefficients with the sparse b coefficient with the
    // knowledge that they only have the values -1, 0 or 1.
    for (j=0, p=0; j<n; j++) {
        for (k=0; k<n; k++) {
            sparse[j+k] += a[k] * b_sparse[j];
        }
    }

    for (k=0; k<2*n-1; k++) {
        BARRETT_REDUCTION(sparse[k], sparse[k], ntt->u.ntt32.k,
            ntt->u.ntt32.m, ntt->u.ntt32.q);
    }

    // Perform the ring modular reduction
    for (j=n; j--;) {
        r[j] = sparse[j] - sparse[j + n];
        if (r[j] >= ntt->u.ntt32.q) r[j] -= ntt->u.ntt32.q;
        if (r[j] < 0) r[j] += ntt->u.ntt32.q;
    }
}
#endif

SINT32 bliss_b_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
    SINT32 i;
    SINT32 *t, *v;
    SINT16 *a, *z;
    UINT16 n, n_bits, q, p, d, kappa, b_inf, entropy, z1_bits, z2_bits;
    FLOAT sig, reject_m;
    const SINT16 *w, *w_inv, *r;
    UINT32 b_l2;
    SINT32 *c_idx = NULL;
    SINT32 *my_idx;
    SINT32 two_pow_dm1;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Initialising BLISS-B verification variables\n");

    // Obtain all of the parameters required for key pair generation
    signature_params(sc, &n, &n_bits, &q, &p, &d, &kappa, &sig, &reject_m,
        &entropy, &z1_bits, &z2_bits, &w, &w_inv, &r);
    verification_params(sc, &b_inf, &b_l2);

    // Generate a mask for modulo n operations
    SINT32 mask = (1 << n_bits) - 1;

    // Ensure that the entropy coders are initialized
    sc->coding_signature.type = (sc_entropy_type_e) entropy;

    // Precompute the rounding factor for z
    two_pow_dm1 = 1 << (d - 1);

    // Allocate temporary memory
    // NOTE: t + 4*n is also used for an oracle intermediate array
    t = sc->temp;
    if (NULL == t) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    v = t + n;
    my_idx = v + n;
    c_idx = my_idx + kappa;
    z = (SINT16 *)PTR_ALIGN((SINT16 *)(c_idx + kappa), 16, 4);//(SINT16 *)(c_idx + 2*kappa);
    a = ((SINT16 *) sc->pubkey->key) + n;

    // Check for an uninitialised public key
    if (NULL == a) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Compressed signature",
        sigbuf, siglen);

    // Decompress the signature
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_signature,
        n * (z1_bits + z2_bits) + kappa * n_bits, sigbuf, siglen, NULL, 0);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        goto verification_early_failure;
    }
    entropy_poly_decode_32(packer, n, t, z1_bits,
        SIGNED_COEFF, sc->coding_signature.type);
    entropy_poly_decode_16(packer, n, z, z2_bits,
        SIGNED_COEFF, sc->coding_signature.type);
    for (i=0; i<kappa; i++) {
        if (SC_FUNC_FAILURE == utils_entropy.pack_decode(packer, (UINT32*)&c_idx[i], n_bits)) {
            SC_PRINT_ERROR(sc, "BLISS signature decode error 2\n");
            SC_LOG_ERROR(sc, SC_ERROR);
            goto verification_early_failure;
        }
    }
    utils_entropy.pack_destroy(&packer);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received t", t, n);
    SC_PRINT_1D_INT16(sc, SC_LEVEL_DEBUG, "Received z", z, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received Oracle", c_idx, kappa);

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt    = &sc->bliss->ntt;
    ntt_params_t *ntt_2q = &sc->bliss->ntt_2q;

    // Compute norms
    if (SC_FUNC_FAILURE == check_norms(sc, t, z, n, d)) {
        SC_LOG_ERROR(sc, SC_ERROR);
        goto verification_early_failure;
    }

    SC_PRINT_DEBUG(sc, "  Calculate v = t * a (mod x^n + 1)\n");
#ifdef BLISS_USE_SPARSE_MULTIPLIER
    SINT32 tpk[512];
    /*for (i=0; i<n; i++) {
        tpk[i] = ((SINT16 *) sc->pubkey->key + n)[i];
    }
    sc_ntt->inv_ntt_32_16(tpk, ntt, tpk, w, r);*/
    //sc_ntt->center_32(tpk, n, ntt);
    /*fprintf(stderr, "t = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", t[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "h = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", tpk[i]);
    }
    fprintf(stderr, "\n");*/
    sparse_mul_mod_ring(v, a, t, n, ntt);
    //sc_ntt->center_32(v, n, ntt);
    /*fprintf(stderr, "v = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", v[i]);
    }
    fprintf(stderr, "\n");*/
#else
    sc_ntt->fwd_ntt_32_16(v, ntt, t, w);
    sc_ntt->mul_32_pointwise_16(v, ntt, v, a);
    sc_ntt->inv_ntt_32_16(v, ntt, v, w_inv, r);
#endif
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v", v, n);

    SC_PRINT_DEBUG(sc, "Verification\n");

    // if v[i] is odd then increment it by q, automatically vectorisable
    for (i=n; i--;) {
        v[i] += (v[i] & 1) * q;
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v", v, n);

    // v = v + C * q
    for (i = 0; i < kappa; i++) {
        BARRETT_REDUCTION(v[c_idx[i]], v[c_idx[i]] + q, ntt_2q->u.ntt32.k,
            ntt_2q->u.ntt32.m, ntt_2q->u.ntt32.q);
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v", v, n);

    // Drop bits and add z
    for (i=n; i--;) {
        SINT32 tmp;
        tmp  = ((v[i] + two_pow_dm1) >> d) + z[i];
        tmp -= (tmp >= p) * p;
        tmp += (tmp < 0) * p;
        z[i] = tmp;
    }
    SC_PRINT_1D_INT16(sc, SC_LEVEL_DEBUG, "z", z, n);

    // Generate the oracle data from the v vector
    if (SC_FUNC_FAILURE == oracle(sc, my_idx, kappa, m, m_len, z, n, mask)) {
        SC_LOG_ERROR(sc, SC_ERROR);
        goto oracle_failure;
    }

    // Compare the given oracle data with the received information
    for (i=0; i<kappa; i++) {
        if (my_idx[i] != c_idx[i]) {
            SC_LOG_ERROR(sc, SC_ERROR);
            goto verification_failure;
        }
    }

    sc->stats.sig_num_verified++;
    SC_PRINT_DEBUG(sc, "SUCCESS!\n");
    SC_PRINT_1D_INT16(sc, SC_LEVEL_DEBUG, "v", z, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Oracle", my_idx, kappa);
    SC_MEMZERO(t, (3 * n + 2 * kappa) * sizeof(SINT32));
    return SC_FUNC_SUCCESS;

verification_failure:
    SC_PRINT_1D_INT16(sc, SC_LEVEL_DEBUG, "v", z, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Oracle", my_idx, kappa);
    SC_PRINT_DEBUG(sc, "Verification failed\n");
oracle_failure:
verification_early_failure:
    SC_MEMZERO(t, (3 * n + 2 * kappa) * sizeof(SINT32));

    sc->stats.sig_num_unverified++;

    SC_PRINT_DEBUG(sc, "FAILURE!\n");
    return SC_FUNC_FAILURE;
}

#endif // DISABLE_SIGNATURES_CLIENT

char * bliss_b_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I", "II", "III", "IV"};
    static char stats[2048];
    snprintf(stats, 2047, "\nBLISS Signature (BLISS-B-%s):\n\
Keys           %8" FMT_LIMB " key-pairs  / %8" FMT_LIMB " trials [%.6f trials per key-pair]\n\
Signatures     %8" FMT_LIMB " signatures / %8" FMT_LIMB " trials [%.6f trials per signature]\n\
Verifications  %8" FMT_LIMB " passed     / %8" FMT_LIMB " failed\n\n\
Sampler:                 %s (%d-bit)\n\
PRNG:                    %s\n\
Oracle Hash:             %s\n\n\
Public Key compression:  %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   public  %10.2f%13.2f%16.3f%%\n\n\
Private Key compression: %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   f       %10.2f%13.2f%16.3f%%\n\
   g       %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Signature compression:   %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   z1      %10.2f%13.2f%16.3f%%\n\
   z2      %10.2f%13.2f%16.3f%%\n\
   oracle  %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n",
        param_set_name[sc->bliss->params->set],
        sc->stats.keygen_num,
        sc->stats.keygen_num_trials,
        (!sc->stats.keygen_num)? 0 : (DOUBLE)sc->stats.keygen_num_trials / (DOUBLE)sc->stats.keygen_num,
        sc->stats.sig_num,
        sc->stats.sig_num_trials,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.sig_num_trials / (DOUBLE)sc->stats.sig_num,
        sc->stats.sig_num_verified,
        sc->stats.sig_num_unverified,
        sc_sampler_names[sc->sampling],
        sc->sampling_precision,
        safecrypto_prng_names[(int)prng_get_type(sc->prng_ctx[0])],
        sc_hash_names[sc->bliss->oracle_hash],
        sc_entropy_names[(int)sc->coding_pub_key.type],
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.components[SC_STAT_PUB_KEY][0].bits? 100 * (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits : 0,
        sc_entropy_names[(int)sc->coding_priv_key.type],
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.components[SC_STAT_PRIV_KEY][0].bits? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.components[SC_STAT_PRIV_KEY][0].bits? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.components[SC_STAT_PRIV_KEY][0].bits? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits : 0,
        sc_entropy_names[(int)sc->coding_signature.type],
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.components[SC_STAT_SIGNATURE][0].bits)? 0 : 100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.components[SC_STAT_SIGNATURE][1].bits)? 0 : 100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.components[SC_STAT_SIGNATURE][2].bits)? 0 : 100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.sig_num)? 0 : (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits_coded/(DOUBLE)sc->stats.sig_num,
        (!sc->stats.components[SC_STAT_SIGNATURE][3].bits)? 0 : 100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits);
    return stats;
}


#undef FMT_LIMB
