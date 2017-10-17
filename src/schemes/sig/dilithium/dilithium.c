/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

#include "dilithium.h"

#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/crypto/xof.h"
#include "utils/arith/arith.h"
#include "utils/arith/module_lwe.h"
#include "utils/arith/ntt.h"
#include "utils/arith/sc_math.h"
#include "utils/entropy/entropy.h"
#include "utils/entropy/packer.h"
#include "utils/sampling/sampling.h"
#include "dilithium_params.h"

#include <math.h>


#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif

/// A preprocessor macro for barrett reduction:
///     r = x - q*((x*m) >> k)
///     if (q < r) r -= q
#define DILITHIUM_BARRETT_REDUCTION(r,x,k,m,q) \
    {SINT64 t, c; \
    t = ((SINT64)(x) * (m)) >> (k); \
    c = (x) - t * (q); \
    if ((q) <= c) \
        c -= (q); \
    r = (SINT32) c;}

#define BARRETT_DIVISION(r,x,k,m,q) \
    {SINT64 t, c; \
    t = ((SINT64)(x) * (m)) >> (k); \
    c = (x) - t * (q); \
    if ((q) <= c) \
        t++; \
    r = (SINT32) t;}

#ifdef DILITHIUM_STORE_T_RESIDUALS
#define NUM_TEMP_DILITHIUM_RINGS    (5*k + 2*l + 4)
#define NUM_TEMP_DILITHIUM_G_RINGS  (8*k + 2*l + 4)
#else
#define NUM_TEMP_DILITHIUM_RINGS    (7*k + 2*l + 4)
#define NUM_TEMP_DILITHIUM_G_RINGS  (10*k + 2*l + 4)
#endif


SINT32 dilithium_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 2, 4, 3, 0, 0, 0)) {
        return SC_FUNC_FAILURE;
    }

    // Precomputation for entropy coding
    sc->coding_pub_key.type             =
        (flags[0] & SC_FLAG_0_ENTROPY_BAC)?            SC_ENTROPY_BAC :
        (flags[0] & SC_FLAG_0_ENTROPY_BAC_RLE)?        SC_ENTROPY_BAC_RLE :
        (flags[0] & SC_FLAG_0_ENTROPY_STRONGSWAN)?     SC_ENTROPY_STRONGSWAN :
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN_STATIC)? SC_ENTROPY_HUFFMAN_STATIC :
                                                       SC_ENTROPY_NONE;
    sc->coding_pub_key.entropy_coder    = NULL;
    sc->coding_priv_key.type            =
        (flags[0] & SC_FLAG_0_ENTROPY_BAC)?            SC_ENTROPY_BAC :
        (flags[0] & SC_FLAG_0_ENTROPY_BAC_RLE)?        SC_ENTROPY_BAC_RLE :
        (flags[0] & SC_FLAG_0_ENTROPY_STRONGSWAN)?     SC_ENTROPY_STRONGSWAN :
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN_STATIC)? SC_ENTROPY_HUFFMAN_STATIC :
                                                       SC_ENTROPY_NONE;
    sc->coding_priv_key.entropy_coder   = NULL;
    sc->coding_signature.type           =
        (flags[0] & SC_FLAG_0_ENTROPY_BAC)?            SC_ENTROPY_BAC :
        (flags[0] & SC_FLAG_0_ENTROPY_BAC_RLE)?        SC_ENTROPY_BAC_RLE :
        (flags[0] & SC_FLAG_0_ENTROPY_STRONGSWAN)?     SC_ENTROPY_STRONGSWAN :
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN_STATIC)? SC_ENTROPY_HUFFMAN_STATIC :
                                                       SC_ENTROPY_NONE;
    sc->coding_signature.entropy_coder  = NULL;

    sc->blinding = (flags[0] & SC_FLAG_0_SAMPLE_BLINDING)?  BLINDING_SAMPLES : NORMAL_SAMPLES;
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
                                                 CDF_GAUSSIAN_SAMPLING;
                                                 //ZIGGURAT_GAUSSIAN_SAMPLING;

    // Allocate memory for Dilithium configuration
    sc->dilithium = SC_MALLOC(sizeof(dilithium_cfg_t));
    if (NULL == sc->dilithium) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified Dilithium parameter set
    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        switch (set)
        {
            case 0:  sc->dilithium->params = &param_dilithium_0;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            case 1:  sc->dilithium->params = &param_dilithium_1;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            case 2:  sc->dilithium->params = &param_dilithium_2;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            case 3:  sc->dilithium->params = &param_dilithium_3;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            default: SC_FREE(sc->dilithium, sizeof(dilithium_cfg_t));
                     return SC_FUNC_FAILURE;
        }
    }
    else {
        switch (set)
        {
            case 0:  sc->dilithium->params = &param_dilithium_g_0;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            case 1:  sc->dilithium->params = &param_dilithium_g_1;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            case 2:  sc->dilithium->params = &param_dilithium_g_2;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            case 3:  sc->dilithium->params = &param_dilithium_g_3;
                     sc->dilithium->entropy = sc->coding_signature.type;
                     break;
            default: SC_FREE(sc->dilithium, sizeof(dilithium_cfg_t));
                     return SC_FUNC_FAILURE;
        }
    }

    UINT32 n = sc->dilithium->params->n;
    UINT32 k = sc->dilithium->params->k;
    UINT32 l = sc->dilithium->params->l;

    // Initialise the reduction scheme
    sc->dilithium->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->dilithium->ntt, n, sc->dilithium->params->q);

    // Initialise the alpha reduction scheme
    sc->dilithium->ntt_alpha.n = sc->dilithium->params->n;
    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        sc->dilithium->ntt_alpha.u.ntt32.q = 2 * sc->dilithium->params->gamma_2;
    }
    else {
        sc->dilithium->ntt_alpha.u.ntt32.q = sc->dilithium->params->alpha;
    }
    barrett_init(&sc->dilithium->ntt_alpha);
    sc->dilithium->ntt_alpha.q_dbl = sc->dilithium->ntt_alpha.u.ntt32.q;
    sc->dilithium->ntt_alpha.inv_q_dbl = 1.0f / sc->dilithium->ntt_alpha.q_dbl;

    // Create pointers for the arithmetic functions used by Dilithium
    sc->sc_ntt = utils_arith_ntt(sc->dilithium->ntt_optimisation);
    sc->sc_poly = utils_arith_poly();
    sc->sc_vec = utils_arith_vectors();

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
            sc->dilithium->oracle_hash = (512 == hash_length)? SC_HASH_BLAKE2_512 :
                                         (384 == hash_length)? SC_HASH_BLAKE2_384 :
                                         (256 == hash_length)? SC_HASH_BLAKE2_256 :
                                                               SC_HASH_BLAKE2_224;
        } break;
        case SC_FLAG_0_HASH_SHA2:
        {
            sc->dilithium->oracle_hash = (512 == hash_length)? SC_HASH_SHA2_512 :
                                         (384 == hash_length)? SC_HASH_SHA2_384 :
                                         (256 == hash_length)? SC_HASH_SHA2_256 :
                                                               SC_HASH_SHA2_224;
        } break;
        case SC_FLAG_0_HASH_SHA3:
        {
            sc->dilithium->oracle_hash = (512 == hash_length)? SC_HASH_SHA3_512 :
                                         (384 == hash_length)? SC_HASH_SHA3_384 :
                                         (256 == hash_length)? SC_HASH_SHA3_256 :
                                                               SC_HASH_SHA3_224;
        } break;
        case SC_FLAG_0_HASH_WHIRLPOOL:
        {
            sc->dilithium->oracle_hash = SC_HASH_WHIRLPOOL_512;
        } break;
        case SC_FLAG_0_HASH_FUNCTION_DEFAULT:
        default:
        {
            sc->dilithium->oracle_hash = sc->dilithium->params->oracle_hash;
        }
    }

    // Create the hash to be used by the random oracle
    sc->hash = utils_crypto_hash_create(sc->dilithium->oracle_hash);
    if (NULL == sc->hash) {
        return SC_FUNC_FAILURE;
    }

    // Create the XOF to be used by the random oracle
    sc->xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128);
    if (NULL == sc->xof) {
        return SC_FUNC_FAILURE;
    }

    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        // Retrieve the Gaussian Sampler standard deviation
        FLOAT sigma   = sc->dilithium->params->sigma;
        FLOAT tailcut = sc->dilithium->params->tailcut;

        // Initialise the random distribution sampler
        sc->sc_gauss = create_sampler(sc->sampling,
            sc->sampling_precision, sc->blinding, n, SAMPLING_DISABLE_BOOTSTRAP,
            sc->prng_ctx[0], tailcut, sigma);

#ifdef USE_RUNTIME_NTT_TABLES
        // Dynamically allocate memory for the necessary NTT tables
        SINT32 *temp = (SINT32*) SC_MALLOC(sizeof(SINT32) * 2 * n);
        sc->dilithium->params->w = temp;
        sc->dilithium->params->r = temp + n;
        roots_of_unity_s32(sc->dilithium->params->w, sc->dilithium->params->r,
            n, sc->dilithium->params->q, sc->dilithium->params->prim_root);
#endif
    }

    // Dynamically allocate memory for temporary storage
    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        sc->temp_size = NUM_TEMP_DILITHIUM_RINGS * n * sizeof(SINT32);
    }
    else {
        sc->temp_size = NUM_TEMP_DILITHIUM_G_RINGS * n * sizeof(SINT32);
    }
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            SC_FREE(sc->sampler, 1 * sizeof(void *));
            destroy_sampler(&sc->sc_gauss);
            SC_FREE(sc->dilithium, sizeof(dilithium_cfg_t));
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT32) * 2 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 dilithium_destroy(safecrypto_t *sc)
{
    UINT32 n, k, l;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->dilithium->params->n;
    k = sc->dilithium->params->k;
    l = sc->dilithium->params->l;

    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
#ifdef USE_RUNTIME_NTT_TABLES
        SC_FREE(sc->dilithium->params->w, sizeof(SINT32) * 2 * n);
#endif

        destroy_sampler(&sc->sc_gauss);
    }

    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

    // Free all resources associated with key-pair and signature
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, (NUM_DILITHIUM_PRIVKEY_K*k + l) * n * sizeof(SINT32) + 32 * sizeof(UINT8));
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, k*n * sizeof(SINT32) + 32 * sizeof(UINT8));
        sc->pubkey->len = 0;
    }

    utils_crypto_hash_destroy(sc->hash);
    utils_crypto_xof_destroy(sc->xof);

    if (sc->dilithium) {
        SC_FREE(sc->dilithium, sizeof(dilithium_cfg_t));
    }

#ifdef SC_THREADPOOLS
    const utils_threading_t *threading = utils_threading();
    threading->pool_destroy(threadpool, THREADPOOL_GRACEFUL_EXIT);
#endif

    SC_PRINT_DEBUG(sc, "Dilithium scheme destroyed");

    return SC_FUNC_SUCCESS;
}

SINT32 dilithium_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, k, d, q_bits;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->dilithium->params->n;
    k      = sc->dilithium->params->k;
    d      = sc->dilithium->params->d;
    q_bits = sc->dilithium->params->q_bits;

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, k * n * sizeof(SINT32) + 32 * sizeof(UINT8));
    }
    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(k * n * sizeof(SINT32) + 32 * sizeof(UINT8));
        if (NULL == sc->pubkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    // Create a bit packer to extract the public key from the buffer
    SINT32 *pubkey = (SINT32 *) sc->pubkey->key;
    UINT8  *rho    = (UINT8*)(pubkey + k * n);
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        (q_bits - d) * k * n + 32*8, key, key_len, NULL, 0);
    if (NULL == packer) {
        return SC_FUNC_FAILURE;
    }
    entropy_poly_decode_32(packer, k*n, pubkey, q_bits - d,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    entropy_poly_decode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    utils_entropy.pack_destroy(&packer);
    sc->pubkey->len = n;

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Loaded public key", pubkey, k*n);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Loaded public rho", rho, 32);

    return SC_FUNC_SUCCESS;
}

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 dilithium_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 dilithium_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT32 n, k, l, q_bits, eta_bits;
    SINT32 *privkey, *s1, *s2, *t;
    UINT8 *rho;
#ifdef DILITHIUM_STORE_T_RESIDUALS
    SINT32 *t1, *t0;
    UINT32 q, d;
#endif

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n        = sc->dilithium->params->n;
    q_bits   = sc->dilithium->params->q_bits;
    eta_bits = sc->dilithium->params->eta_bits;
    l        = sc->dilithium->params->l;
    k        = sc->dilithium->params->k;
#ifdef DILITHIUM_STORE_T_RESIDUALS
    q        = sc->dilithium->params->q;
    d        = sc->dilithium->params->d;
#endif

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, (NUM_DILITHIUM_PRIVKEY_K*k + l) * n * sizeof(SINT32) + 32 * sizeof(UINT8));
    }
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC((NUM_DILITHIUM_PRIVKEY_K*k + l) * n * sizeof(SINT32) + 32 * sizeof(UINT8));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    // Create a bit packer to extract the public key from the buffer
    privkey = (SINT32 *) sc->privkey->key;
    s1      = privkey;
    s2      = s1 + l * n;
    t       = s2 + k * n;
#ifdef DILITHIUM_STORE_T_RESIDUALS
    t1      = t  + k * n;
    t0      = t1 + k * n;
#endif
    rho     = (UINT8*)(privkey + (NUM_DILITHIUM_PRIVKEY_K*k + l) * n);
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        ((eta_bits + 1) * (l + k) + q_bits * k) * n + 32*8, key, key_len, NULL, 0);
    if (NULL == packer) {
        return SC_FUNC_FAILURE;
    }

    // s1
    entropy_poly_decode_32(packer, l*n, s1, eta_bits + 1,
        SIGNED_COEFF, SC_ENTROPY_NONE);

    // s2
    entropy_poly_decode_32(packer, k*n, s2, eta_bits + 1,
        SIGNED_COEFF, SC_ENTROPY_NONE);

    // t
    entropy_poly_decode_32(packer, k*n, t, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);

    // rho
    entropy_poly_decode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);

    utils_entropy.pack_destroy(&packer);
    sc->privkey->len = n;

    // Round the resulting kx1 key matrix to form the public key.
#ifdef DILITHIUM_STORE_T_RESIDUALS
    decompose(t1, t0, t, n, k, d, q);
    SINT32 *pk = sc->pubkey->key;
    for (i=0; i<k*n; i++) {
        pk[i] = t1[i];
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Loaded t1", t1, k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Loaded t0", t0, k * n);

#ifndef DILITHIUM_USE_SPARSE_MULTIPLIER
    const SINT32 *ntt_w = sc->dilithium->params->w;
    const SINT32 *ntt_r = sc->dilithium->params->r;
    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->dilithium->ntt;

    // Replace t0 with NTT(t0)
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_32(t0 + n*i, ntt, t0 + n*i, ntt_w);
    }
#endif
#endif

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Loaded privkey s1", s1, l*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Loaded privkey s2", s2, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Loaded privkey t", t, k*n);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Loaded privkey rho", rho, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Loaded privkey stream", (UINT8*)privkey, (NUM_DILITHIUM_PRIVKEY_K*k + l) * n * sizeof(SINT32) + 32);

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_CLIENT

#ifdef DISABLE_SIGNATURES_SERVER

SINT32 dilithium_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 dilithium_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 dilithium_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT32 n, k, d, q_bits;
    const SINT32 *pubkey;
    const UINT8 *rho;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->dilithium->params->n;
    k      = sc->dilithium->params->k;
    d      = sc->dilithium->params->d;
    q_bits = sc->dilithium->params->q_bits;

    pubkey = (SINT32 *) sc->pubkey->key;
    rho    = (const UINT8*)(pubkey + k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encoded public key", pubkey, k*n);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Encoded public rho", rho, 32);

    // Statistics
    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += (q_bits - d) * k * n;
    sc->stats.components[SC_STAT_PUB_KEY][1].bits += 32*8;
    sc->stats.components[SC_STAT_PUB_KEY][2].bits += (q_bits - d) * k * n + 32*8;

    // Create a bit packer to compress the public key
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        (q_bits - d) * k * n + 32*8, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_32(packer, k*n, pubkey, q_bits - d,
        UNSIGNED_COEFF, SC_ENTROPY_NONE,
        &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);
    entropy_poly_encode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE,
        &sc->stats.components[SC_STAT_PUB_KEY][1].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PUB_KEY][2].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

SINT32 dilithium_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT32 n, q_bits, eta_bits, l, k;
    SINT32 *privkey;
    const UINT8 *rho;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n        = sc->dilithium->params->n;
    q_bits   = sc->dilithium->params->q_bits;
    eta_bits = sc->dilithium->params->eta_bits;
    l        = sc->dilithium->params->l;
    k        = sc->dilithium->params->k;

    privkey  = (SINT32 *) sc->privkey->key;
    rho      = (const UINT8*)(privkey + (NUM_DILITHIUM_PRIVKEY_K*k + l) * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encoded privkey s1", privkey, l*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encoded privkey s2", privkey + l*n, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encoded privkey t", privkey + (k+l)*n, k*n);
#ifdef DILITHIUM_STORE_T_RESIDUALS
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encoded privkey t1", privkey + (2*k+l)*n, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encoded privkey t0", privkey + (3*k+l)*n, k*n);
#endif
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Encoded privkey rho", rho, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Encoded privkey stream",
        (UINT8*)privkey, (NUM_DILITHIUM_PRIVKEY_K*k + l) * n * sizeof(SINT32) + 32);

    // Statistics
    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += (eta_bits + 1) * l * n;
    sc->stats.components[SC_STAT_PRIV_KEY][1].bits += (eta_bits + 1) * k * n;
    sc->stats.components[SC_STAT_PRIV_KEY][2].bits += q_bits * k * n;
    sc->stats.components[SC_STAT_PRIV_KEY][3].bits += 32*8;
    sc->stats.components[SC_STAT_PRIV_KEY][4].bits += ((eta_bits + 1) * (l + k) + q_bits * k) * n + 32*8;

    SINT32 *temp = privkey;

    // Create a bit packer to compress the public key
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        ((eta_bits + 1) * (l + k) + q_bits * k) * n + 32*8, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // s1
    entropy_poly_encode_32(packer, l*n, temp, eta_bits + 1,
        SIGNED_COEFF, SC_ENTROPY_NONE,
        &sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);

    // s2
    entropy_poly_encode_32(packer, k*n, temp + l*n, eta_bits + 1,
        SIGNED_COEFF, SC_ENTROPY_NONE,
        &sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded);

    // t
    entropy_poly_encode_32(packer, k*n, privkey + (k+l)*n, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE,
        &sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded);

    // rho
    entropy_poly_encode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE,
        &sc->stats.components[SC_STAT_PRIV_KEY][3].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PRIV_KEY][4].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_SERVER


#ifdef DISABLE_SIGNATURES_SERVER

SINT32 dilithium_keygen(safecrypto_t *sc)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 dilithium_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 dilithium_keygen(safecrypto_t *sc)
{
    size_t i;
#ifdef DILITHIUM_USE_CSPRNG_SAM
    prng_ctx_t *csprng = NULL;
#else
    utils_crypto_xof_t *xof = NULL;
#endif
    SINT32 *t, *s1, *s2, *c, *temp, *pk;
    UINT32 n, q, q_bits, eta, eta_bits, l, k, d;
    UINT8 rho[32];

#ifdef DILITHIUM_STORE_T_RESIDUALS
    SINT32 *t1, *t0;
#endif

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Dilithium KeyGen\n");

    n        = sc->dilithium->params->n;
    q        = sc->dilithium->params->q;
    q_bits   = sc->dilithium->params->q_bits;
    eta      = sc->dilithium->params->eta;
    eta_bits = sc->dilithium->params->eta_bits;
    l        = sc->dilithium->params->l;
    k        = sc->dilithium->params->k;
    d        = sc->dilithium->params->d;

    // Allocate temporary memory
    c    = sc->temp;
    if (NULL == c) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    temp = c + n;

    // Allocate key pair memory
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC((NUM_DILITHIUM_PRIVKEY_K * k + l) * n * sizeof(SINT32) + 32 * sizeof(UINT8));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(k * n * sizeof(SINT32) + 32 * sizeof(UINT8));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, (NUM_DILITHIUM_PRIVKEY_K * k + l) * n * sizeof(SINT32) + 32 * sizeof(UINT8));
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    s1 = sc->privkey->key;
    s2 = s1 + l * n;
    t  = s2 + k * n;
#ifdef DILITHIUM_STORE_T_RESIDUALS
    t1 = t  + k * n;
    t0 = t1 + k * n;
#endif
    pk = sc->pubkey->key;

    const SINT32 *ntt_w = sc->dilithium->params->w;
    const SINT32 *ntt_r = sc->dilithium->params->r;
    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->dilithium->ntt;

    // Statistics
    sc->stats.keygen_num++;
restart:
    sc->stats.keygen_num_trials++;

    // Generate a 256 bit random byte array to be used to seed a CSPRNG.
    prng_mem(sc->prng_ctx[0], rho, 32);

    // Generate s1 and s2 from a uniform random distribution with values of
    // -eta to +eta inclusive.
    uniform_rand_sample_small_csprng(sc->prng_ctx[0], q, eta, eta_bits, s1, n, l);
    uniform_rand_sample_small_csprng(sc->prng_ctx[0], q, eta, eta_bits, s2, n, k);
    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        // Verify that the maximum singular value of (s1, s2)^T is <= S
        UINT32 max_singular_s = sc->dilithium->params->max_singular_s;
        UINT32 max_singular   = max_singular_value(s1, l, s2, k, n);
        SC_PRINT_DEBUG(sc, "max_singular_s = %d, max_singular = %d\n", max_singular_s, max_singular);
        if (max_singular_s < max_singular) {
            goto restart;
        }
    }
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "rho", rho, 32);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s1", s1, l * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s2", s2, k * n);

#ifdef DILITHIUM_USE_CSPRNG_SAM
    // Generate a CSPRNG and seed it with rho as entropy.
    csprng = create_csprng(sc, rho, 32);
#else
    xof = sc->xof;
    xof_init(xof);
    xof_absorb(xof, rho, 32);
    xof_final(xof);
#endif

    // Matrix multiplication of A and s1, where A is uniform random
    // sampled as a k x l matrix of ring polynomials with n coefficients.
    // The kxl A matrix is multiplied by the lx1 s1 matrix to form a kx1
    // matrix to which s2 is added.
#ifdef DILITHIUM_USE_CSPRNG_SAM
    create_rand_product_32_csprng(csprng,
#else
    create_rand_product_32_xof(xof,
#endif
        q, q_bits, t, s1, n, k, l, c, temp,
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
        RND_PRD_DISABLE_OVERWRITE,
#else
        RND_PRD_ENABLE_OVERWRITE,
#endif
        RND_PRD_NOT_TRANSPOSED,
        ntt_w, ntt_r, sc_poly, sc_ntt, ntt);
    sc_poly->add_32(t, k*n, t, s2);
    sc_ntt->normalize_32(t, k*n, ntt);
    SC_MEMCOPY(s1 + (NUM_DILITHIUM_PRIVKEY_K*k + l)*n, rho, 32);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t", t, k*n);
#ifndef DILITHIUM_USE_SPARSE_MULTIPLIER
    sc_ntt->normalize_32(s1, l*n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "NTT(s1)", s1, l*n);
#endif

#ifdef DILITHIUM_USE_CSPRNG_SAM
    // Destroy the CSPRNG
    prng_destroy(csprng);
#endif

    // Store rho with the public key
    SC_MEMCOPY(pk + k*n, rho, 32);

    // Round the resulting kx1 key matrix to form the public key.
#ifdef DILITHIUM_STORE_T_RESIDUALS
    decompose(t1, t0, t, n, k, d, q);
    for (i=0; i<k*n; i++) {
        pk[i] = t1[i];
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t1", t1, k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t0", t0, k * n);

#ifndef DILITHIUM_USE_SPARSE_MULTIPLIER
    // Replace t0 with NTT(t0)
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_32(t0 + n*i, ntt, t0 + n*i, ntt_w);
    }
    sc_ntt->normalize_32(t0, k*n, ntt);
#endif
#else
    pwr_2_round(pk, t, n, k, d);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t1", pk, k * n);
#endif

    // Clear the temporary memory resources
    SC_MEMZERO(c, (l + 1) * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;

finish_free:
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, (NUM_DILITHIUM_PRIVKEY_K*k + l) * n * sizeof(SINT32) + 32 * sizeof(UINT8));
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, k*n * sizeof(SINT32) + 32 * sizeof(UINT8));
    }

    // Clear the temporary memory resources
    SC_MEMZERO(c, (l + 1) * n * sizeof(SINT32));

    // Destroy the random oracle
#ifdef DILITHIUM_USE_CSPRNG_SAM
    if (NULL != csprng) {
        prng_destroy(csprng);
    }
#endif

    return SC_FUNC_FAILURE;
}

static void dilithium_hash(safecrypto_t *sc, const UINT8 *r, const SINT32 *t1, const UINT8 *w1,
    const UINT8 *m, size_t m_len, size_t n, size_t k, UINT8 *md)
{
    size_t i, j;
    UINT8 data[256];

    // Hash the input data to form a fixed length byte string
    hash_init(sc->hash);
    hash_update(sc->hash, r, 32);

    for (i=0; i<(k*n)>>8; i++) {
        for (j=0; j<256; j++) {
            data[j] = t1[i*256+j];
        }
        hash_update(sc->hash, data, 256);
    }

    hash_update(sc->hash, w1, k*n);
    hash_update(sc->hash, m, m_len);
    hash_final(sc->hash, md);
}

static void dilithium_g_hash(safecrypto_t *sc, const UINT8 *r, const SINT32 *t1, const SINT32 *w1,
    const UINT8 *m, size_t m_len, size_t n, size_t k, UINT8 *md)
{
    // Hash the input data to form a fixed length byte string
    hash_init(sc->hash);
    hash_update(sc->hash, r, 32);
    hash_update(sc->hash, (UINT8*)t1, k*n*sizeof(SINT32));
    hash_update(sc->hash, (UINT8*)w1, k*n*sizeof(SINT32));
    hash_update(sc->hash, m, m_len);
    hash_final(sc->hash, md);
}

// A random oracle that maps the input data that uniquely identifies the
// message to a polynomial ring.
static void h_function(safecrypto_t *sc, SINT32 *c, const UINT8 *r,
    const SINT32 *t1, const UINT8 *w1, const UINT8 *m, size_t m_len,
    size_t n, size_t k)
{
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "r", r, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "t1", (UINT8*)t1, k*n*sizeof(SINT32));
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "w1", w1, k*n);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, m_len);

    const UINT32 q                = sc->dilithium->params->q;
    const SINT32 q_bits           = sc->dilithium->params->q_bits;
    const size_t weight_of_c      = sc->dilithium->params->weight_of_c;

#ifdef DILITHIUM_USE_H_FUNC_XOF
    size_t i, j, x;
    const size_t num_weight_bytes = (weight_of_c + 7) >> 3;
    UINT8 signs[num_weight_bytes + weight_of_c];

    utils_crypto_xof_t *h_xof = sc->xof;
    xof_init(h_xof);
    xof_absorb(h_xof, r, 32);
    for (i=0; i<(k*n)>>8; i++) {
        UINT8 data[256];
        for (j=0; j<256; j++) {
            data[j] = t1[i*256+j];
        }
        xof_absorb(h_xof, data, 256);
    }
    xof_absorb(h_xof, w1, k*n);
    xof_absorb(h_xof, m, m_len);
    xof_final(h_xof);
    xof_squeeze(h_xof, signs, num_weight_bytes + weight_of_c);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "H(r,t1,w1,msg)", signs, num_weight_bytes + weight_of_c);

    // Generate the output coefficients for the spare polynomial
    kyber_oracle_core(n, weight_of_c, c, num_weight_bytes, signs);
#else
    UINT8 md[64];

    // Hash the input data to form a fixed length byte string
    dilithium_hash(sc, r, t1, w1, m, m_len, n, k, md);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "H(r,t1,w1,msg)", md, sc->hash->length);

    // Use the byte string to generate a unique ring polynomial of n elements
#ifdef DILITHIUM_USE_CSPRNG_SAM
    kyber_oracle_csprng(sc, n, q, q_bits, weight_of_c, md, sc->hash->length, c);
#else
    kyber_oracle_xof(sc, n, q, q_bits, weight_of_c, md, sc->hash->length, c);
#endif
#endif

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "c", c, n);
}

// A random oracle that maps the input data that uniquely identifies the
// message to a polynomial ring.
static void h_g_function(safecrypto_t *sc, SINT32 *c, const UINT8 *r,
    const SINT32 *t1, const SINT32 *w1, const UINT8 *m, size_t m_len,
    size_t n, size_t k)
{
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "r", r, 32);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t1", t1, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "w1", w1, k*n);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, m_len);

    const UINT32 q                = sc->dilithium->params->q;
    const SINT32 q_bits           = sc->dilithium->params->q_bits;
    const size_t weight_of_c      = sc->dilithium->params->weight_of_c;

#ifdef DILITHIUM_USE_H_FUNC_XOF
    size_t i, j, x;
    const size_t num_weight_bytes = (weight_of_c + 7) >> 3;
    UINT8 *signs = SC_MALLOC(num_weight_bytes + weight_of_c);
    UINT8 *msg   = SC_MALLOC(32 + k*n*3 + m_len);

    SC_MEMCOPY(msg, r, 32);
    for (i=0; i<(k*n)>>8; i++) {
        UINT8 data[256];
        for (j=0; j<256; j++) {
            data[j] = t1[i*256+j];
        }
        SC_MEMCOPY(msg + 32 + i*256, data, 256);
    }
    for (i=0; i<(k*n)>>7; i++) {
        UINT8 data[256];
        for (j=0; j<128; j++) {
            //data[4*j  ] = w1[i*64+j] >> 24;
            //data[4*j+1] = w1[i*64+j] >> 16;
            data[2*j  ] = w1[i*128+j] >> 8;
            data[2*j+1] = w1[i*128+j];
        }
        SC_MEMCOPY(msg + 32 + k*n + i*256, data, 256);
    }
    //SC_MEMCOPY(msg + 32 + k*n, w1, k*n*sizeof(SINT32));
    SC_MEMCOPY(msg + 32 + k*n + k*n*2, m, m_len);

    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m for XOF", msg, 32 + k*n*3 + m_len);

    utils_crypto_xof_t *h_xof = sc->xof;
    xof_init(h_xof);
    xof_absorb(h_xof, msg, 32 + k*n*3 + m_len);
    xof_final(h_xof);
    xof_squeeze(h_xof, signs, num_weight_bytes + weight_of_c);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "H(r,t1,w1,msg)", signs, num_weight_bytes + weight_of_c);

    // Generate the output coefficients for the spare polynomial
    kyber_oracle_core(n, weight_of_c, c, num_weight_bytes, signs);

    SC_FREE(msg, 32 + k*n*3 + m_len);
    SC_FREE(signs, num_weight_bytes + weight_of_c);
#else
    UINT8 md[64];

    // Hash the input data to form a fixed length byte string
    dilithium_g_hash(sc, r, t1, w1, m, m_len, n, k, md);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "H(r,t1,w1,msg)", md, sc->hash->length);

    // Use the byte string to generate a unique ring polynomial of n elements
#ifdef DILITHIUM_USE_CSPRNG_SAM
    kyber_oracle_csprng(sc, n, q, q_bits, weight_of_c, md, sc->hash->length, c);
#else
    kyber_oracle_xof(sc, n, q, q_bits, weight_of_c, md, sc->hash->length, c);
#endif
#endif

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "c", c, n);
}

// Check if the norm of v is greater than or equal to b, ||v|| >= b
static SINT32 check_norm_inf(const SINT32 *v, size_t n, size_t len, SINT32 q, SINT32 b)
{
    size_t i;
    SINT32 lower_half = (q - 1) >> 1;
    SINT32 upper_b    = q - b;

    // Scan through the l matrices of length n,
    // Terminate early if the threshold is exceeded and return 1.
    UINT32 retval = 0;
    for (i=0; i<len*n; i++) {
        UINT32 v_is_smaller = v[i] <= lower_half;
        retval |= v_is_smaller && (v[i] >= b) || !v_is_smaller && (v[i] <= upper_b);
    }

    return retval;
}

// Calculate the norm of two matrices
static DOUBLE calc_norm(const SINT32 *a, size_t len, size_t n)
{
    size_t i;
    SINT64 modx = 0;
    for (i=0; i<len*n; i++) {
        modx += a[i] * a[i];
    }
    return sqrt((DOUBLE)modx);
}

// As per Algorithm 10, find the HighOrderBits of r and r + z given reduction
// factor alpha. Return the difference modulo (q-1)/alpha, i.e. 16
static void make_g_hint(SINT32 *h, const SINT32 *r, const SINT32 *z, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha)
{
    size_t i;
    SINT32 t;
    SINT32 q      = p->u.ntt32.q;
    SINT32 m      = (q - 1) / alpha->u.ntt32.q;  /// @todo Make a parameter
    SINT32 m_mask = m - 1;

    for (i=0; i<k*n; i++) {
        // (r[i] + z[i]) mod q
        SINT32 sum;
        //DILITHIUM_BARRETT_REDUCTION(sum, r[i] + z[i], bk, bm, q);
        sum  = r[i] + z[i];
        sum -= (sum >= q) * q;
        sum += (sum < 0) * q;
        SINT32 r1 = round_alpha(r[i], &t, alpha, p);
        SINT32 r0 = round_alpha(sum, &t, alpha, p);
        h[i] = (r0 - r1) & m_mask;
        if (h[i] >= (m >> 1)) {
            h[i] -= m;
        }
    }
}

// As per Algorithm 11, use the h hint integers to recover z from r
static void use_g_hint(SINT32 *z, const SINT32 *h, const SINT32 *r, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha)
{
    size_t i;
    SINT32 t1, t2;
    SINT32 q      = p->u.ntt32.q;
    SINT32 m      = (q - 1) / alpha->u.ntt32.q;
    SINT32 m_mask = m - 1;

    for (i=0; i<k*n; i++) {
        t2  = round_alpha(r[i], &t1, alpha, p);
        z[i] = (t2 + h[i]) & m_mask;
    }
}

// As per Algorithm 5, find the HighOrderBits of r and r + z given reduction
// factor alpha. If there is a mismatch return a 1, otherwise return a 0.
static SINT32 make_hint(SINT32 *SC_RESTRICT h, const SINT32 *SC_RESTRICT r, const SINT32 *SC_RESTRICT z, size_t n,
    size_t k, const ntt_params_t *p, const ntt_params_t *alpha)
{
    size_t i;
    SINT32 t, sum = 0;
    SINT64 q  = p->u.ntt32.q;

    for (i=0; i<k*n; i++) {
        // (r[i] + z[i]) mod q
        SINT32 add;
        add  = r[i] + z[i];
        add -= (add >= q) * q;
        add += (add < 0) * q;
        h[i] = add;
    }
    for (i=0; i<k*n; i++) {
        SINT32 add;
        UINT32 r1 = round_alpha(r[i], &t, alpha, p);
        UINT32 r0 = round_alpha(h[i], &t, alpha, p);
        add = r1 != r0;
        h[i] = add;
        sum += add;
    }

    return sum;
}

// As per Algorithm 6, use the h hint bits to recover z from r
static void use_hint(UINT8 *z, const SINT32 *h, const SINT32 *r, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha)
{
    size_t i;
    SINT32 t1, t2;
    SINT32 q      = p->u.ntt32.q;
    SINT32 m      = (q - 1) / alpha->u.ntt32.q;
    SINT32 m_mask = m - 1;

    for (i=0; i<k*n; i++) {
        t2 = round_alpha(r[i], &t1, alpha, p);
        if (1 == h[i]) {
            if (t1 > 0) {
                t2++;
            }
            else {
                t2--;
            }
        }

        if (t2 < 0) {
            t2 += m;
        }

        z[i] = t2 & m_mask; // t2 % m
    }
}

static void sparse_mul_mod_ring(SINT32 * SC_RESTRICT r, const SINT32 * SC_RESTRICT a,
    const SINT32 * SC_RESTRICT b_sparse, size_t n, SINT32 * SC_RESTRICT temp)
{
    size_t j, k;

    // Reset the output to zero
    for (j=2*n-1; j--;) {
        temp[j] = 0;
    }

    // Accumulate the a coefficients with the sparse b coefficient with the
    // knowledge that they only have the values -1, 0 or 1.
    for (j=0; j<n; j++) {
        if (b_sparse[j] < 0) {
            for (k=0; k<n; k++) {
                temp[j+k] -= a[k];
            }
        }
        else if (b_sparse[j] > 0) {
            for (k=0; k<n; k++) {
                temp[j+k] += a[k];
            }
        }
    }

    // Perform the ring modular reduction
    for (j=n; j--;) {
        r[j] = temp[j] - temp[j + n];
    }
}

static void sparse_mul_mod_q_ring(SINT32 *r, const SINT32 *a, const SINT32 *b_sparse,
    size_t n, ntt_params_t *ntt, size_t period, SINT32 *sparse)
{
    size_t i, j, p;
    SINT32 q = ntt->u.ntt32.q;

    // Reset the output to zero
    for (i=2*n-1; i--;) {
        sparse[i] = 0;
    }

    // Accumulate the a coefficients with the sparse b coefficient with the
    // knowledge that they only have the values -1, 0 or 1.
    // Only perform reduction at the specified rate.
    for (i=0, p=0; i<n; i++) {
        if (b_sparse[i] < 0) {
            for (j=0; j<n; j++) {
                sparse[i+j] -= a[j];
            }
        }
        else if (b_sparse[i] > 0) {
            for (j=0; j<n; j++) {
                sparse[i+j] += a[j];
            }
        }
        if (period == ++p) {
            p = 0;
            for (j=0; j<n+i; j++) {
                sparse[j] -= (sparse[j] >= q) * q;
                sparse[j] += (sparse[j] < 0) * q;
            }
        }
    }

    // Perform the ring modular reduction
    for (j=n; j--;) {
        r[j] = sparse[j] - sparse[j + n];
    }
}

SINT32 dilithium_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
    size_t i;
#ifdef DILITHIUM_USE_CSPRNG_SAM
    prng_ctx_t *csprng;
#else
    utils_crypto_xof_t *xof;
#endif
#ifdef DILITHIUM_STORE_T_RESIDUALS
    const SINT32 *t0, *t1;
#else
    SINT32 *t0, *t1;
#endif
    SINT32 *w, *h, *y, *c, *temp, *ntt_c, *z, *ct0, *wcs2;
    SINT32 *z1, *z2, *y1, *y2, *w1, *w0;
    UINT8 *w1_bytes;
    UINT32 n, q, q_bits, z_bits, alpha, beta,
        omega_bits, gamma_1, gamma_1_bits, gamma_2, sigma, l, k, d;
    const UINT8 *r;
    const SINT32 *privkey;
    SINT32 num_ones = 0;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Dilithium Sign\n");

    n            = sc->dilithium->params->n;
    q            = sc->dilithium->params->q;
    q_bits       = sc->dilithium->params->q_bits;
    z_bits       = sc->dilithium->params->z_bits;
    alpha        = sc->dilithium->params->alpha;
    beta         = sc->dilithium->params->beta;
    omega_bits   = sc->dilithium->params->omega_bits;
    gamma_1      = sc->dilithium->params->gamma_1;
    gamma_1_bits = sc->dilithium->params->gamma_1_bits;
    gamma_2      = sc->dilithium->params->gamma_2;
    sigma        = sc->dilithium->params->sigma;
    l            = sc->dilithium->params->l;
    k            = sc->dilithium->params->k;
    d            = sc->dilithium->params->d;

    // Assign a pointer tot he private key
    privkey  = sc->privkey->key;

    // Allocate temporary memory
    if (NULL == sc->temp) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    r        = (const UINT8*)(privkey + (NUM_DILITHIUM_PRIVKEY_K*k + l)*n);
    c        = sc->temp;
    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        temp     = c + n;
        ntt_c    = temp + 2*n;
#ifdef DILITHIUM_STORE_T_RESIDUALS
        t1       = privkey + (2*k + l)*n;
        t0       = t1 + k*n;
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
        w        = ntt_c;
#else
        w        = ntt_c + n;
#endif
#else
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
        t0       = ntt_c;
#else
        t0       = ntt_c + n;
#endif
        t1       = t0 + k*n;
        w        = t1 + k*n;
#endif
        h        = w + k*n;
        y        = h + k*n;
        z        = y + l*n;
        ct0      = z + l*n;
        wcs2     = ct0 + k*n;
        w1_bytes = (UINT8*)(wcs2 + k*n);
    }
    else {
        temp     = c + n;
        ntt_c    = temp + 2*n;
#ifdef DILITHIUM_STORE_T_RESIDUALS
        t1       = privkey + (2*k + l)*n;
        t0       = t1 + k*n;
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
        w        = ntt_c;
#else
        w        = ntt_c + n;
#endif
#else
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
        t0       = ntt_c;
#else
        t0       = ntt_c + n;
#endif
        t1       = t0 + k*n;
        w        = t1 + k*n;
#endif
        h        = w + k*n;
        y        = h + k*n;
        y1       = y;
        y2       = y1 + l*n;
        z        = y2 + k*n;
        z1       = z;
        z2       = z1 + l * n;
        ct0      = z2 + k*n;
        wcs2     = ct0 + k*n;
        w1_bytes = (UINT8*)(wcs2 + k*n);
        w1       = wcs2 + k*n;
        w0       = w1 + k*n;
    }

    const SINT32 *ntt_w = sc->dilithium->params->w;
    const SINT32 *ntt_r = sc->dilithium->params->r;
    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    const utils_arith_vec_t *sc_vec = sc->sc_vec;
    utils_sampling_t* sc_gauss = sc->sc_gauss;
    ntt_params_t *ntt = &sc->dilithium->ntt;
    ntt_params_t *ntt_alpha = &sc->dilithium->ntt_alpha;

    // Obtain t0 and t1 from the private key value t and the parameter d
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t", privkey + (k+l)*n, k * n);
#ifndef DILITHIUM_STORE_T_RESIDUALS
    decompose(t1, t0, privkey + (k+l)*n, n, k, d, q);
#endif
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t1", t1, k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t0", t0, k * n);

restart:
    SC_PRINT_DEBUG(sc, "RESTARTING SIGNATURE");

    // Statistics
    sc->stats.sig_num_trials++;

    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        // Generate y from a uniform random distribution with -(gamma_1-1) to
        // +(gamma_1-1) inclusive.
        uniform_rand_sample_csprng(sc->prng_ctx[0], q, gamma_1 - 1, gamma_1_bits, y, n, l);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "y", y, l * n);
    }
    else {
        get_vector_32(sc_gauss, y1, l*n, 0);
        get_vector_32(sc_gauss, y2, k*n, 0);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "y1", y1, l * n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "y2", y2, k * n);
    }

    // Generate a 512 bit random byte array and use it to seed a CSPRNG/XOF
#ifdef DILITHIUM_USE_CSPRNG_SAM
    csprng = create_csprng(sc, r, 32);
#else
    xof = sc->xof;
    xof_init(xof);
    xof_absorb(xof, r, 32);
    xof_final(xof);
#endif
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "r", r, 32);

    // Generate the kx1 matrix w = A*y mod q for Dilithium and
    // w = A*y1 + y2 mod q for Dilithium-G
#ifdef DILITHIUM_USE_CSPRNG_SAM
    create_rand_product_32_csprng(csprng,
#else
    create_rand_product_32_xof(xof,
#endif
        q, q_bits, w, y, n, k, l, c, wcs2,
        RND_PRD_DISABLE_OVERWRITE, RND_PRD_NOT_TRANSPOSED,
        ntt_w, ntt_r, sc_poly, sc_ntt, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "y (AFTER create_rand_product())", y, l * n);
    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        sc_poly->add_32(w, k*n, w, y2);
        sc_ntt->normalize_32(w, k*n, ntt);
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "w", w, k*n);

#ifdef DILITHIUM_USE_CSPRNG_SAM
    // Destroy the CSPRNG
    prng_destroy(csprng);
    csprng = NULL;
#endif

    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        // Generate the high order representation of w
        high_order_bits(w1_bytes, w, n, k, ntt, ntt_alpha);
        SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "w1", w1_bytes, k*n);

        // Calculate H(rho, t1, w1, mu) such that a sparse polynomial with 60
        // coefficients have the values 1 or -1
        h_function(sc, c, r, t1, w1_bytes, m, m_len, n, k);
    }
    else {
        // Generate the high order representation of w
        decompose_g(w1, w0, w, n, k, ntt_alpha, q);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "w1", w1, k*n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "w0", w0, k*n);

        // Calculate H(rho, t1, w1, mu) such that a sparse polynomial with 60
        // coefficients have the values 1 or -1
        h_g_function(sc, c, r, t1, w1, m, m_len, n, k);
    }

    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        // Check 1 - Verify that the norm of z = y + c * s1 is less than gamma_1 - beta
#ifndef DILITHIUM_USE_SPARSE_MULTIPLIER
        sc_ntt->fwd_ntt_32_32(ntt_c, ntt, c, ntt_w);
#endif
        for (i=0; i<l; i++) {
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
            sparse_mul_mod_ring(z + n*i, privkey + n*i, c, n, temp);
#else
            sc_ntt->mul_32_pointwise(temp, ntt, ntt_c, privkey + n*i);
            sc_ntt->inv_ntt_32_32(z + n*i, ntt, temp, ntt_w, ntt_r);
#endif
        }
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "z (BEFORE ADDITION)", z, l*n);
        sc_poly->add_32(z, l*n, z, y);
        sc_ntt->normalize_32(z, l*n, ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "z", z, l*n);
        if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
            SC_PRINT_DEBUG(sc, "z restart");
            SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "privkey", privkey, l*n);
            goto restart;
        }

        // Check 2 - Verify that the norm of LowOrderBits_q(w - c*s2, 2*gamma_2) is
        // less than gamma_2 - beta
        for (i=0; i<k; i++) {
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
            sparse_mul_mod_ring(wcs2 + n*i, privkey + l*n + n*i, c, n, temp);
#else
            sc_ntt->fwd_ntt_32_32(temp, ntt, privkey + l*n + n*i, ntt_w);
            sc_ntt->mul_32_pointwise(temp, ntt, ntt_c, temp);
            sc_ntt->inv_ntt_32_32(wcs2 + n*i, ntt, temp, ntt_w, ntt_r);
#endif
        }
        sc_poly->sub_32(wcs2, k*n, w, wcs2);
        sc_ntt->normalize_32(wcs2, k*n, ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "w - c*s2", wcs2, k*n);
        low_order_bits(ct0, wcs2, n, k, ntt, ntt_alpha);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "LowOrderBits_q (w − c*s_2 , 2*gamma_2)", ct0, k*n);
        if (check_norm_inf(ct0, n, k, q, gamma_2 - beta)) {
            SC_PRINT_DEBUG(sc, "w − c*s_2 restart");
            goto restart;
        }

        // Check 3 - Verify that the norm of c*t0 is less than gamma_2 - beta
        for (i=0; i<k; i++) {
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
            sparse_mul_mod_q_ring(ct0 + n*i, t0 + n*i, c, n, ntt, n>>1, temp);
#else
#ifndef DILITHIUM_STORE_T_RESIDUALS
            sc_ntt->fwd_ntt_32_32(t0 + n*i, ntt, t0 + n*i, ntt_w);
#endif
            sc_ntt->mul_32_pointwise(temp, ntt, ntt_c, t0 + n*i);
            sc_ntt->inv_ntt_32_32(ct0 + n*i, ntt, temp, ntt_w, ntt_r);
#endif
        }
        sc_ntt->normalize_32(ct0, k*n, ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "c*t0", ct0, k*n);
        if (check_norm_inf(ct0, n, k, q, gamma_2 - beta)) {
            SC_PRINT_DEBUG(sc, "ct0 restart");
            goto restart;
        }

        // Create the hint to be appended to the signature
        // Add ct0 to wcs2 and normalise, negate ct0
        sc_poly->add_32(wcs2, k*n, wcs2, ct0);
        sc_ntt->normalize_32(wcs2, k*n, ntt);
        sc_poly->mod_negate_32(ct0, k*n, q, ct0);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "-c*t0", ct0, k*n);
        num_ones = make_hint(h, wcs2, ct0, n, k, ntt, ntt_alpha);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "hint", h, k*n);
        SC_PRINT_DEBUG(sc, "Number of ones in hint: %d (omega = %d)", num_ones, sc->dilithium->params->omega);

        // If the number of asserted bits in h is greater than omega then restart
        if (num_ones > sc->dilithium->params->omega) {
            SC_PRINT_DEBUG(sc, "Number of ones restart");
            goto restart;
        }
    }
    else {
        // Compute z1 and z2 - uses the fact that z1|z2 and y1|y2 are
        // contiguous in memory.
#ifndef DILITHIUM_USE_SPARSE_MULTIPLIER
        sc_ntt->fwd_ntt_32_32(ntt_c, ntt, c, ntt_w);
#endif
        for (i=0; i<l+k; i++) {
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
            sparse_mul_mod_ring(z + n*i, privkey + n*i, c, n, temp);
#else
            sc_ntt->fwd_ntt_32_32(temp, ntt, privkey + n*i, ntt_w);
            sc_ntt->mul_32_pointwise(temp, ntt, ntt_c, temp);
            sc_ntt->inv_ntt_32_32(z + n*i, ntt, temp, ntt_w, ntt_r);
#endif
        }
        sc_ntt->normalize_32(z, (l+k)*n, ntt);
        SINT32 cs_norm = sc_vec->scalar_32(z, z, (l+k)*n);
        sc_poly->add_32(y, (l+k)*n, z, y);
        SINT32 cs_inner_prod = sc_vec->scalar_32(y, z, (l+k)*n);
        sc_ntt->normalize_32(y, (l+k)*n, ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "z1", y, l*n);

        // Rejection sampling - calculate (1/3).exp(-2<z,cs> + ||cs||^2)/(2*sigma^2))
        DOUBLE exp_value = -2 * (DOUBLE) cs_inner_prod +
            (DOUBLE) cs_norm;// * (DOUBLE) cs_norm;
        exp_value /= 2 * (DOUBLE) sigma * (DOUBLE) sigma;
        exp_value = 0.333 * exp(exp_value);
        UINT32 u = prng_var(sc->prng_ctx[0], 1);
        SC_PRINT_DEBUG(sc, "(1/3).exp(-2<z,cs> + ||cs||^2)/(2*sigma^2)) = %f, u = %d\n", exp_value, u);
        if ((DOUBLE)u > exp_value) {
            goto restart;
        }

        // z2 = z2 - c*t0 - w0
        for (i=0; i<k; i++) {
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
            sparse_mul_mod_ring(ct0 + n*i, t0 + n*i, c, n, temp);
#else
#ifndef DILITHIUM_STORE_T_RESIDUALS
            sc_ntt->fwd_ntt_32_32(t0 + n*i, ntt, t0 + n*i, ntt_w);
#endif
            sc_ntt->mul_32_pointwise(temp, ntt, ntt_c, t0 + n*i);
            sc_ntt->inv_ntt_32_32(ct0 + n*i, ntt, temp, ntt_w, ntt_r);
#endif
        }
        sc_poly->sub_32(y2, k*n, y2, ct0);
        sc_poly->sub_32(y2, k*n, y2, w0);
        sc_ntt->center_32(y, (l+k)*n, ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "z2 = z2 - c*t0 - w0", y2, k*n);

        // If the norm ||(z1,z2)|| >= B then restart
        DOUBLE z1z2_norm = calc_norm(y, l + k, n);
        SC_PRINT_DEBUG(sc, "||(z1, z2)|| = %f vs B = %d\n", z1z2_norm, beta);
        //fprintf(stderr, "%f vs %d\n", z1z2_norm, beta);
        if (z1z2_norm >= beta) {
            goto restart;
        }

        // Create the hint to be appended to the signature
        for (i=0; i<k*n; i++) {
            wcs2[i] = alpha * w1[i] - y2[i];
        }
        sc_ntt->normalize_32(wcs2, k*n, ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "alpha * w1 - z2", wcs2, k*n);
        make_g_hint(h, wcs2, y2, n, k, ntt, ntt_alpha);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "hint", h, k*n);

        z = y1;
    }

    sc_ntt->center_32(z, l*n, ntt);

    // Pack the output signature and perform any entropy coding
    size_t packer_bits;
    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        packer_bits = l*n*z_bits + 9*k*n + 2*n;
    }
    else {
        packer_bits = l*n*z_bits + k*n + 2*n;
    }
    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        packer_bits += 8 * k*n;
    }
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_signature,
        packer_bits, NULL, 0, sigret, siglen);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        goto finish_free;
    }
    entropy_poly_encode_32(packer, l*n, z, z_bits,
        SIGNED_COEFF,
        (SC_SCHEME_SIG_DILITHIUM == sc->scheme)? SC_ENTROPY_NONE : sc->coding_signature.type,
        &sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded);
    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        entropy_poly_encode_32(packer, k*n, h, 9,
            SIGNED_COEFF, sc->coding_signature.type,
            &sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded);
        sc->stats.components[SC_STAT_SIGNATURE][1].bits += 9*k*n;
        sc->stats.components[SC_STAT_SIGNATURE][3].bits += 9*k*n;
    }
    else {
        size_t h_bits = 8 + ((k + 1) >> 1);
        i = 0;
        utils_entropy.pack_insert(packer, num_ones, omega_bits);
        sc->stats.components[SC_STAT_SIGNATURE][1].bits += num_ones * h_bits;
        sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded += num_ones * h_bits;
        sc->stats.components[SC_STAT_SIGNATURE][3].bits += num_ones * h_bits + omega_bits;
        while (num_ones) {
            if (h[i]) {
                utils_entropy.pack_insert(packer, i, h_bits);
                num_ones--;
            }
            i++;
        }
    }
    entropy_poly_encode_32(packer, n, c, 2,
        UNSIGNED_COEFF, SC_ENTROPY_NONE,
        &sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded);
    sc->stats.components[SC_STAT_SIGNATURE][3].bits += l*n*z_bits + 2*n;
    utils_entropy.pack_get_buffer(packer, sigret, siglen);
    utils_entropy.pack_destroy(&packer);

    // Statistics
    sc->stats.sig_num++;
    sc->stats.components[SC_STAT_SIGNATURE][0].bits += l*n*z_bits;
    sc->stats.components[SC_STAT_SIGNATURE][2].bits += 2*n;
    sc->stats.components[SC_STAT_SIGNATURE][3].bits_coded += *siglen * 8;

    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Compressed signature", *sigret, *siglen);

    // Clear the temporary memory resources
    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        SC_MEMZERO(c, (6*k + 2*l + 4) * n * sizeof(SINT32));
    }
    else {
        SC_MEMZERO(c, (9*k + 2*l + 4) * n * sizeof(SINT32));
    }

    return SC_FUNC_SUCCESS;

finish_free:
    // Clear the temporary memory resources
    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        SC_MEMZERO(c, (6*k + 2*l + 4) * n * sizeof(SINT32));
    }
    else {
        SC_MEMZERO(c, (9*k + 2*l + 4) * n * sizeof(SINT32));
    }

#ifdef DILITHIUM_USE_CSPRNG_SAM
    // Destroy the CSPRNG
    prng_destroy(csprng);
#endif

    return SC_FUNC_FAILURE;
}

#endif // DISABLE_SIGNATURES_SERVER

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 dilithium_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 *sigbuf, size_t siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

static SINT32 check_hint_ones(const SINT32 *h, size_t k, size_t n)
{
    size_t i;
    SINT32 sum = 0;

    for (i=0; i<k*n; i++) {
        sum += h[i];
    }

    return sum;
}

SINT32 dilithium_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
    size_t i, j;
#ifdef DILITHIUM_USE_CSPRNG_SAM
    prng_ctx_t *csprng = NULL;
#else
    utils_crypto_xof_t *xof;
#endif
    SINT32 *t0, *t1, *w, *w1, *y, *c, *temp, *ntt_c, *z, *h;
    UINT8 *w1_bytes;
    UINT32 n, q, q_bits, z_bits, alpha, beta, omega_bits, gamma_1, l, k, d;
    const UINT8 *r;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Dilithium Verify\n");

    n            = sc->dilithium->params->n;
    q            = sc->dilithium->params->q;
    q_bits       = sc->dilithium->params->q_bits;
    z_bits       = sc->dilithium->params->z_bits;
    alpha        = sc->dilithium->params->alpha;
    beta         = sc->dilithium->params->beta;
    omega_bits   = sc->dilithium->params->omega_bits;
    gamma_1      = sc->dilithium->params->gamma_1;
    l            = sc->dilithium->params->l;
    k            = sc->dilithium->params->k;
    d            = sc->dilithium->params->d;

    // Allocate temporary memory
    c        = sc->temp;
    if (NULL == c) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    temp     = c + n;
    ntt_c    = temp + 2*n;
    t0       = ntt_c + n;
    w        = t0 + k*n;
    y        = w + k*n;
    z        = y + l*n;
    w1       = z + l*n;
    w1_bytes = (UINT8*)(z + l*n);
    h        = w1 + k*n;
    t1       = sc->pubkey->key;
    r        = (const UINT8*)(t1 + k*n);

    const SINT32 *ntt_w = sc->dilithium->params->w;
    const SINT32 *ntt_r = sc->dilithium->params->r;
    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->dilithium->ntt;
    ntt_params_t *ntt_alpha = &sc->dilithium->ntt_alpha;


    // Create a packer to decode the input symbols
    sc_packer_t *ipacker;
    ipacker = utils_entropy.pack_create(sc, &sc->coding_signature,
        0, sigbuf, siglen, NULL, 0);
    if (NULL == ipacker) {
        return SC_FUNC_FAILURE;
    }
    entropy_poly_decode_32(ipacker, l*n, z, z_bits,
        SIGNED_COEFF, (SC_SCHEME_SIG_DILITHIUM == sc->scheme)? SC_ENTROPY_NONE : sc->coding_signature.type);
    sc_ntt->normalize_32(z, l*n, ntt);
    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        entropy_poly_decode_32(ipacker, k*n, h, 9,
            SIGNED_COEFF, sc->coding_signature.type);
    }
    else {
        size_t h_bits = 8 + ((k + 1) >> 1);
        UINT32 num_ones;
        utils_entropy.pack_remove(ipacker, &num_ones, omega_bits);
        SC_MEMZERO(h, k * n * sizeof(SINT32));
        for (i=0; i<num_ones; i++) {
            UINT32 temp;
            utils_entropy.pack_remove(ipacker, &temp, h_bits);
            h[temp] = 1;
        }
    }
    for (i=0; i<n; i++) {
        UINT32 temp;
        utils_entropy.pack_remove(ipacker, &temp, 2);
        c[i] = (3 == temp)? -1 : temp;
    }
    utils_entropy.pack_destroy(&ipacker);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received z", z, l*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received h", h, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received c", c, n);

    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        // Verify that the norm of z is less than or equal to gamma_1 - beta
        if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
            SC_PRINT_DEBUG(sc, "||z|| is >= gamma_1 - beta\n");
            SC_LOG_ERROR(sc, SC_ERROR);
            goto finish_free;
        }

        // Verify that the number of ones in the hint is <= omega
        if (check_hint_ones(h, k, n) > sc->dilithium->params->omega) {
            goto finish_free;
        }
    }
    else {
        // Verify that the norm of h is less than or equal to (q-1)/alpha
        if (check_norm_inf(h, n, k, q, (q-1)/alpha)) {
            SC_PRINT_DEBUG(sc, "||h|| is >= (q-1)/alpha)\n");
            SC_LOG_ERROR(sc, SC_ERROR);
            goto finish_free;
        }
    }

    // Create a CSPRNG and generate the kx1 matrix w = A*z mod q
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Verify r", r, 32);
#ifdef DILITHIUM_USE_CSPRNG_SAM
    csprng = create_csprng(sc, r, 32);
#else
    xof = sc->xof;
    xof_init(xof);
    xof_absorb(xof, r, 32);
    xof_final(xof);
#endif
#ifdef DILITHIUM_USE_CSPRNG_SAM
    create_rand_product_32_csprng(csprng,
#else
    create_rand_product_32_xof(xof,
#endif
        q, q_bits, w, z, n, k, l, ntt_c, t0,
        RND_PRD_DISABLE_OVERWRITE, RND_PRD_NOT_TRANSPOSED,
        ntt_w, ntt_r, sc_poly, sc_ntt, ntt);
#ifdef DILITHIUM_USE_CSPRNG_SAM
    prng_destroy(csprng);
    csprng = NULL;
#endif
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Verify w = A*z", w, k*n);

    // Calculate c * t1 . 2^d
#ifndef DILITHIUM_USE_SPARSE_MULTIPLIER
    sc_ntt->fwd_ntt_32_32(ntt_c, ntt, c, ntt_w);
#endif
    for (i=0; i<k; i++) {
        for (j=n; j--;) {
            t0[n*i + j] = t1[j + n*i] << d;
        }
#ifdef DILITHIUM_USE_SPARSE_MULTIPLIER
        sparse_mul_mod_q_ring(t0 + n*i, t0 + n*i, c, n, ntt, n>>1, temp);
#else
        sc_ntt->fwd_ntt_32_32(temp, ntt, t0 + n*i, ntt_w);
        sc_ntt->mul_32_pointwise(temp, ntt, ntt_c, temp);
        sc_ntt->inv_ntt_32_32(t0 + n*i, ntt, temp, ntt_w, ntt_r);
#endif
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Verify c*t1.2^d", t0, k*n);

    // A*z - c*t1.2^d mod q
    sc_poly->sub_32(t0, k*n, w, t0);
    sc_ntt->normalize_32(t0, k*n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Verify A*z - c*t1.2^d", t0, k*n);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Verify hint", h, k*n);
    if (SC_SCHEME_SIG_DILITHIUM == sc->scheme) {
        // Use the signature hint to recreate w1 from A*z - c*t1.2^d
        use_hint(w1_bytes, h, t0, n, k, ntt, ntt_alpha);
        SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Verify w1", w1_bytes, k*n);

        // Calculate H(rho, t1, w1, mu) such that a sparse polynomial with 60
        // coefficients have the values 1 or -1
        h_function(sc, temp, r, t1, w1_bytes, m, m_len, n, k);
    }
    else {
        // Use the signature hint to recreate w1 from A*z - c*t1.2^d
        use_g_hint(w1, h, t0, n, k, ntt, ntt_alpha);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Verify w1", w1, k*n);

        // Calculate H(rho, t1, w1, mu) such that a sparse polynomial with 60
        // coefficients have the values 1 or -1
        h_g_function(sc, temp, r, t1, w1, m, m_len, n, k);
    }

    // Check the output of the H function against the received value
    // in the signature
    for (i=0; i<n; i++) {
        if (temp[i] != c[i]) {
            SC_LOG_ERROR(sc, SC_ERROR);
            goto finish_free;
        }
    }

    // If using Dilithium-G verify that ||(z1, A*z1 - c*t1) - alpha*w1)|| < B
    if (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme) {
        for (i=0; i<k*n; i++) {
            w[i] = (SINT32) w1_bytes[i] * alpha;
        }
        sc_poly->sub_32(w1, k*n, t0, w);
        DOUBLE z1z2_norm = calc_norm(z, l + k, n);
        if (z1z2_norm >= beta) {
            goto finish_free;
        }
    }

    // Clear the temporary memory resources
    SC_MEMZERO(c, (4*k + 2*l + 4) * n * sizeof(SINT32));

    sc->stats.sig_num_verified++;

    return SC_FUNC_SUCCESS;

finish_free:
    // Clear the temporary memory resources
    SC_MEMZERO(c, (4*k + 2*l + 4) * n * sizeof(SINT32));

    sc->stats.sig_num_unverified++;

    return SC_FUNC_FAILURE;
}

#endif // DISABLE_SIGNATURES_CLIENT

char * dilithium_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I", "II", "III", "G-0", "G-I", "G-II", "G-III"};
    static char stats[2048];
    snprintf(stats, 2047, "\nDilithium Signature (Dilithium-%s):\n\
Keys           %8" FMT_LIMB " key-pairs  / %8" FMT_LIMB " trials [%.6f trials per key-pair]\n\
Signatures     %8" FMT_LIMB " signatures / %8" FMT_LIMB " trials [%.6f trials per signature]\n\
Verifications  %8" FMT_LIMB " passed     / %8" FMT_LIMB " failed\n\n\
Sampler:                 %s\n\
PRNG:                    %s\n\
Oracle Hash:             %s\n\n\
Public Key compression:  %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   t1      %10.2f%13.2f%16.3f%%\n\
   rho     %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Private Key compression: %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   s1      %10.2f%13.2f%16.3f%%\n\
   s2      %10.2f%13.2f%16.3f%%\n\
   t       %10.2f%13.2f%16.3f%%\n\
   rho     %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Signature compression:   %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   z       %10.2f%13.2f%16.3f%%\n\
   h       %10.2f%13.2f%16.3f%%\n\
   c       %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n",
        (SC_SCHEME_SIG_DILITHIUM_G == sc->scheme)?
            param_set_name[sc->dilithium->params->set + 4] :
            param_set_name[sc->dilithium->params->set],
        sc->stats.keygen_num,
        sc->stats.keygen_num_trials,
        (DOUBLE)sc->stats.keygen_num_trials / (DOUBLE)sc->stats.keygen_num,
        sc->stats.sig_num,
        sc->stats.sig_num_trials,
        (DOUBLE)sc->stats.sig_num_trials / (DOUBLE)sc->stats.sig_num,
        sc->stats.sig_num_verified,
        sc->stats.sig_num_unverified,
        sc_sampler_names[sc->sampling],
        safecrypto_prng_names[(int)prng_get_type(sc->prng_ctx[0])],
        crypto_hash_names[sc->dilithium->oracle_hash],
        sc_entropy_names[(int)sc->coding_pub_key.type],
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][1].bits/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][1].bits_coded/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][1].bits : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][2].bits/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][2].bits_coded/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][2].bits : 0,
        sc_entropy_names[(int)sc->coding_priv_key.type],
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][1].bits : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][2].bits : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][3].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][3].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][3].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][3].bits : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][4].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][4].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][4].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][4].bits : 0,
        sc_entropy_names[(int)sc->coding_signature.type],
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][3].bits);
    return stats;
}


#undef FMT_LIMB
