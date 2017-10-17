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

#include "dlp_ibe.h"
#include "dlp_ibe_params.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/xof.h"
#include "utils/crypto/prng.h"
#include "utils/arith/arith.h"
#ifndef DISABLE_IBE_SERVER
#include "utils/arith/gpv.h"
#include "utils/arith/sc_poly_mpz.h"
#include "utils/arith/poly_fft.h"
#endif // !DISABLE_IBE_CLIENT
#include "utils/arith/sc_math.h"
#include "utils/entropy/entropy.h"
#include "utils/entropy/packer.h"
#include "utils/sampling/sampling.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif

#define DLP_IBE_NUM_TEMP_POLYNOMIALS        8

#ifdef DLP_IBE_USE_CLASSICAL_GSO
#define MODIFIED_GRAM_SCHMIDT modified_gram_schmidt_classical
#else
#ifdef DLP_IBE_USE_SINGLE_PREC_FLOATS
#define MODIFIED_GRAM_SCHMIDT modified_gram_schmidt_fast_flt
#else
#ifdef DLP_IBE_USE_DOUBLE_PREC_FLOATS
#define MODIFIED_GRAM_SCHMIDT modified_gram_schmidt_fast_dbl
#else
#define MODIFIED_GRAM_SCHMIDT modified_gram_schmidt_fast_ldbl
#endif
#endif
#endif

#ifdef DLP_IBE_USE_SINGLE_PREC_FLOATS
#define GPV_PRECOMPUTE_INV gpv_precompute_inv_flt
#else
#ifdef DLP_IBE_USE_DOUBLE_PREC_FLOATS
#define GPV_PRECOMPUTE_INV gpv_precompute_inv_dbl
#else
#define GPV_PRECOMPUTE_INV gpv_precompute_inv_ldbl
#endif
#endif


SINT32 dlp_ibe_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 1, 4, 0, 1, 3, 0)) {
        return SC_FUNC_FAILURE;
    }

    // Precomputation for entropy coding
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_pub_key.entropy_coder    = NULL;
    sc->coding_priv_key.type            =
        (flags[0] & SC_FLAG_0_ENTROPY_BAC)?            SC_ENTROPY_BAC :
        (flags[0] & SC_FLAG_0_ENTROPY_BAC_RLE)?        SC_ENTROPY_BAC_RLE :
        (flags[0] & SC_FLAG_0_ENTROPY_STRONGSWAN)?     SC_ENTROPY_STRONGSWAN :
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN_STATIC)? SC_ENTROPY_HUFFMAN_STATIC :
                                                       SC_ENTROPY_NONE;
    sc->coding_priv_key.entropy_coder   = NULL;
    sc->coding_user_key.type            =
        (flags[0] & SC_FLAG_0_ENTROPY_BAC)?            SC_ENTROPY_BAC :
        (flags[0] & SC_FLAG_0_ENTROPY_BAC_RLE)?        SC_ENTROPY_BAC_RLE :
        (flags[0] & SC_FLAG_0_ENTROPY_STRONGSWAN)?     SC_ENTROPY_STRONGSWAN :
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN_STATIC)? SC_ENTROPY_HUFFMAN_STATIC :
                                                       SC_ENTROPY_NONE;
    sc->coding_user_key.entropy_coder   = NULL;
    sc->coding_encryption.type          = SC_ENTROPY_NONE;
    sc->coding_encryption.entropy_coder = NULL;
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

    // Allocate memory for IBE configuration
    sc->dlp_ibe = SC_MALLOC(sizeof(dlp_ibe_cfg_t));
    if (NULL == sc->dlp_ibe) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified IBE parameter set
    switch (set)
    {
        case 0:  sc->dlp_ibe->params = &param_dlp_ibe_0;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 1:  sc->dlp_ibe->params = &param_dlp_ibe_1;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 2:  sc->dlp_ibe->params = &param_dlp_ibe_2;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 3:  sc->dlp_ibe->params = &param_dlp_ibe_3;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 4:  sc->dlp_ibe->params = &param_dlp_ibe_4;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 5:  sc->dlp_ibe->params = &param_dlp_ibe_5;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
#if 0
        case 6:  sc->dlp_ibe->params = &param_dlp_ibe_6;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 7:  sc->dlp_ibe->params = &param_dlp_ibe_7;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 8:  sc->dlp_ibe->params = &param_dlp_ibe_8;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 9:  sc->dlp_ibe->params = &param_dlp_ibe_9;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
        case 10:  sc->dlp_ibe->params = &param_dlp_ibe_10;
                 sc->dlp_ibe->entropy = sc->coding_encryption.type;
                 break;
#endif
        default: SC_FREE(sc->dlp_ibe, sizeof(dlp_ibe_cfg_t));
                 return SC_FUNC_FAILURE;
    }

    // Obtain parameters for the selected parameter set
    UINT16 n = sc->dlp_ibe->params->n;

    // Set a flag to indicate if the B and B_gs matrices (and the norm of
    // each B_gs row) are to be computed and stored.
    sc->dlp_ibe->keep_matrices = DLP_IBE_KEEP_GSO_MATRICES;
    sc->dlp_ibe->b             = NULL;
    sc->dlp_ibe->b_gs          = NULL;
    sc->dlp_ibe->b_gs_inv_norm = NULL;

    // Initialise the reduction scheme
    sc->dlp_ibe->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_BARRETT)?   SC_NTT_BARRETT :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->dlp_ibe->ntt, n, sc->dlp_ibe->params->q);

    // Create pointers for the arithmetic functions used by sc_ibe
    sc->sc_ntt = utils_arith_ntt(sc->dlp_ibe->ntt_optimisation);
    sc->sc_poly = utils_arith_poly();
    sc->sc_vec = utils_arith_vectors();

    // Create storage for the user secret key
    sc->dlp_ibe->user_key = SC_MALLOC(sizeof(SINT32) * 2 * n);

    // Configure the hashing algorithm to be used for the oracle.
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

    crypto_hash_e hash_func;
    switch (flags[0] & SC_FLAG_0_HASH_FUNCTION_MASK)
    {
        case SC_FLAG_0_HASH_BLAKE2:
        {
            hash_func = (512 == hash_length)? SC_HASH_BLAKE2_512 :
                        (384 == hash_length)? SC_HASH_BLAKE2_384 :
                        (256 == hash_length)? SC_HASH_BLAKE2_256 :
                                              SC_HASH_BLAKE2_224;
        } break;
        case SC_FLAG_0_HASH_SHA2:
        {
            hash_func = (512 == hash_length)? SC_HASH_SHA2_512 :
                        (384 == hash_length)? SC_HASH_SHA2_384 :
                        (256 == hash_length)? SC_HASH_SHA2_256 :
                                              SC_HASH_SHA2_224;
        } break;
        case SC_FLAG_0_HASH_SHA3:
        {
            hash_func = (512 == hash_length)? SC_HASH_SHA3_512 :
                        (384 == hash_length)? SC_HASH_SHA3_384 :
                        (256 == hash_length)? SC_HASH_SHA3_256 :
                                              SC_HASH_SHA3_224;
        } break;
        case SC_FLAG_0_HASH_WHIRLPOOL:
        {
            hash_func = SC_HASH_WHIRLPOOL_512;
        } break;
        case SC_FLAG_0_HASH_FUNCTION_DEFAULT:
        default:
        {
            hash_func = sc->dlp_ibe->params->hash_type;
        }
    }

    // Create the hash to be used by the random oracle
    sc->hash = utils_crypto_hash_create(hash_func);
    if (NULL == sc->hash) {
        return SC_FUNC_FAILURE;
    }

    // Create the XOF to be used by the random oracle
    sc->xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128);
    if (NULL == sc->xof) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the random distribution sampler
    FLOAT sigma  = sqrt((1.36 * sc->dlp_ibe->params->q / 2) / n);
    sc->sc_gauss = create_sampler(sc->sampling,
        sc->sampling_precision, sc->blinding, n, SAMPLING_DISABLE_BOOTSTRAP,
         sc->prng_ctx[0], 13.0f, sigma);
    if (NULL == sc->sc_gauss) {
        utils_crypto_hash_destroy(sc->hash);
        utils_crypto_xof_destroy(sc->xof);
        SC_FREE(sc->dlp_ibe, sizeof(dlp_ibe_cfg_t));
        return SC_FUNC_FAILURE;
    }
    sc->sampler = NULL;

#ifdef USE_RUNTIME_NTT_TABLES
    // Dynamically allocate memory for the necessary NTT tables
    SINT32 *temp = (SINT32*) SC_MALLOC(sizeof(SINT32) * 2 * n);
    sc->dlp_ibe->params->w = temp;
    sc->dlp_ibe->params->r = temp + n;
    roots_of_unity_s32(sc->dlp_ibe->params->w, sc->dlp_ibe->params->r,
        n, sc->dlp_ibe->params->q, sc->dlp_ibe->params->nth_root_of_unity);
#endif

    // Dynamically allocate memory for temporary storage
    sc->temp_size = (DLP_IBE_NUM_TEMP_POLYNOMIALS * n) * sizeof(SINT32);
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            utils_crypto_hash_destroy(sc->hash);
            utils_crypto_xof_destroy(sc->xof);
            destroy_sampler(&sc->sc_gauss);
            SC_FREE(sc->dlp_ibe, sizeof(dlp_ibe_cfg_t));
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT32) * 2 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 dlp_ibe_destroy(safecrypto_t *sc)
{
    UINT16 n;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->dlp_ibe->params->n;

    destroy_sampler(&sc->sc_gauss);

    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->dlp_ibe->params->w, sizeof(SINT32) * 2 * n);
#endif

    // Free all resources associated with key-pair and signature
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT32));
        sc->pubkey->len = 0;
    }

    // Free resources associated with the user secret key
    // and zero the memory
    SC_FREE(sc->dlp_ibe->user_key, sizeof(SINT32) * 2 * n);

    // Free resources associated with the polynomial basis
    if (sc->dlp_ibe->keep_matrices) {
        if (sc->dlp_ibe->b) {
            SC_FREE(sc->dlp_ibe->b, sizeof(SINT32) * 4 * n * n);
        }
        if (sc->dlp_ibe->b_gs) {
            SC_FREE(sc->dlp_ibe->b_gs, sizeof(GSO_TYPE) * 4 * n * n);
        }
        if (sc->dlp_ibe->b_gs_inv_norm) {
            SC_FREE(sc->dlp_ibe->b_gs_inv_norm, sizeof(GSO_TYPE) * 2 * n);
        }
    }

    if (sc->dlp_ibe) {
        utils_crypto_hash_destroy(sc->hash);
        utils_crypto_xof_destroy(sc->xof);
        SC_FREE(sc->dlp_ibe, sizeof(dlp_ibe_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "SAFEcrypto IBE algorithm destroyed");

    return SC_FUNC_SUCCESS;
}

#ifdef DISABLE_IBE_SERVER

SINT32 dlp_ibe_keygen(safecrypto_t *sc)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else // !DISABLE_IBE_SERVER

SINT32 dlp_ibe_keygen(safecrypto_t *sc)
{
    size_t i;
    SINT32 *h;
    UINT32 n, n_bits, q;
    const SINT16 *w, *r;
    gpv_t gpv;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "SAFEcrypto IBE KeyGen\n");

    n = sc->dlp_ibe->params->n;
    q = sc->dlp_ibe->params->q;

    // Allocate temporary memory
    gpv.f = sc->temp;
    if (NULL == gpv.f) {
        return SC_FUNC_FAILURE;
    }
    gpv.g = gpv.f + n;
    gpv.F = gpv.f + 2 * n;
    gpv.G = gpv.f + 3 * n;
    gpv.n = n;
    h     = gpv.f + 4 * n;

    // Gather statistics
    sc->stats.keygen_num++;


    SINT32 num_retries = -1;
    while (num_retries < 0) {
        num_retries = gpv_gen_basis(sc, gpv.f, gpv.g, h, n, q,
            sc->sc_gauss, sc->prng_ctx[0], gpv.F, gpv.G, 0);
        sc->stats.keygen_num_trials += num_retries + 1;
    }

    // Allocate key pair memory
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(4 * n * sizeof(SINT32));
        if (NULL == sc->privkey->key) {
            goto finish_free;
        }
    }

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT32));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
            goto finish_free;
        }
    }

    // Store the key pair in the SAFEcrypto structure for future use
    SINT32 *key = (SINT32*) sc->privkey->key;
    for (i=4*n; i--;) {
        key[i] = gpv.f[i]; // NOTE: f, g, F and G are contiguous
    }
    key = (SINT32*) sc->pubkey->key;
    for (i=n; i--;) {
        key[i] = h[i];
    }
    sc->privkey->len = 4 * n;
    sc->pubkey->len = n;

    // Create the polynomial basis matrices if they are to be maintained in memory
    if (sc->dlp_ibe->keep_matrices) {
#ifdef DLP_IBE_EXPAND_BASIS
        if (sc->dlp_ibe->b) {
            SC_FREE(sc->dlp_ibe->b, sizeof(SINT32) * 4 * n * n);
        }
        sc->dlp_ibe->b = SC_MALLOC(sizeof(SINT32) * 4 * n * n);
        gpv.b = sc->dlp_ibe->b;

        // Generate the polynomial basis matrix
        gpv_expand_basis(&gpv);
#endif

        if (sc->dlp_ibe->b_gs) {
            SC_FREE(sc->dlp_ibe->b_gs, sizeof(GSO_TYPE) * 4 * n * n);
        }
        if (sc->dlp_ibe->b_gs_inv_norm) {
            SC_FREE(sc->dlp_ibe->b_gs_inv_norm, sizeof(GSO_TYPE) * 2 * n);
        }
        sc->dlp_ibe->b_gs = SC_MALLOC(sizeof(GSO_TYPE) * 4 * n * n);
        sc->dlp_ibe->b_gs_inv_norm = SC_MALLOC(sizeof(GSO_TYPE) * 2 * n);

        // Gram-Schmidt orthogonolisation of the polynomial basis
        MODIFIED_GRAM_SCHMIDT(&gpv, sc->dlp_ibe->b_gs, q);

        // Precompute the norm of each row of b_gs
        GPV_PRECOMPUTE_INV(sc->dlp_ibe->b_gs, sc->dlp_ibe->b_gs_inv_norm, 2*n);
    }

#ifdef DLP_IBE_USE_SPARSE_MULTIPLICATION
    {//if (sc->dlp_ibe->params->q_bits >= 26) {
#else
    {
#endif
        // Store an NTT domain version of the public key
        sc->sc_ntt->fwd_ntt_32_32_large(key + n, &sc->dlp_ibe->ntt,
            h, sc->dlp_ibe->params->w);
        sc->sc_ntt->normalize_32(key + n, n, &sc->dlp_ibe->ntt);
    }

    SC_PRINT_DEBUG(sc, "Print keys\n");
    SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 32);

finish_free:
    // Clear the temporary memory used for generation
    SC_MEMZERO(gpv.f, 5 * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_IBE_SERVER


#ifdef DISABLE_IBE_CLIENT

SINT32 dlp_ibe_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else // !DISABLE_IBE_CLIENT

SINT32 dlp_ibe_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n = sc->dlp_ibe->params->n;
    q_bits = sc->dlp_ibe->params->q_bits;

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT32));
    }
    sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT32));
    if (NULL == sc->pubkey->key) {
        return SC_FUNC_FAILURE;
    }

    // Create a bit packer to extract the public key from the buffer
    SINT32 *pubkey = (SINT32 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, key, key_len, NULL, 0);
    entropy_poly_decode_32(packer, n, pubkey, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    utils_entropy.pack_destroy(&packer);
    sc->pubkey->len = n;

    // Store an NTT domain version of the public key
    sc->sc_ntt->fwd_ntt_32_32_large(pubkey + n, &sc->dlp_ibe->ntt,
        pubkey, sc->dlp_ibe->params->w);
    sc->sc_ntt->normalize_32(pubkey + n, n, &sc->dlp_ibe->ntt);

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_IBE_CLIENT

#ifdef DISABLE_IBE_SERVER

SINT32 dlp_ibe_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 dlp_ibe_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 dlp_ibe_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else // !DISABLE_IBE_SERVER

/// Extract a signed key polynomial from a byte stream
static SINT32 extract_signed_key(safecrypto_t *sc, SINT32 *sc_key,
    sc_entropy_t *coding, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, q_bits_1, q_bits_2;
    SINT32 q_min, q_max;
    UINT32 sign, sign_extension, value;
    SINT32 s;

    n              = sc->dlp_ibe->params->n;
    q_bits_1       = 6 * 1.17 * sqrt((DOUBLE)sc->dlp_ibe->params->q / (DOUBLE)(2*n));
    q_bits_1       = 1 + sc_ceil_log2(q_bits_1);
    q_bits_2       = 5 + q_bits_1;
    sign           = 1 << (q_bits_1 - 1);
    q_min          = -sign;
    q_max          = sign - 1;
    sign_extension = ((1 << (32 - q_bits_1)) - 1) << q_bits_1;

    sc_packer_t *packer = utils_entropy.pack_create(sc, coding,
        2 * n * (q_bits_1 + q_bits_2), key, key_len, NULL, 0);
    if (NULL == packer) {
        return SC_FUNC_FAILURE;
    }

    entropy_poly_decode_32(packer, n, sc_key, q_bits_1,
        SIGNED_COEFF, sc->coding_priv_key.type);
    entropy_poly_decode_32(packer, n, sc_key + n, q_bits_1,
        SIGNED_COEFF, sc->coding_priv_key.type);
    entropy_poly_decode_32(packer, n, sc_key + 2*n, q_bits_2,
        SIGNED_COEFF, sc->coding_priv_key.type);
    entropy_poly_decode_32(packer, n, sc_key + 3*n, q_bits_2,
        SIGNED_COEFF, sc->coding_priv_key.type);

    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

SINT32 dlp_ibe_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SINT32 *privkey;
    UINT16 n;

    n = sc->dlp_ibe->params->n;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
    }
    sc->privkey->key = SC_MALLOC(4 * n * sizeof(SINT32));
    if (NULL == sc->privkey->key) {
        return SC_FUNC_FAILURE;
    }

    // Assign pointers to buffers
    privkey = (SINT32 *) sc->privkey->key;

    // Extract the private key
    extract_signed_key(sc, privkey, &sc->coding_priv_key, key, key_len);
    sc->privkey->len = 4 * n;

    SC_PRINT_DEBUG(sc, "Private key loaded\n");
    SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 32);

    return SC_FUNC_SUCCESS;
}

SINT32 dlp_ibe_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n = sc->dlp_ibe->params->n;
    q_bits = sc->dlp_ibe->params->q_bits;

    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += n * q_bits;

    // Create a bit packer to compress the public key
    SINT32 *pubkey = (SINT32 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, NULL, 0, key, key_len);
    entropy_poly_encode_32(packer, n, pubkey, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &packer->sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

SINT32 dlp_ibe_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT16 n, q_bits_1, q_bits_2;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n        = sc->dlp_ibe->params->n;
    q_bits_1 = 6 * 1.17 * sqrt((DOUBLE)sc->dlp_ibe->params->q / (DOUBLE)(2*n));
    q_bits_1 = 1 + sc_ceil_log2(q_bits_1);
    q_bits_2 = 5 + q_bits_1;

    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += n * q_bits_1;
    sc->stats.components[SC_STAT_PRIV_KEY][1].bits += n * q_bits_1;
    sc->stats.components[SC_STAT_PRIV_KEY][2].bits += n * q_bits_2;
    sc->stats.components[SC_STAT_PRIV_KEY][3].bits += n * q_bits_2;
    sc->stats.components[SC_STAT_PRIV_KEY][4].bits += 2 * n * (q_bits_1 + q_bits_2);

    // Create a bit packer to compress the private key polynomial f
    SINT32 *privkey = (SINT32 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        2 * n * (q_bits_1 + q_bits_2), NULL, 0, key, key_len);
    entropy_poly_encode_32(packer, n, privkey, q_bits_1,
        SIGNED_COEFF, sc->coding_priv_key.type, &packer->sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);
    entropy_poly_encode_32(packer, n, privkey + n, q_bits_1,
        SIGNED_COEFF, sc->coding_priv_key.type, &packer->sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded);
    entropy_poly_encode_32(packer, n, privkey + 2*n, q_bits_2,
        SIGNED_COEFF, sc->coding_priv_key.type, &packer->sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded);
    entropy_poly_encode_32(packer, n, privkey + 3*n, q_bits_2,
        SIGNED_COEFF, sc->coding_priv_key.type, &packer->sc->stats.components[SC_STAT_PRIV_KEY][3].bits_coded);

    // Extract the buffer with the polynomial f and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PRIV_KEY][4].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_IBE_SERVER

// A random oracle that generates a fixed length random number sequence
// if given a variable length unique user ID.
static void oracle(safecrypto_t *sc, const UINT8 *id, size_t id_len, UINT8 *md)
{
    hash_init(sc->hash);
    hash_update(sc->hash, id, id_len);
    hash_final(sc->hash, md);
}

// Use a random oracle output (i.e. a hash message digest) to
// create a ring polynomial that represents the user ID.
static void id_function(safecrypto_t *sc, const UINT8 *id, size_t id_len, SINT32 *c)
{
    size_t i;
    const size_t n      = sc->dlp_ibe->params->n;
    const UINT32 q      = sc->dlp_ibe->params->q;
    const SINT32 q_bits = sc->dlp_ibe->params->q_bits;

#ifdef DLP_USE_RANDOM_ORACLE_CSPRNG
    UINT8 md[64] SC_DEFAULT_ALIGNED;
    static const UINT8 id_nonce[16] = "SAFEcrypto nonce";

    // Translate the User ID to a unique message digest to seed the CSPRNG
    oracle(sc, id, id_len, md);

    // Use the message digest as an IV for a CSPRNG
    prng_ctx_t *prng = prng_create(SC_ENTROPY_USER_PROVIDED,
        SC_PRNG_AES_CTR_DRBG, SC_PRNG_THREADING_NONE, 0x01000000);
    prng_set_entropy(prng, md, 64);
    prng_init(prng, id_nonce, 16);

    // Generate polynomial coefficients mod q from the CSPRNG
    for (i=0; i<n; i++) {
        c[i] = prng_var(prng, q_bits);
        if (c[i] >= q) {
            c[i] -= q;
        }
    }
    prng_destroy(prng);
#else
    UINT32 mask = (1 << q_bits) - 1;
    xof_init(sc->xof);
    xof_absorb(sc->xof, id, id_len);
    xof_final(sc->xof);
    xof_squeeze(sc->xof, c, n*sizeof(SINT32));

    // Generate polynomial coefficients mod q from the CSPRNG
    for (i=0; i<n; i++) {
        c[i] &= mask;
        c[i] -= (c[i] >= q) * q;
    }
#endif
}

// Use a random oracle output (i.e. a hash message digest) to
// create a byte sequence to be used as a one-time-pad.
static prng_ctx_t * k_function_csprng(safecrypto_t *sc, UINT8 *k, size_t n)
{
    size_t i;
    UINT8 md[64];
    const UINT32 q      = sc->dlp_ibe->params->q;
    const SINT32 q_bits = sc->dlp_ibe->params->q_bits;

    static const UINT8 id_nonce[16] = "SAFEcrypto nonce";

    // Generate a unique message digest
    oracle(sc, k, n, md);

    // Use the message digest as an IV for a CSPRNG
    prng_ctx_t *prng = prng_create(SC_ENTROPY_USER_PROVIDED,
        SC_PRNG_AES_CTR_DRBG, SC_PRNG_THREADING_NONE, 0x01000000);
    prng_set_entropy(prng, md, 64);
    prng_init(prng, id_nonce, 16);

    // Generate polynomial coefficients mod q from the CSPRNG
    prng_mem(prng, k, n>>3);

    // NOTE: Do not destroy the CSPRNG as it is used again!

    return prng;
}

// Use a random oracle output (i.e. a hash message digest) to
// create a byte sequence to be used as a one-time-pad.
static void k_function_xof(safecrypto_t *sc, UINT8 *k, size_t n)
{
    size_t i;
    UINT8 md[64];
    const UINT32 q      = sc->dlp_ibe->params->q;
    const SINT32 q_bits = sc->dlp_ibe->params->q_bits;

    UINT32 mask = (1 << q_bits) - 1;
    xof_init(sc->xof);
    xof_absorb(sc->xof, k, n);
    xof_final(sc->xof);
    xof_squeeze(sc->xof, k, n>>3);
}

#ifdef DISABLE_IBE_SERVER

SINT32 dlp_ibe_extract(safecrypto_t *sc, size_t idlen, const UINT8 *id,
    size_t *sklen, UINT8 **sk)
{
    return DC_FUNC_FAILURE;
}

#else // !DISABLE_IBE_SERVER

SINT32 dlp_ibe_extract(safecrypto_t *sc, size_t idlen, const UINT8 *id,
    size_t *sklen, UINT8 **sk)
{
    SINT32 retval = SC_FUNC_FAILURE;
    size_t i;
    UINT32 n, q, q_bits;
    SINT32 *f, *g, *F, *G;
    SINT32 *c, *v;
    LONGDOUBLE sig;
    gpv_t gpv;
    UINT32 gaussian_flags = 0;
#if defined(DLP_IBE_EFFICIENT_GAUSSIAN_SAMPLING)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_EFFICIENT;
#elif defined(DLP_IBE_GAUSSIAN_SAMPLE_MW_BOOTSTRAP)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP;
#endif

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // NOTE: The logic to detect already generated secret keys is assumed
    // to be external to the SAFEcrypto library. Otherwise we would need to
    // provide the storage logic in a generic manner that could be used in
    // a variety of different systems, for example callback functions would be
    // needed to check for the existance of a User Secret Key and load it.
    //
    // The implemented interface is such that a User must themselves check in
    // their implementation for the existance of a User Secret key and if not
    // present only then should the safecrypto_ibe_extract() function be called,
    // A User Secret Key must be provided to an instance of SAFEcrypto using the
    // safecrypto_set_id() function prior to any Encrypt or Decrypt operation.

    // Obtain all the constants and variables
    n        = sc->dlp_ibe->params->n;
    q        = sc->dlp_ibe->params->q;
    //q_bits   = sc->dlp_ibe->params->q_bits - 5;
    q_bits   = 6 * 1.17 * sqrt((DOUBLE)sc->dlp_ibe->params->q / (DOUBLE)(2*n));
    q_bits   = 8 + sc_ceil_log2(q_bits);


    f        = sc->privkey->key;
    g        = f + n;
    F        = g + n;
    G        = F + n;
    gpv.f    = f;
    gpv.g    = g;
    gpv.F    = F;
    gpv.G    = G;
    gpv.n    = n;

    c        = sc->temp;
    v        = sc->dlp_ibe->user_key;

    // Translate the ID into a polynomial using a random oracle
    id_function(sc, id, idlen, c);

    // Obtain the Gram Scmidt orthogonalisation of the polynomial basis
    GSO_TYPE *b_gs SC_DEFAULT_ALIGNED = NULL;
    GSO_TYPE *b_gs_inv_norm SC_DEFAULT_ALIGNED = NULL;

    if (0 == sc->dlp_ibe->keep_matrices) {
#ifdef DLP_IBE_EXPAND_BASIS
        gpv.b = SC_MALLOC(sizeof(SINT32) * 4*n*n);
        if (NULL == gpv.b) {
            SC_FREE(gpv.b, sizeof(SINT32) * 4*n*n);
            return SC_FUNC_FAILURE;
        }

        // Generate the polynomial basis matrix
        gpv_expand_basis(&gpv);
#endif

        b_gs     = SC_MALLOC(sizeof(GSO_TYPE) * (4*n*n + 2*n));
        if (NULL == b_gs) {
            SC_FREE(b_gs, sizeof(GSO_TYPE) * (4*n*n + 2*n));
            return SC_FUNC_FAILURE;
        }
        b_gs_inv_norm = b_gs + 4*n*n;

        // Gram-Schmidt orthogonolisation of the polynomial basis
        MODIFIED_GRAM_SCHMIDT(&gpv, b_gs, q);

        // Precompute the norm of each row of b_gs
        GPV_PRECOMPUTE_INV(b_gs, b_gs_inv_norm, 2*n);
    }
    else {
        gpv.b = sc->dlp_ibe->b;
        b_gs = sc->dlp_ibe->b_gs;
        b_gs_inv_norm = sc->dlp_ibe->b_gs_inv_norm;
    }

    // Generate a sampled polynomial using the polynomial basis
    sig = 2.0L / b_gs_inv_norm[0];
    SC_PRINT_DEBUG(sc, "Extract() sigma = %3.6Lf\n", sig);
#ifdef DLP_IBE_EXPAND_BASIS
    gaussian_lattice_sample(sc, &gpv, b_gs, b_gs_inv_norm, c, v, NULL, q, sig, gaussian_flags);
#else
    gaussian_lattice_sample_on_the_fly(sc, &gpv, b_gs, b_gs_inv_norm, c, v, q, sig);
#endif
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "id", id, idlen);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "sk", v, n);
    sc->sc_ntt->center_32(v, n, &sc->dlp_ibe->ntt);

    // Output an encoded byte stream representing the secret key SK
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
        .entropy_coder = NULL
    };
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &coding_raw,
        q_bits * n, NULL, 0, sk, sklen);
    if (NULL == packer) {
        goto finish;
    }
    entropy_poly_encode_32(packer, n, v, q_bits,
        SIGNED_COEFF, sc->coding_user_key.type, &sc->stats.components[SC_STAT_EXTRACT][0].bits_coded);
    sc->stats.components[SC_STAT_EXTRACT][0].bits += q_bits * n;
    utils_entropy.pack_get_buffer(packer, sk, sklen);
    utils_entropy.pack_destroy(&packer);

    retval = SC_FUNC_SUCCESS;

    // Gather statistics
    sc->stats.extract_num++;

finish:
    // Free all memory resources
    if (0 == sc->dlp_ibe->keep_matrices) {
        if (gpv.b) {
            SC_FREE(gpv.b, sizeof(SINT32) * 4*n*n);
        }
        if (b_gs) {
            SC_FREE(b_gs, sizeof(GSO_TYPE) * (4*n*n + 2*n));
        }
    }

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, 1 * n * sizeof(SINT32));

    return retval;
}

#endif // DISABLE_IBE_SERVER

#ifdef DISABLE_IBE_CLIENT

SINT32 dlp_ibe_secret_key(safecrypto_t *sc, size_t sklen, const UINT8 *sk)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 dlp_ibe_encrypt(safecrypto_t *sc,
    size_t idlen, const UINT8* id,
    size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 dlp_ibe_decrypt(safecrypto_t *sc, size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else // !DISABLE_IBE_CLIENT

SINT32 dlp_ibe_secret_key(safecrypto_t *sc, size_t sklen, const UINT8 *sk)
{
    if (NULL == sc          ||
        NULL == sk          ||
        NULL == sc->dlp_ibe ||
        NULL == sc->dlp_ibe->params) {
        return SC_FUNC_FAILURE;
    }

    size_t i;
    const UINT32 n      = sc->dlp_ibe->params->n;
    //const UINT32 q_bits = sc->dlp_ibe->params->q_bits - 5;
    UINT32 q_bits = 6 * 1.17 * sqrt((DOUBLE)sc->dlp_ibe->params->q / (DOUBLE)(2*n));
    q_bits        = 8 + sc_ceil_log2(q_bits);

    if (sklen > (n * q_bits + 7)>>3) {
        fprintf(stderr, "sklen is too big\n");
        return SC_FUNC_FAILURE;
    }

    // Store the assigned secret key
    sc_entropy_t sk_coding;
    sk_coding.type          = SC_ENTROPY_NONE;
    sk_coding.entropy_coder = NULL;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sk_coding,
        n * q_bits, sk, sklen, NULL, 0);
    entropy_poly_decode_32(packer, n, sc->dlp_ibe->user_key, q_bits,
        SIGNED_COEFF, sc->coding_user_key.type);

    /*for (i=0; i<n; i++) {
        UINT32 value;
        utils_entropy.pack_decode(packer, &value, q_bits);
        sc->dlp_ibe->user_key[i] = (SINT32) value;
    }*/
    utils_entropy.pack_destroy(&packer);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "dlp_ibe_set_id() sk decoded",
        sc->dlp_ibe->user_key, n);

    // Translate the secret key to the NTT "domain"
    sc->sc_ntt->fwd_ntt_32_32_large(sc->dlp_ibe->user_key + n,
        &sc->dlp_ibe->ntt, sc->dlp_ibe->user_key, sc->dlp_ibe->params->w);
    sc->sc_ntt->center_32(sc->dlp_ibe->user_key + n, n,
        &sc->dlp_ibe->ntt);

    return SC_FUNC_SUCCESS;
}

static void sparse_mul_mod_ring(SINT32 *r, const SINT32 *a, const SINT32 *b_sparse, size_t n)
{
    size_t j, k;
    SINT32 sparse[2*n-1] SC_DEFAULT_ALIGNED;

    // Reset the output to zero
    for (j=2*n-1; j--;) {
        sparse[j] = 0;
    }

    // Accumulate the a coefficients with the sparse b coefficient with the
    // knowledge that they only have the values -1, 0 or 1.
    for (j=0; j<n; j++) {
        if (b_sparse[j] < 0) {
            for (k=0; k<n; k++) {
                sparse[j+k] -= a[k];
            }
        }
        else if (b_sparse[j] > 0) {
            for (k=0; k<n; k++) {
                sparse[j+k] += a[k];
            }
        }
    }

    // Perform the ring modular reduction
    for (j=n; j--;) {
        r[j] = sparse[j] - sparse[j + n];
    }
}

SINT32 dlp_ibe_encrypt(safecrypto_t *sc,
    size_t idlen, const UINT8* id,
    size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    size_t i, j;
    UINT32 n, q2, q4, q_bits, l;
    SINT32 m_scale;
    SINT32 *h, *h_ntt;
    const SINT32 *w, *r;
    ntt_params_t *ntt;
    prng_ctx_t *k_prng;
    const utils_arith_ntt_t *sc_ntt;
    const utils_arith_poly_t *sc_poly;
    const utils_sampling_t *sc_gauss;
    SINT32 *e1, *e2, *e3, *c, *u, *v, *enc_k;
    UINT8 *k, *k2;
    const UINT8 *msg = from;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Assign values to commonly used variables
    n        = sc->dlp_ibe->params->n;
    q2       = sc->dlp_ibe->params->q >> 1;
    q4       = sc->dlp_ibe->params->q >> 2;
    q_bits   = sc->dlp_ibe->params->q_bits;
    l        = sc->dlp_ibe->params->l;
    m_scale  = sc->dlp_ibe->params->m_scale;
    w        = sc->dlp_ibe->params->w;
    r        = sc->dlp_ibe->params->r;
    ntt      = &sc->dlp_ibe->ntt;
    sc_ntt   = sc->sc_ntt;
    sc_poly  = sc->sc_poly;
    sc_gauss = sc->sc_gauss;

#ifdef SC_IBE_MESSAGE_LENGTH_N
    if (flen != (n >> 3)) {
        SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS);
        return SC_FUNC_FAILURE;
    }
#endif

    // Obtain pointers to the public key (NTT domain version)
    h        = (SINT32 *) sc->pubkey->key;
    h_ntt    = (SINT32 *) sc->pubkey->key + n;

    // Obtain pointers to temporary storage variables
    e1       = sc->temp;
    e2       = sc->temp +   n;
    e3       = sc->temp + 2*n;
    enc_k    = sc->temp + 3*n;
    u        = sc->temp + 4*n;
    v        = sc->temp + 5*n;
    c        = sc->temp + 6*n;
    k        = (UINT8*)(sc->temp + 7*n);
    k2       = k + n;

    // Create the bit packer used to create the output stream
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_encryption,
        n*(q_bits+q_bits-l) + flen*8, NULL, 0, to, tlen);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Translate the ID into a polynomial in the NTT domain using a random oracle
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "id", (UINT8*)id, idlen);
    id_function(sc, id, idlen, c);

    // Generate a random key for the KEM
    for (i=0; i<n; i+=32) {
        UINT32 rnd32 = prng_32(sc->prng_ctx[0]);
        for (j=0; j<32; j++) {
            k[i+j] = rnd32 & 0x1;
            rnd32 >>= 1;
        }
    }
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "KEM k", k, n);

    // Encoding of key
    SC_PRINT_DEBUG(sc, "Encoding %d bits\n", n);
    for (i=0; i<n; i++) {
        enc_k[i] = (k[i] & 0x1) * m_scale;
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Plaintext", enc_k, n);

    // Obtain uniform random values (e1,e2,r) <= {-1,0,1}^N
    for (i=0; i<n; i++) {
        UINT32 rand_bits = prng_var(sc->prng_ctx[0], 6);
        e1[i] = (SINT32)rand_bits & 0x1;
        rand_bits >>= 1;
        if (rand_bits & 0x1) e1[i] = -e1[i];
        rand_bits >>= 1;
        e2[i] = (SINT32)rand_bits & 0x1;
        rand_bits >>= 1;
        if (rand_bits & 0x1) e2[i] = -e2[i];
        rand_bits >>= 1;
        e3[i] = (SINT32)rand_bits & 0x1;
        rand_bits >>= 1;
        if (rand_bits & 0x1) e3[i] = -e3[i];
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Error distribution e1", e1, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Error distribution e2", e2, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Error distribution e3", e3, n);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "c", c, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "h", h, n);

    // NTT multiplications e3 * h and e3 * H(id)
#ifdef DLP_IBE_USE_SPARSE_MULTIPLICATION
#if 1
    if (sc->dlp_ibe->params->q_bits < 26 && 512 == n) {
        sc_ntt->fwd_ntt_32_32(e3, ntt, e3, w);
        sc->sc_ntt->mul_32_pointwise(u, ntt, e3, h_ntt);
        sc_ntt->inv_ntt_32_32(u, ntt, u, w, r);
    }
    else {
        sc_ntt->fwd_ntt_32_32_large(e3, ntt, e3, w);
        sc->sc_ntt->mul_32_pointwise(u, ntt, e3, h_ntt);
        sc_ntt->inv_ntt_32_32_large(u, ntt, u, w, r);
    }
    sc_ntt->fwd_ntt_32_32_large(c, ntt, c, w);
    sc->sc_ntt->mul_32_pointwise(v, ntt, e3, c);
    sc_ntt->inv_ntt_32_32_large(v, ntt, v, w, r);
#else
    if (sc->dlp_ibe->params->q_bits < 26) {
        sparse_mul_mod_ring(u, h, e3, n);
        sparse_mul_mod_ring(v, c, e3, n);
    }
    else {
        sc_ntt->fwd_ntt_32_32_large(e3, ntt, e3, w);
        sc_ntt->fwd_ntt_32_32_large(c, ntt, c, w);
        sc->sc_ntt->mul_32_pointwise(u, ntt, e3, h_ntt);
        sc->sc_ntt->mul_32_pointwise(v, ntt, e3, c);
        sc_ntt->inv_ntt_32_32_large(u, ntt, u, w, r);
        sc_ntt->inv_ntt_32_32_large(v, ntt, v, w, r);
    }
#endif
#else
    sc_ntt->fwd_ntt_32_32_large(e3, ntt, e3, w);
    sc_ntt->fwd_ntt_32_32_large(c, ntt, c, w);
    sc->sc_ntt->mul_32_pointwise(u, ntt, e3, h_ntt);
    sc->sc_ntt->mul_32_pointwise(v, ntt, e3, c);
    sc_ntt->inv_ntt_32_32_large(u, ntt, u, w, r);
    sc_ntt->inv_ntt_32_32_large(v, ntt, v, w, r);
#endif

    // u = e3 * h + e1
    for (i=0; i<n; i++) {
        sc_poly->add_32_scalar(u + i, n, q2);
    }
    sc_poly->add_single_32(u, n, e1);
    sc_ntt->normalize_32(u, n, ntt);
    for (i=0; i<n; i++) {
        sc_poly->sub_32_scalar(u + i, n, q2);
    }

    // u = e3 * H(id) + e2 + enc_k
    for (i=0; i<n; i++) {
        sc_poly->add_32_scalar(v + i, n, q2);
    }
    sc_poly->add_single_32(v, n, e2);
    sc_poly->add_single_32(v, n, enc_k);
    sc_ntt->normalize_32(v, n, ntt);
    for (i=0; i<n; i++) {
        sc_poly->sub_32_scalar(v + i, n, q2);
    }

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encrypt u", u, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encrypt v", v, n);

    // Generate the one-time-pad using a random oracle
#ifdef DLP_USE_RANDOM_ORACLE_CSPRNG
    k_prng = k_function_csprng(sc, k, n);
#else
    k_function_xof(sc, k, n);
#endif
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Message m", (UINT8*)from, n>>3);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "one-time-pad k", k, n>>3);

    // Bit packing
    for (i=0; i<n; i++) {
        v[i] >>= l;
    }
    entropy_poly_encode_32(packer, n, u, q_bits, SIGNED_COEFF,
        sc->coding_encryption.type, &packer->sc->stats.components[SC_STAT_ENCRYPT][0].bits_coded);
    entropy_poly_encode_32(packer, n, v, q_bits - l, SIGNED_COEFF,
        sc->coding_encryption.type, &packer->sc->stats.components[SC_STAT_ENCRYPT][1].bits_coded);

    // Decrypt the message in blocks of n/8 bytes
#ifdef SC_IBE_MESSAGE_LENGTH_N
    for (i=0; i<n>>3; i++) {
        k[i] ^= from[i];
    }
    entropy_poly_encode_8(packer, n>>3, k, 8, UNSIGNED_COEFF, SC_ENTROPY_NONE, NULL);
#else
    for (i=0, j=0; i<flen; i++) {
        k[j] ^= from[i];
        utils_entropy.pack_insert(packer, k[j], 8);

        j++;
        if ((n >> 3) == j) {
            j = 0;
            if (i != (flen - 1)) {
#ifdef DLP_USE_RANDOM_ORACLE_CSPRNG
                prng_mem(k_prng, k, n>>3);
#else
                xof_squeeze(sc->xof, k, n>>3);
#endif
            }
        }
    }
#endif
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "m ^ H(k)", k, n>>3);

    // Extracting buffer
    utils_entropy.pack_get_buffer(packer, to, tlen);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Ciphertext", *to, *tlen);
    utils_entropy.pack_destroy(&packer);

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, DLP_IBE_NUM_TEMP_POLYNOMIALS * n * sizeof(SINT32));

    // Gather statistics
    sc->stats.encrypt_num++;
    sc->stats.components[SC_STAT_ENCRYPT][0].bits += n * q_bits;
    sc->stats.components[SC_STAT_ENCRYPT][1].bits += n * (q_bits - l);
    sc->stats.components[SC_STAT_ENCRYPT][2].bits += flen * 8;
    sc->stats.components[SC_STAT_ENCRYPT][3].bits += n * (q_bits + q_bits - l) + 8 * flen;
    sc->stats.components[SC_STAT_ENCRYPT][2].bits_coded += flen * 8;
    sc->stats.components[SC_STAT_ENCRYPT][3].bits_coded += *tlen * 8;

#ifdef DLP_USE_RANDOM_ORACLE_CSPRNG
    // Destroy the CSPRNG created by k_function()
    prng_destroy(k_prng);
#endif

    return SC_FUNC_SUCCESS;
}

SINT32 dlp_ibe_decrypt(safecrypto_t *sc, size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    size_t i, j;
    UINT32 n, q, q2, q4, q_bits, l;
    const SINT32 *w, *r;
    ntt_params_t *ntt;
    prng_ctx_t *k_prng;
    const utils_arith_ntt_t *sc_ntt;
    const utils_arith_poly_t *sc_poly;
    utils_sampling_t *sc_gauss;
    SINT32 *u, *v;
    SINT32 *sk;
    UINT8 *k, *c;
    const UINT8 *msg = from;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Assign values to commonly used variables
    n         = sc->dlp_ibe->params->n;
    q         = sc->dlp_ibe->params->q;
    q2        = sc->dlp_ibe->params->q >> 1;
    q4        = sc->dlp_ibe->params->q >> 2;
    q_bits    = sc->dlp_ibe->params->q_bits;
    l         = sc->dlp_ibe->params->l;
    w         = sc->dlp_ibe->params->w;
    r         = sc->dlp_ibe->params->r;
    ntt       = &sc->dlp_ibe->ntt;
    sc_ntt    = sc->sc_ntt;
    sc_poly   = sc->sc_poly;
    sc_gauss  = sc->sc_gauss;

    // Obtain a pointer to the user secret key
    sk        = sc->dlp_ibe->user_key + n;

    // Obtain pointers to temporary storage variables
    u         = sc->temp;
    v         = u + n;
    k         = (UINT8*)(v + n);
    c         = k + n;

    // Decompress the ciphertext
    sc_packer_t *ipacker;
    ipacker = utils_entropy.pack_create(sc, &sc->coding_encryption,
        0, from, flen, NULL, 0);
    if (NULL == ipacker) {
        return SC_FUNC_FAILURE;
    }
    entropy_poly_decode_32(ipacker, n, u, q_bits,
        SIGNED_COEFF, sc->coding_encryption.type);
    entropy_poly_decode_32(ipacker, n, v, q_bits - l,
        SIGNED_COEFF, sc->coding_encryption.type);
    for (i=0; i<n; i++) {
        v[i] <<= l;
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received u", u, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received v", v, n);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Received c", c, n>>3);

    // Derive the key k from the input message u and v polynomials
    if (sc->dlp_ibe->params->q_bits < 26 && 512 == n) {
        sc_ntt->fwd_ntt_32_32(u, ntt, u, w);
        sc->sc_ntt->mul_32_pointwise(u, ntt, u, sk);
        sc_ntt->inv_ntt_32_32(u, ntt, u, w, r);
    }
    else {
        sc_ntt->fwd_ntt_32_32_large(u, ntt, u, w);
        sc->sc_ntt->mul_32_pointwise(u, ntt, u, sk);
        sc_ntt->inv_ntt_32_32_large(u, ntt, u, w, r);
    }
    sc_poly->sub_single_32(v, n, u);
    sc_ntt->normalize_32(v, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "k (unscaled)", v, n);

    for (i=0; i<n; i++) {
        SINT32 v_rnd = v[i] + q4;
        k[i] = (v_rnd >= q2 && v_rnd < q)? 1 : 0;
    }
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "KEM k", k, n);

    // Generate the one-time-pad using a random oracle
#ifdef DLP_USE_RANDOM_ORACLE_CSPRNG
    k_prng = k_function_csprng(sc, k, n);
#else
    k_function_xof(sc, k, n);
#endif
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "one-time-pad k", k, n>>3);

    // Create the output byte stream
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
        .entropy_coder = NULL
    };
    sc_packer_t *opacker;
    opacker = utils_entropy.pack_create(sc, &coding_raw,
        flen * 8, NULL, 0, to, tlen);
    if (NULL == opacker) {
        goto finish;
    }

    // Decode the message
#ifdef SC_IBE_MESSAGE_LENGTH_N
    for (i=0; i<n>>3; i++) {
        UINT32 temp;
        utils_entropy.pack_remove(ipacker, &temp, 8);
        temp ^= k[i];
        utils_entropy.pack_insert(opacker, temp, 8);
    }
#else
    size_t mask = (n >> 3) - 1;
    j = 0;
    while (utils_entropy.pack_is_data_avail(ipacker)) {
        if (j > 0) {
#ifdef DLP_USE_RANDOM_ORACLE_CSPRNG
            prng_mem(k_prng, k, n>>3);
#else
            xof_squeeze(sc->xof, k, n>>3);
#endif
        }
        j++;

        for (i=0; i<n>>3; i++) {
            UINT32 temp;
            utils_entropy.pack_remove(ipacker, &temp, 8);
            temp ^= k[i];
            utils_entropy.pack_insert(opacker, temp, 8);
        }
    }
#endif
    utils_entropy.pack_get_buffer(opacker, to, tlen);
    utils_entropy.pack_destroy(&opacker);
    utils_entropy.pack_destroy(&ipacker);

    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Message m", *to, *tlen);

    // Gather statistics
    sc->stats.decrypt_num++;

finish:
    SC_MEMZERO(sc->temp, DLP_IBE_NUM_TEMP_POLYNOMIALS * n * sizeof(SINT32));

#ifdef DLP_USE_RANDOM_ORACLE_CSPRNG
    prng_destroy(k_prng);
#endif

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_IBE_CLIENT

char * dlp_ibe_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I", "II", "III", "IV", "V"};
    static char stats[2048];
    snprintf(stats, 2047, "\nDLP-IBE-%s (q=%d [%d-bit], N=%d, l=%d)\n\
    KeyGen       %" FMT_LIMB " key-pairs  / %8" FMT_LIMB " trials\n\
    Extract      %8" FMT_LIMB "\n\
    Encryption   %8" FMT_LIMB "\n\
    Decryption   %8" FMT_LIMB "\n\n\
    Sampler:         %s\n\
    PRNG:            %s\n\
    Oracle Hash:     %s\n\n\
    Public Key compression:      %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       h       %10.2f%13.2f%16.3f%%\n\n\
    Private Key compression:     %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       f       %10.2f%13.2f%16.3f%%\n\
       g       %10.2f%13.2f%16.3f%%\n\
       F       %10.2f%13.2f%16.3f%%\n\
       G       %10.2f%13.2f%16.3f%%\n\
       total   %10.2f%13.2f%16.3f%%\n\n\
    User Secret Key compression: %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       sk      %10.2f%13.2f%16.3f%%\n\n\
    Encryption compression:      %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       u       %10.2f%13.2f%16.3f%%\n\
       v       %10.2f%13.2f%16.3f%%\n\
       m       %10.2f%13.2f%16.3f%%\n\
       total   %10.2f%13.2f%16.3f%%\n\n",
        param_set_name[sc->dlp_ibe->params->set],
        sc->dlp_ibe->params->q,
        sc->dlp_ibe->params->q_bits,
        sc->dlp_ibe->params->n,
        sc->dlp_ibe->params->l,
        sc->stats.keygen_num,
        sc->stats.keygen_num_trials,
        sc->stats.extract_num,
        sc->stats.encrypt_num,
        sc->stats.decrypt_num,
        sc_sampler_names[sc->sampling],
        safecrypto_prng_names[(int)prng_get_type(sc->prng_ctx[0])],
        crypto_hash_names[sc->dlp_ibe->params->hash_type],
        sc_entropy_names[(int)sc->coding_pub_key.type],
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits : 0,
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
        sc_entropy_names[(int)sc->coding_user_key.type],
        sc->stats.extract_num? (DOUBLE)sc->stats.components[SC_STAT_EXTRACT][0].bits/(DOUBLE)sc->stats.extract_num : 0,
        sc->stats.extract_num? (DOUBLE)sc->stats.components[SC_STAT_EXTRACT][0].bits_coded/(DOUBLE)sc->stats.extract_num : 0,
        sc->stats.extract_num? 100 * (DOUBLE)sc->stats.components[SC_STAT_EXTRACT][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_EXTRACT][0].bits : 0,
        sc_entropy_names[(int)sc->coding_encryption.type],
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits/(DOUBLE)sc->stats.encrypt_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits_coded/(DOUBLE)sc->stats.encrypt_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits/(DOUBLE)sc->stats.encrypt_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits_coded/(DOUBLE)sc->stats.encrypt_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits/(DOUBLE)sc->stats.encrypt_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits_coded/(DOUBLE)sc->stats.encrypt_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][3].bits/(DOUBLE)sc->stats.encrypt_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][3].bits_coded/(DOUBLE)sc->stats.encrypt_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][3].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][3].bits);
    return stats;
}


#undef FMT_LIMB
