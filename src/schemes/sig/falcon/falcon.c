/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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

#include "schemes/sig/falcon/falcon.h"
#include "falcon_params.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/xof.h"
#include "utils/crypto/prng.h"
#include "utils/arith/arith.h"
#include "utils/arith/sc_math.h"
#include "utils/arith/sc_poly_mpz.h"
#include "utils/arith/poly_fft.h"
#include "utils/arith/gpv.h"
#include "utils/entropy/packer.h"
#include "utils/entropy/entropy.h"
#include "utils/sampling/sampling.h"

#include "utils/arith/internal.h"
#include "utils/arith/gpv.h"

#include <math.h>

#define FALCON_NUM_TEMP     8

#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif

#define M1_BITS(b)  ((b) - 1)


SINT32 falcon_sig_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
	FLOAT sig;

	if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 1, 4, 1, 0, 0, 0)) {
        return SC_FUNC_FAILURE;
    }

    // Allocate memory for FALCON signature configuration
    sc->falcon = SC_MALLOC(sizeof(falcon_cfg_t));
    if (NULL == sc->falcon) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_priv_key.type            =
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN)? SC_ENTROPY_HUFFMAN_STATIC :
                                                SC_ENTROPY_NONE;
    sc->coding_signature.type           =
        (flags[0] & SC_FLAG_0_ENTROPY_HUFFMAN)? SC_ENTROPY_HUFFMAN_STATIC :
                                                SC_ENTROPY_NONE;
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

    SC_PRINT_DEBUG(sc, "FALCON");

    // Initialise the SAFEcrypto struct with the specified ENS/DLP signature parameter set
    switch (set)
    {
        case 0:  sc->falcon->params  = &param_falcon_0;
                 sc->falcon->entropy = sc->coding_signature.type;
                 break;
        /*case 1:  sc->falcon->params  = &param_falcon_1;
                 sc->falcon->entropy = sc->coding_signature.type;
                 break;*/
        case 2:  sc->falcon->params  = &param_falcon_2;
                 sc->falcon->entropy = sc->coding_signature.type;
                 break;
        default: SC_FREE(sc->falcon, sizeof(falcon_cfg_t));
                 SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS);
                 return SC_FUNC_FAILURE;
    }

    // Obtain parameters for the selected parameter set
    UINT16 n     = sc->falcon->params->n;
    UINT16 kappa = sc->falcon->params->kappa;

    // Set a flag to indicate if the B and B_gs matrices (and the norm of
    // each B_gs row) are to be computed and stored.
    sc->falcon->keep_matrices = 1;
    sc->falcon->b             = NULL;
    sc->falcon->b_gs          = NULL;
    sc->falcon->b_gs_inv_norm = NULL;

    // Initialise the reduction scheme
    sc->falcon->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_BARRETT)?   SC_NTT_BARRETT :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->falcon->ntt, n, sc->falcon->params->q);

    // Create pointers for the arithmetic functions used by ENS/DLP
    sc->sc_ntt = utils_arith_ntt(sc->falcon->ntt_optimisation);
    sc->sc_poly = utils_arith_poly();
    sc->sc_vec = utils_arith_vectors();

    // Configure the hashing algorithm to be used for the random oracle.
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

    sc_hash_e hash_func;
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
            hash_func = sc->falcon->params->hash_type;
        }
    }

    // Create the hash to be used by the random oracle
    sc->falcon->oracle_hash = hash_func;
    sc->hash = utils_crypto_hash_create(hash_func);
    if (NULL == sc->hash) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Create the XOF to be used by the random oracle
    sc->xof = utils_crypto_xof_create(SC_XOF_SHAKE128);
    if (NULL == sc->xof) {
        return SC_FUNC_FAILURE;
    }

    // Retrieve the Gaussian Sampler standard deviation
    sig = 1.17 * sqrt(sc->falcon->params->q / (2*n));

    // Precompute any variables for the random distribution sampler
    sc->sc_gauss = create_sampler(sc->sampling,
        sc->sampling_precision, sc->blinding, n, SAMPLING_DISABLE_BOOTSTRAP,
        sc->prng_ctx[0], 10.0f, sig);

#ifdef USE_RUNTIME_NTT_TABLES
    // Dynamically allocate memory for the necessary NTT tables
    SINT16 *temp = (SINT16*) SC_MALLOC(sizeof(SINT16) * 2 * n);
    if (NULL == temp) {
        utils_crypto_hash_destroy(sc->hash);
        utils_crypto_xof_destroy(sc->xof);
        destroy_sampler(&sc->sc_gauss);
        SC_FREE(sc->falcon, sizeof(falcon_cfg_t));
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    sc->falcon->params->w = temp;
    sc->falcon->params->r = temp + n;
    SINT32 retval = roots_of_unity_s16(sc->falcon->params->w, sc->falcon->params->r,
        n, sc->falcon->params->q, 0);
#endif

    // Dynamically allocate memory for temporary storage
    sc->temp_size = (FALCON_NUM_TEMP * n + kappa) * sizeof(SINT32) + 4 * n * sizeof(DOUBLE);
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            utils_crypto_hash_destroy(sc->hash);
            utils_crypto_xof_destroy(sc->xof);
            destroy_sampler(&sc->sc_gauss);
            SC_FREE(sc->falcon, sizeof(falcon_cfg_t));
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT16) * 2 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

	return SC_FUNC_SUCCESS;
}

SINT32 falcon_sig_destroy(safecrypto_t *sc)
{
	UINT16 n, kappa;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->falcon->params->n;
    kappa = sc->falcon->params->kappa;

    destroy_sampler(&sc->sc_gauss);

    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

    // Free all resources associated with key-pair and signature
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT16));
        sc->pubkey->len = 0;
    }

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->falcon->params->w, sizeof(SINT16) * 2 * n);
#endif

    // Free resources associated with the polynomial basis
    if (sc->falcon->keep_matrices) {
        if (sc->falcon->b) {
            SC_FREE(sc->falcon->b, sizeof(SINT32) * 4 * n * n);
        }
#ifdef FALCON_USE_LONGDOUBLE_PREC_FLOATS
        if (sc->falcon->b_gs) {
            SC_FREE(sc->falcon->b_gs, sizeof(LONGDOUBLE) * 4 * n * n);
        }
        if (sc->falcon->b_gs_inv_norm) {
            SC_FREE(sc->falcon->b_gs_inv_norm, sizeof(LONGDOUBLE) * 2 * n);
        }
#else
#ifdef FALCON_USE_DOUBLE_PREC_FLOATS
        if (sc->falcon->b_gs) {
            SC_FREE(sc->falcon->b_gs, sizeof(DOUBLE) * 4 * n * n);
        }
        if (sc->falcon->b_gs_inv_norm) {
            SC_FREE(sc->falcon->b_gs_inv_norm, sizeof(DOUBLE) * 2 * n);
        }
#else
        if (sc->falcon->b_gs) {
            SC_FREE(sc->falcon->b_gs, sizeof(FLOAT) * 4 * n * n);
        }
        if (sc->falcon->b_gs_inv_norm) {
            SC_FREE(sc->falcon->b_gs_inv_norm, sizeof(FLOAT) * 2 * n);
        }
#endif
#endif
    }

    utils_crypto_hash_destroy(sc->hash);
    utils_crypto_xof_destroy(sc->xof);

    if (sc->falcon) {
        SC_FREE(sc->falcon, sizeof(falcon_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "FALCON Signature algorithm destroyed");

    return SC_FUNC_SUCCESS;
}

static SINT32 create_gpv_matrices(safecrypto_t *sc, gpv_t *gpv, UINT32 q, UINT32 n)
{
    if (sc->falcon->b) {
        SC_FREE(sc->falcon->b, sizeof(SINT32) * 4 * n * n);
    }
    sc->falcon->b = SC_MALLOC(sizeof(SINT32) * 4 * n * n);
#ifdef FALCON_USE_LONGDOUBLE_PREC_FLOATS
    if (sc->falcon->b_gs) {
        SC_FREE(sc->falcon->b_gs, sizeof(LONGDOUBLE) * 4 * n * n);
    }
    if (sc->falcon->b_gs_inv_norm) {
        SC_FREE(sc->falcon->b_gs_inv_norm, sizeof(LONGDOUBLE) * 2 * n);
    }
    sc->falcon->b_gs = SC_MALLOC(sizeof(LONGDOUBLE) * 4 * n * n);
    sc->falcon->b_gs_inv_norm = SC_MALLOC(sizeof(LONGDOUBLE) * 2 * n);
#else
#ifdef FALCON_USE_DOUBLE_PREC_FLOATS
    if (sc->falcon->b_gs) {
        SC_FREE(sc->falcon->b_gs, sizeof(DOUBLE) * 4 * n * n);
    }
    if (sc->falcon->b_gs_inv_norm) {
        SC_FREE(sc->falcon->b_gs_inv_norm, sizeof(DOUBLE) * 2 * n);
    }
    sc->falcon->b_gs = SC_MALLOC(sizeof(DOUBLE) * 4 * n * n);
    sc->falcon->b_gs_inv_norm = SC_MALLOC(sizeof(DOUBLE) * 2 * n);
#else
    if (sc->falcon->b_gs) {
        SC_FREE(sc->falcon->b_gs, sizeof(FLOAT) * 4 * n * n);
    }
    if (sc->falcon->b_gs_inv_norm) {
        SC_FREE(sc->falcon->b_gs_inv_norm, sizeof(FLOAT) * 2 * n);
    }
    sc->falcon->b_gs = SC_MALLOC(sizeof(FLOAT) * 4 * n * n);
    sc->falcon->b_gs_inv_norm = SC_MALLOC(sizeof(FLOAT) * 2 * n);
#endif
#endif
    gpv->b = sc->falcon->b;

    // Generate the polynomial basis matrix
    gpv_expand_basis(gpv);

    // Gram-Schmidt orthogonolisation of the polynomial basis and
    // precompute the norm of each row of b_gs
#ifdef FALCON_USE_LONGDOUBLE_PREC_FLOATS
    modified_gram_schmidt_fast_ldbl(gpv, sc->falcon->b_gs, q);
    gpv_precompute_inv_ldbl(sc->falcon->b_gs, sc->falcon->b_gs_inv_norm, 2*n);
#else
#ifdef FALCON_USE_DOUBLE_PREC_FLOATS
    modified_gram_schmidt_fast_dbl(gpv, sc->falcon->b_gs, q);
    gpv_precompute_inv_dbl(sc->falcon->b_gs, sc->falcon->b_gs_inv_norm, 2*n);
#else
    modified_gram_schmidt_fast_flt(gpv, sc->falcon->b_gs, q);
    gpv_precompute_inv_flt(sc->falcon->b_gs, sc->falcon->b_gs_inv_norm, 2*n);
#endif
#endif

    return SC_FUNC_SUCCESS;
}

SINT32 falcon_sig_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, q_bits;
    SINT32 *h, *h_ntt;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->falcon->params->n;
    q_bits = sc->falcon->params->q_bits;
    h      = sc->temp;
    h_ntt  = h + n;


    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT16));
    }
    sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
    if (NULL == sc->pubkey->key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Create a bit packer to extract the public key from the buffer
    SINT16 *pubkey = (SINT16 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, key, key_len, NULL, 0);
    if (NULL == packer) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT16));
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_decode_16(packer, n, pubkey, q_bits,
        UNSIGNED_COEFF, sc->coding_pub_key.type, 0);
    utils_entropy.pack_destroy(&packer);
    sc->pubkey->len = n;

    // Store an NTT domain version of the public key
    for (i=n; i--;) {
        h[i] = pubkey[i];
    }
    sc->sc_ntt->fwd_ntt_32_16_large(h_ntt, &sc->falcon->ntt,
        h, sc->falcon->params->w);
    sc->sc_ntt->normalize_32(h_ntt, n, &sc->falcon->ntt);
    for (i=n; i--;) {
        pubkey[i + n] = h_ntt[i];
    }

    SC_MEMZERO(sc->temp, 2 * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;
}

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 falcon_sig_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 falcon_sig_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    UINT16 n;
    SINT32 fg_bits, FG_bits;

    n       = sc->falcon->params->n;
    fg_bits = sc->falcon->params->fg_bits;
    FG_bits = sc->falcon->params->FG_bits;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
        sc->privkey->len = 0;
    }
    sc->privkey->key = SC_MALLOC(4 * n * sizeof(SINT32));
    if (NULL == sc->privkey->key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Create a bit packer to extract the private key polynomials f and g from the buffer
    SINT32 *privkey = (SINT32 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        2 * n * (fg_bits + FG_bits), key, key_len, NULL, 0);
    if (NULL == packer) {
        SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
        sc->privkey->len = 0;
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_decode_32(packer, n, privkey, fg_bits,
        SIGNED_COEFF, sc->coding_priv_key.type, 1);
    entropy_poly_decode_32(packer, n, privkey+n, fg_bits,
        SIGNED_COEFF, sc->coding_priv_key.type, 1);
    entropy_poly_decode_32(packer, n, privkey+2*n, FG_bits,
        SIGNED_COEFF, SC_ENTROPY_NONE, 2);
    entropy_poly_decode_32(packer, n, privkey+3*n, FG_bits,
        SIGNED_COEFF, SC_ENTROPY_NONE, 2);
    utils_entropy.pack_destroy(&packer);

    sc->privkey->len = 4* n;

    // Reconstruct the GPV matrices if necessary
    if (sc->falcon->keep_matrices) {
        size_t i;
        gpv_t gpv;
        SINT32 *t = sc->temp;
        for (i=0; i<4*n; i++) {
            t[i] = privkey[i];
        }

        gpv.f = t;
        gpv.g = t+n;
        gpv.F = t+2*n;
        gpv.G = t+3*n;
        gpv.n = n;
        create_gpv_matrices(sc, &gpv, sc->falcon->params->q, n);

        SC_MEMZERO(t, 4 * n * sizeof(SINT32));
    }

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_CLIENT

#ifdef DISABLE_SIGNATURES_SERVER

SINT32 falcon_sig_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 falcon_sig_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 falcon_sig_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
	UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n      = sc->falcon->params->n;
    q_bits = sc->falcon->params->q_bits;

    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += n * q_bits;

    // Create a bit packer to compress the public key
    SINT16 *pubkey = (SINT16 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_16(packer, n, pubkey, q_bits, UNSIGNED_COEFF,
        SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

SINT32 falcon_sig_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
	UINT16 n;
	SINT32 fg_bits, FG_bits;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n       = sc->falcon->params->n;
    fg_bits = sc->falcon->params->fg_bits;
    FG_bits = sc->falcon->params->FG_bits;

    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += n * fg_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][1].bits += n * fg_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][2].bits += n * FG_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][3].bits += n * FG_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][4].bits += 2 * n * (fg_bits + FG_bits);

    // Create a bit packer to compress the private key polynomials f and g
    SINT32 *privkey = (SINT32 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        2 * n * (fg_bits + FG_bits), NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Encode the four polynomials f, g, F, G
    entropy_poly_encode_32(packer, n, privkey, fg_bits, SIGNED_COEFF,
        sc->coding_priv_key.type, 1, &sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);
    entropy_poly_encode_32(packer, n, privkey+n, fg_bits, SIGNED_COEFF,
        sc->coding_priv_key.type, 1, &sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded);
    entropy_poly_encode_32(packer, n, privkey+2*n, FG_bits, SIGNED_COEFF,
        SC_ENTROPY_NONE, 2, &sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded);
    entropy_poly_encode_32(packer, n, privkey+3*n, FG_bits, SIGNED_COEFF,
        SC_ENTROPY_NONE, 2, &sc->stats.components[SC_STAT_PRIV_KEY][3].bits_coded);

    // Extract the buffer with the polynomial g and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PRIV_KEY][4].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_SERVER

static SINT32 check_norm_bd(FLOAT bd, const SINT32 *s1, const SINT32 *s2, size_t n)
{
    size_t i;
#ifdef FALCON_USE_LONGDOUBLE_PREC_FLOATS
    LONGDOUBLE norm = 0;
    for (i=n; i--;) {
        norm += s1[i] * s1[i] + s2[i] * s2[i];
    }
    norm = sqrtl(norm);
#else
#ifdef FALCON_USE_DOUBLE_PREC_FLOATS
    DOUBLE norm = 0;
    for (i=n; i--;) {
        norm += s1[i] * s1[i] + s2[i] * s2[i];
    }
    norm = sqrt(norm);
#else
    FLOAT norm = 0;
    for (i=n; i--;) {
        norm += s1[i] * s1[i] + s2[i] * s2[i];
    }
    norm = sqrtf(norm);
#endif
#endif

    fprintf(stderr, "norm = %3.3f\n", norm);

    return (norm >= bd)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}

// A random oracle that generates a fixed length random number sequence
// if given a variable length unique user ID.
static void oracle_csprng(safecrypto_t *sc, const UINT8 *msg, size_t msg_len, UINT8 *md)
{
    hash_init(sc->hash);
    hash_update(sc->hash, msg, msg_len);
    hash_final(sc->hash, md);
}

// A random oracle that generates a fixed length random number sequence
// if given a variable length unique user ID.
static void oracle_xof(safecrypto_t *sc, const UINT8 *msg, size_t msg_len)
{
    xof_init(sc->xof);
    xof_absorb(sc->xof, msg, msg_len);
    xof_final(sc->xof);
}

// Use a random oracle output (i.e. a hash message digest) to
// create a ring polynomial that uniquely represents a binary message.
static void h_function_csprng(safecrypto_t *sc, const UINT8 *md, SINT32 *c, size_t n)
{
    size_t i;
    const SINT32 q      = sc->falcon->params->q;
    const SINT32 q_bits = sc->falcon->params->q_bits;

    static const UINT8 h_nonce[16] = "SAFEcrypto nonce";

    // Use the message digest as an IV for a CSPRNG
    prng_ctx_t *prng = prng_create(SC_ENTROPY_USER_PROVIDED,
        SC_PRNG_AES_CTR_DRBG, SC_PRNG_THREADING_NONE, 0x01000000);
    prng_set_entropy(prng, md, 64);
    prng_init(prng, h_nonce, 16);

    // Generate polynomial coefficients mod q from the CSPRNG
    for (i=0; i<n; i++) {
        c[i] = prng_var(prng, q_bits);
        if (c[i] >= q) {
            c[i] -= q;
        }
    }

    // Free the CSPRNG resources
    prng_destroy(prng);
}

// Use a random oracle output (i.e. a hash message digest) to
// create a ring polynomial that uniquely represents a binary message.
static void h_function_xof(safecrypto_t *sc, SINT32 *c, size_t n)
{
    size_t i;
    const SINT32 q      = sc->falcon->params->q;
    const SINT32 q_bits = sc->falcon->params->q_bits;

    for (int j=0; j < n/32; j++){
	    SINT32 c_tmp[32];
        UINT32 mask = (1 << q_bits) - 1;
        xof_squeeze(sc->xof, c_tmp, 32 *sizeof(SINT32));

        // Generate polynomial coefficients mod q from the CSPRNG
        for (i=0; i<32; i++) {
            c_tmp[i] &= mask;
            c_tmp[i] -= ((UINT32)(q - c_tmp[i]) >> 31) * q;
	        c[j*32 + i] = c_tmp[i];
        }
	}
}

static void small_mul_mod_ring(SINT32 *r, const SINT32 *a, const SINT16 *b_sparse,
    size_t n, UINT32 q, SINT32 *sparse)
{
    size_t j, k;

    // Reset the output to zero
    for (j=2*n-1; j--;) {
        sparse[j] = 0;
    }

    // Accumulate the a coefficients with the sparse b coefficient with the
    // knowledge that they only have the values -1, 0 or 1.
    for (j=0; j<n; j++) {
        for (k=0; k<n; k++) {
            sparse[j+k] += a[k] * b_sparse[j];
        }
    }

    // Perform the ring modular reduction
    for (j=n; j--;) {
        r[j] = sparse[j] - sparse[j + n];
    }
}

SINT32 falcon_sig_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv)
{
    return SC_FUNC_FAILURE;
}

SINT32 falcon_sig_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv)
{
    return SC_FUNC_FAILURE;
}

#ifdef DISABLE_SIGNATURES_SERVER

SINT32 falcon_sig_keygen(safecrypto_t *sc)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 falcon_sig_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

/*static SINT32 get_gso(safecrypto_t *sc, UINT32 n, SINT32 q, gpv_t *gpv, SINT32 **b, GSO_TYPE **b_gs, GSO_TYPE **b_gs_inv_norm)
{
    // Obtain the Gram Scmidt orthogonalisation of the polynomial basis
    if (0 == sc->falcon->keep_matrices) {
        *b    = SC_MALLOC(sizeof(SINT32) * 4*n*n);
        if (NULL == *b) {
            SC_FREE(*b, sizeof(SINT32) * 4*n*n);
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
        *b_gs = SC_MALLOC(sizeof(GSO_TYPE) * (4*n*n + 2*n));
        if (NULL == *b_gs) {
            SC_FREE(*b_gs, sizeof(GSO_TYPE) * (4*n*n + 2*n));
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
        *b_gs_inv_norm = *b_gs + 4*n*n;
        gpv->b = *b;

        // Generate the polynomial basis matrix
        gpv_expand_basis(gpv);

        // Gram-Schmidt orthogonolisation of the polynomial basis
        // and precompute the norm of each row of b_gs
        modified_gram_schmidt(gpv, *b_gs, q);
        gpv_precompute_inv(*b_gs, *b_gs_inv_norm, 2*n);
    }
    else {
        gpv->b         = sc->falcon->b;
        *b             = sc->falcon->b;
        *b_gs          = sc->falcon->b_gs;
        *b_gs_inv_norm = sc->falcon->b_gs_inv_norm;
    }
} */

static FLOAT get_std_dev(SINT32 *s, size_t n)
{
    size_t i;
    FLOAT mean = 0, sd = 0;

    // Calculate the mean
    for (i=0; i<n; i++) {
        mean += s[i];
    }
    mean /= n;

    // Calculate the standard deviation
    for (i=0; i<n; i++) {
        FLOAT temp = s[i] - mean;
        sd += temp * temp;
    }
    sd /= n - 1;

    return sd;
}

/* start of imported FALCON functions*****
 * Convert an integer polynomial (with small values) into the
 * representation with complex numbers.
 */

static inline size_t
skoff_b00(unsigned logn, unsigned ter)
{
	(void)logn;
	(void)ter;
	return 0;
}

static inline size_t
skoff_b01(unsigned logn, unsigned ter)
{
	return (1 + ((ter) << 1)) << ((logn) - (ter));
}

static inline size_t
skoff_b10(unsigned logn, unsigned ter)
{
	return 2 * (1 + ((ter) << 1)) << ((logn) - (ter));
}

static inline size_t
skoff_b11(unsigned logn, unsigned ter)
{
	return 3 * (1 + ((ter) << 1)) << ((logn) - (ter));
}

static inline size_t
skoff_tree(unsigned logn, unsigned ter)
{
	return 4 * (1 + ((ter) << 1)) << ((logn) - (ter));
}

static void
LDL_fft(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g01,
	const DOUBLE *restrict g11, unsigned logn, DOUBLE *restrict tmp)
{
	size_t n;
	n = (1 + ((0) << 1)) << (logn) - (0);
	/* Let tmp = mu = G[0,1] / G[0,0]. */
	memcpy(tmp, g01, n * sizeof *g01);
/*for(int i=0; i<n; i++){
  fprintf(stderr, "temp=g01: %3.0f \n", tmp[i]);
}
for(int i=0; i<n; i++){
  fprintf(stderr, "g00: %3.0f \n", g00[i]);
}*/
	falcon_poly_div_fft(tmp, g00, logn);
//fprintf(stderr, "temp=g01/g00: %3.0f \n", tmp[0]);
//exit(-1); //so only test first call
	/* Let L[1,0] = adj(mu) and tmp = aux = mu * adj(mu). */
	memcpy(l10, tmp, n * sizeof *tmp);
	falcon_poly_adj_fft(l10, logn);
	falcon_poly_mul_fft(tmp, l10, logn);
//fprintf(stderr, "temp*l10: %3.0f \n", tmp[0]); //blows up
	/* D[1,1] = G[1,1] - aux * G[0][0]. */
	falcon_poly_mul_fft(tmp, g00, logn);
	memcpy(d11, g11, n * sizeof *g11);
	falcon_poly_sub_fft(d11, tmp, logn);
}


/*
 * Special case of LDL when G is quasicyclic, i.e. g11 == g00.
 */
static inline void
LDLqc_fft(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g01, unsigned logn,
	DOUBLE *restrict tmp)
{
//fprintf(stderr, "qc CALLING LDL_fft \n");
	LDL_fft(d11, l10, g00, g01, g00, logn, tmp);
}


/*
void
falcon_poly_adj_fft(DOUBLE *a, unsigned logn)
{
	size_t n, u;

	n = (size_t)1 << logn;
	for (u = (n >> 1); u < n; u ++) {
		a[u] = -a[u];
	}
}

void
falcon_poly_sub(DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, u;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		a[u] = a[u]- b[u];
	}
}
*/

static void
smallints_to_double(DOUBLE *r, const SINT32 *t, unsigned logn, unsigned ter)
{
	size_t n, u;

	n = ((size_t)(1 + ((ter) << 1)) << ((logn) - (ter)));
	for (size_t u = 0; u < n; u ++) {
		r[u] = (DOUBLE)(t[u]);
	}
}


unsigned
ffLDL_treesize(unsigned logn)
{
	/*
	 * For logn = 0 (polynomials are constant), the "tree" is a
	 * single element. Otherwise, the tree node has size 2^logn, and
	 * has two child trees for size logn-1 each. Thus, treesize s()
	 * must fulfill these two relations:
	 *
	 *   s(0) = 1
	 *   s(logn) = (2^logn) + 2*s(logn-1)
	 */
	return (logn + 1) << logn;
}

static void
ffLDL_fft_inner(DOUBLE *restrict tree,
	DOUBLE *restrict g0, DOUBLE *restrict g1, unsigned logn, DOUBLE *restrict tmp)
{
	size_t n, hn;

	n = (1 + ((0) << 1)) << ((logn) - (0));
	if (n == 1) {
        //fprintf(stderr, "g0: %3.0f \n", g0[0]);
		tree[0] = g0[0];
		return;
	}
	hn = n >> 1;

	/*
	 * The LDL decomposition yields L (which is written in the tree)
	 * and the diagonal of D. Since d00 = g0, we just write d11
	 * into tmp.
	 */
//fprintf(stderr, "inner CALLING LDLqc_fft \n");
	LDLqc_fft(tmp, tree, g0, g1, logn, tmp + n);
//fprintf(stderr, "tmp at stage n= %zu: %lf \n", n, tmp[0]);

	/*
	 * Split d00 (currently in g0) and d11 (currently in tmp). We
	 * reuse g0 and g1 as temporary storage spaces:
	 *   d00 splits into g1, g1+hn
	 *   d11 splits into g0, g0+hn
	 */
	falcon_poly_split_fft(g1, g1 + hn, g0, logn);
	falcon_poly_split_fft(g0, g0 + hn, tmp, logn);

//fprintf(stderr, "output of fft split n= %zu: %lf and %lf \n", n, g0[0], g0[hn]);
	/*
	 * Each split result is the first row of a new auto-adjoint
	 * quasicyclic matrix for the next recursive step.
	 */
//fprintf(stderr, "inner CALLING ffLDL_fft inner twice \n");
//fprintf(stderr, "input polynomials to ffLDL_fft_inner first recursion n=%zu: %3.0f and %3.0f \n", n, g1[0], g1[hn]);
	ffLDL_fft_inner(tree + n,
		g1, g1 + hn, logn - 1, tmp);
//fprintf(stderr, "input polynomials to ffLDL_fft_inner second recursion n= %zu: %lf and %lf \n", n, g0[0], g0[hn]);
	ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
		g0, g0 + hn, logn - 1, tmp);
}

static void
ffLDL_fft(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g01, const DOUBLE *restrict g11,
	unsigned logn, DOUBLE *restrict tmp)
{
	size_t n, hn;
	DOUBLE *d00, *d11;
	n = (1 + ((0) << 1)) << ((logn) - (0));
	if (n == 1) {
		tree[0] = g00[0];
		return;
	}
	hn = n >> 1;
	d00 = tmp;
	d11 = tmp + n;
	tmp += n << 1;

	memcpy(d00, g00, n * sizeof *g00);
	LDL_fft(d11, tree, g00, g01, g11, logn, tmp);

    /*fprintf(stderr, "ffLDL_fft: %d\n", logn);
    for (size_t u = 0; u < n; u ++) {
        fprintf(stderr, "%3.0f ", d11[u]);
        if (15 == (u&0xF)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    for (size_t u = 0; u < n; u ++) {
        fprintf(stderr, "%3.0f ", tree[u]);
        if (15 == (u&0xF)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");*/

//fprintf(stderr, "tree element 0 after LDL: %3.0f \n", tree[0]);
	falcon_poly_split_fft(tmp, tmp + hn, d00, logn);
	falcon_poly_split_fft(d00, d00 + hn, d11, logn);
	memcpy(d11, tmp, n * sizeof *tmp);
//fprintf(stderr, "CALLING ffLDL_fft inner first time \n");
//fprintf(stderr, "tmp at stageB  n= %zu: %lf \n", n, tmp[0]);
	ffLDL_fft_inner(tree + n,
		d11, d11 + hn, logn - 1, tmp);
//fprintf(stderr, "CALLING ffLDL_fft inner second time \n");
	ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
		d00, d00 + hn, logn - 1, tmp);
}


/*
 * Normalize an ffLDL tree: each leaf of value x is replaced with
 * sigma / sqrt(x).
 */
static void
ffLDL_binary_normalize(DOUBLE *tree, DOUBLE sigma, unsigned logn)
{
	/*
	 * TODO: make an iterative version.
	 */
	size_t n;

	n = (1 + ((0) << 1)) << ((logn) - (0));
	if (n == 1) {
		tree[0] = (sigma / sqrt(tree[0]));
	} else {
		ffLDL_binary_normalize(tree + n,
			sigma, logn - 1);
		ffLDL_binary_normalize(tree + n + ffLDL_treesize(logn - 1),
			sigma, logn - 1);
	}
}

static void
ffLDL_fft_print(DOUBLE *restrict tree, unsigned logn)
{
    size_t n, hn;

    n = (1 + ((0) << 1)) << ((logn) - (0));
    if (n == 1) {
        //fprintf(stderr, "  tree: %3.0f \n", tree[0]);
        return;
    }
    hn = n >> 1;

    //fprintf(stderr, "logn: %d \n", logn);
    ffLDL_fft_print(tree + n, logn - 1);
    ffLDL_fft_print(tree + n + ffLDL_treesize(logn - 1), logn - 1);
}

/*
 * Get the size of the LDL tree for an input with polynomials of size
 * 2^logn. The size is expressed in the number of elements.
 */


static void
load_skey(DOUBLE *restrict sk, unsigned q,
	const SINT32 *f_src, const SINT32 *g_src,
	const SINT32 *F_src, const SINT32 *G_src,
	unsigned logn, unsigned ter, DOUBLE *restrict tmp) //keep ter=0 for the binary case
{
	size_t n;
	DOUBLE *f_tmp, *g_tmp, *F_tmp, *G_tmp; 
	DOUBLE *b00, *b01, *b10, *b11;
	DOUBLE *tree;
	DOUBLE sigma;

	n    = (1 + ((ter) << 1)) << ((logn) - (ter));
	b00  = sk + skoff_b00(logn, ter);
	b01  = sk + skoff_b01(logn, ter);
	b10  = sk + skoff_b10(logn, ter);
	b11  = sk + skoff_b11(logn, ter);
	tree = sk + skoff_tree(logn, ter);

	/*
	 * We load the private key elements directly into the B0 matrix,
	 * since B0 = [[g, -f], [G, -F]].
	 */
	f_tmp = b01;
	g_tmp = b00;
	F_tmp = b11;
	G_tmp = b10;

	smallints_to_double(f_tmp, f_src, logn, ter); //copies f_src to f_tmp (DOUBLE)
	smallints_to_double(g_tmp, g_src, logn, ter);
	smallints_to_double(F_tmp, F_src, logn, ter);
	smallints_to_double(G_tmp, G_src, logn, ter);

#if 0
/*//print out f_src-array
FILE * pFile_sc_f_src;
pFile_sc_f_src=fopen("SC_f_src.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile_sc_f_src, "f_src[%d]: %d  \n", u, f_src[u]);
	}
fclose(pFile_sc_f_src);*/
//OVERWRITE POLYNOMIALS FOR TESTING PURPOSES
// f-array
FILE * pFile_fal_f;
pFile_fal_f=fopen("FAL_f.txt", "r");
	if (pFile_fal_f==NULL){
	fprintf(stderr, "OPENING ERROR SC_f");
	exit (-1);
	}
for (size_t u = 0; u < n; u ++) {
		if(fscanf(pFile_fal_f, "%lf", f_tmp[u])!=1){
			fprintf(stderr, "SCAN ERROR f at f[%zu]", u); 
			exit (-1);
		}
	}
fclose(pFile_fal_f);

// F-array
FILE * pFile_fal_F;
pFile_fal_F=fopen("FAL_F.txt", "r");
for (size_t u = 0; u < n; u ++) {
		if(fscanf(pFile_fal_F, "%lf", F_tmp[u])!=1){
			fprintf(stderr, "SCAN ERROR F"); 
			exit (-1);
		}
	}
fclose(pFile_fal_F);

// g-array
FILE * pFile_fal_g;
pFile_fal_g=fopen("FAL_g.txt", "r");
for (size_t u = 0; u < n; u ++) {
		if(fscanf(pFile_fal_g, "%lf", g_tmp[u])!=1){
			fprintf(stderr, "SCAN ERROR g"); 
			exit (-1);
		}
	}
fclose(pFile_fal_g);

// G-array
FILE * pFile_fal_G;

pFile_fal_G=fopen("FAL_G.txt", "r");
	if (pFile_fal_G==NULL){
	fprintf(stderr, "OPENING ERROR SC_G");
	exit (-1);
	}
for (size_t u = 0; u < n; u ++){
		if(fscanf(pFile_fal_G, "%lf", G_tmp[u])!=1){
			fprintf(stderr, "SCAN ERROR G"); 
			exit (-1);
	}
}
fclose(pFile_fal_G);

//print out f-array
FILE * pFile_sc_f;
pFile_sc_f=fopen("SC_f.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile_sc_f, "%3.0f  \n", f_tmp[u]);
	}
fclose(pFile_sc_f);

//print out F-array
FILE * pFile_sc_F;
pFile_sc_F=fopen("SC_F.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile_sc_F, "%3.0f  \n", F_tmp[u]);
	}
fclose(pFile_sc_F);

//print out g-array
FILE * pFile_sc_g;
pFile_sc_g=fopen("SC_g.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile_sc_g, "%3.0f  \n", g_tmp[u]);
	}
fclose(pFile_sc_g);

//print out G-array
FILE * pFile_sc_G;
pFile_sc_G=fopen("SC_G.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile_sc_G, " %3.0f  \n", G_tmp[u]);
	}
fclose(pFile_sc_G);
#endif


	/*
	 * Compute the FFT for the key elements, and negate f and F....negation done in DLP keygen??
	 */
	/*if (ter) {
		falcon_FFT3(f, logn, 1);
		falcon_FFT3(g, logn, 1);
		falcon_FFT3(F, logn, 1);
		falcon_FFT3(G, logn, 1);
		falcon_poly_neg_fft3(f, logn, 1);
		falcon_poly_neg_fft3(F, logn, 1);
	} else  */

	//{
		falcon_FFT(f_tmp, logn);
		falcon_FFT(g_tmp, logn);
		falcon_FFT(F_tmp, logn);
		falcon_FFT(G_tmp, logn);
		falcon_poly_neg(f_tmp, logn);
		falcon_poly_neg(F_tmp, logn);
	//}

	/*
	 * The Gram matrix is G = B·B*. Formulas are:
	 *   g00 = b00*adj(b00) + b01*adj(b01)
	 *   g01 = b00*adj(b10) + b01*adj(b11)
	 *   g10 = b10*adj(b00) + b11*adj(b01)
	 *   g11 = b10*adj(b10) + b11*adj(b11)
	 */
    {
        DOUBLE *g00, *g01, *g11, *gxx;

		g00 = tmp;
		g01 = g00 + n;
		g11 = g01 + n;
		gxx = g11 + n;

		memcpy(g00, b00, n * sizeof *b00);
		falcon_poly_mulselfadj_fft(g00, logn);
		memcpy(gxx, b01, n * sizeof *b01);
		falcon_poly_mulselfadj_fft(gxx, logn);
		falcon_poly_add(g00, gxx, logn);

		memcpy(g01, b00, n * sizeof *b00);
		falcon_poly_muladj_fft(g01, b10, logn);
		memcpy(gxx, b01, n * sizeof *b01);
		falcon_poly_muladj_fft(gxx, b11, logn);
		falcon_poly_add(g01, gxx, logn);

		memcpy(g11, b10, n * sizeof *b10);
		falcon_poly_mulselfadj_fft(g11, logn);
		memcpy(gxx, b11, n * sizeof *b11);
		falcon_poly_mulselfadj_fft(gxx, logn);
		falcon_poly_add(g11, gxx, logn);

		/*
		 * Compute the Falcon tree.
		 */
		ffLDL_fft(tree, g00, g01, g11, logn, gxx);
        //ffLDL_fft_print(tree, logn);

		/*
		 * Tree normalization:
		 *   sigma = 1.55 * sqrt(q)
		 */
		sigma = sqrt(q)* (1.55);

		/*
		 * Normalize tree with sigma.
		 */
		ffLDL_binary_normalize(tree, sigma, logn);

        FILE * pFile_sc_tree;
        pFile_sc_tree=fopen("SC_tree.txt", "w");
        for (size_t u = 0; u < skoff_tree(logn, ter); u ++) {
            fprintf(pFile_sc_tree, "tree elements: %3.6f \n", tree[u]);
        }
        fclose(pFile_sc_tree);

	}
}

SINT32 falcon_sig_keygen(safecrypto_t *sc)
{
    SINT32 i, iter;
    SINT32 *f, *g, *F, *G, *h, *h_ntt;
    DOUBLE *f_tmp, *g_tmp, *F_tmp, *G_tmp;
    UINT32 n, q, logn;
    gpv_t gpv;
    UINT32 gaussian_flags = 0;
#if defined(FALCON_USE_EFFICIENT_GAUSSIAN_SAMPLING)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_EFFICIENT;
#elif defined(FALCON_GAUSSIAN_SAMPLE_MW_BOOTSTRAP)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP;
#endif
    SINT32   *b = NULL;
    GSO_TYPE *b_gs = NULL;
    GSO_TYPE *b_gs_inv_norm = NULL;
    GSO_TYPE  sig;
    SINT32 sample_error;
    FLOAT std_dev;
	

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "FALCON Signature KeyGen\n");

    n      = sc->falcon->params->n;
    q      = sc->falcon->params->q;
    logn   = sc->falcon->params->n_bits;

    SINT32 s1[n] SC_DEFAULT_ALIGNED;
    SINT32 c[n];

    // Allocate temporary memory
    f = sc->temp;
    if (NULL == f) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    g     = f + n;
    F     = f + 2 * n;
    G     = f + 3 * n;
    h     = f + 4 * n;
    h_ntt = f + 5 * n;
    f_tmp     = (DOUBLE *)(f + 6 *n);
    g_tmp     = f_tmp + n;
    F_tmp     = f_tmp + 2 * n;
    G_tmp    = f_tmp + 3 * n;
	

    unsigned ter = 0; //for binary case
 	
    gpv.f = f;
    gpv.g = g;
    gpv.F = F;
    gpv.G = G;
    gpv.n = n;
    
	size_t sk_len = ((size_t)(logn + 5) << logn) * sizeof(DOUBLE);
	size_t tmp_len = ((size_t)7 << logn) * sizeof(DOUBLE);
	
    DOUBLE *sk = NULL, *tmp = NULL;
	sk = SC_MALLOC(sk_len);
	if (sk == NULL) {
		fprintf(stderr, "bad_skey");
        goto finish_free;
	} 
	sc->falcon->sk = sk;
	tmp = SC_MALLOC(tmp_len);
	if (tmp == NULL) {
		fprintf(stderr, "bad_skey");
        goto finish_free;
	} 
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(4 * n * sizeof(SINT32));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    // Generate the public and private keys
    iter = 0;
restart:
    iter += gpv_gen_basis(sc, f, g, h, n, q,
        sc->sc_gauss, sc->prng_ctx[0], F, G, 0); //RECREATE_FLAG CHANGE BACK TO 0

    // If short basis generation is unsuccessful then restart
    if (iter < 0) {
        goto restart;
    }

    sc->stats.keygen_num++;
    sc->stats.keygen_num_trials += iter;

    SC_PRINT_DEBUG(sc, "Memory allocation for keys\n");

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
            sc->privkey->len = 0;
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    smallints_to_double(f_tmp, f, logn, ter); //copies f to f_tmp (DOUBLE)
    smallints_to_double(g_tmp, g, logn, ter);
    smallints_to_double(F_tmp, F, logn, ter);
    smallints_to_double(G_tmp, G, logn, ter);

    // Create the polynomial basis matrices if they are to be maintained in memory
    if (sc->falcon->keep_matrices) {
        create_gpv_matrices(sc, &gpv, q, n);
    }

    load_skey(sk, q, gpv.f, gpv.g, gpv.F, gpv.G, logn, 0, tmp);

    // Store the key pair in the SAFEcrypto structure for future use
    SINT32 *privkey = (SINT32*) sc->privkey->key;
    for (i=4*n; i--;) {
        privkey[i] = f[i]; // NOTE: f, g, F, G are contiguous
    }
    SINT16 *pubkey = (SINT16*) sc->pubkey->key;
    for (i=n; i--;) {
        pubkey[i] = h[i];
    }
    sc->privkey->len = 4 * n;
    sc->pubkey->len = n; // Actually 2n as the NTT version is also stored

    // Store an NTT domain version of the public key
#if 1
    sc->sc_ntt->fwd_ntt_32_16(h_ntt, &sc->falcon->ntt,
        h, sc->falcon->params->w);
    sc->sc_ntt->normalize_32(h_ntt, n, &sc->falcon->ntt);
    for (i=n; i--;) {
        pubkey[i + n] = h_ntt[i];
    }
#endif

    // Polynomial basis check
    FLOAT sd = 0;
    for (i=0; i<2*n; i++) {

    }

    SC_PRINT_DEBUG(sc, "Print keys\n");
    SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 16);

    if (tmp) {
        SC_FREE(tmp, tmp_len);
    }

    // Clear the temporary memory used for generation
    SC_MEMZERO(f, 6 * n * sizeof(SINT32) + 4 * n *sizeof(DOUBLE));
    return SC_FUNC_SUCCESS;

finish_free:
    if (sk) {
        SC_FREE(sk, sk_len);
    }
    if (tmp) {
        SC_FREE(tmp, tmp_len);
    }
    SC_MEMZERO(f, 6 * n * sizeof(SINT32) + 4 * n *sizeof(DOUBLE));
    return SC_FUNC_FAILURE;
}


SINT32 falcon_sig_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len, UINT8 **sigret, size_t *siglen)
{
    // WITHOUT message recovery:
    // 2. As per IBE Extract, obtain the polynomials s1 and s2 using a
    //    Gaussian sampler and the polynomial basis B such that
    //    hs1 + s2 = t mod q
    // 3. Return the signature (s1, m)

 	SINT32 *s2;	
    DOUBLE *sk = sc->falcon->sk;
    size_t i;
    SINT16 *h, *h_ntt;
    SINT32 *s2_ntt;
    UINT32 n, q, q_bits, n_bits;
    SINT32 *f, *g, *F, *G, *c;
    SINT32 *s1;
    UINT8 md[64];
    SINT32 retval = SC_FUNC_FAILURE;
    gpv_t gpv;
    UINT32 gaussian_flags = 0;
#if defined(FALCON_USE_EFFICIENT_GAUSSIAN_SAMPLING)
    gaussian_flags = GPV_GAU h_function_xofSSIAN_SAMPLE_EFFICIENT;
#elif defined(FALCON_GAUSSIAN_SAMPLE_MW_BOOTSTRAP)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP;
#endif

    if (NULL == sc->falcon) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Obtain all the constants and variables
    n        = sc->falcon->params->n;
    q        = sc->falcon->params->q;
    q_bits   = sc->falcon->params->q_bits;
    n_bits   = sc->falcon->params->n_bits;

    f        = sc->privkey->key;
    g        = f + n;
    F        = g + n;
    G        = F + n;
    gpv.f    = f;
    gpv.g    = g;
    gpv.F    = F;
    gpv.G    = G;
    gpv.n    = n;
    FLOAT bd;
	unsigned ter = 0; //for binary
    
    // Assign pointers for the pre-computed Falcon tree
    DOUBLE *b00, *b01, *b10, *b11, *tree;
	b00 = sk + skoff_b00(n_bits, ter);
	b01 = sk + skoff_b01(n_bits, ter);
	b10 = sk + skoff_b10(n_bits, ter);
	b11 = sk + skoff_b11(n_bits, ter);
	tree = sk + skoff_tree(n_bits, ter);

	// Allocate memory for FALCON signature sampling_fft
    DOUBLE *c0 =SC_MALLOC(sizeof(DOUBLE) * 2 * n);
    if (NULL == c0) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    DOUBLE *c1 = c0 + n;

    DOUBLE *tmp = (DOUBLE*) SC_MALLOC(sizeof(DOUBLE) * 7 * n);
    if (NULL == tmp) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    DOUBLE *z0 =  (DOUBLE*) SC_MALLOC(sizeof(DOUBLE)  * 2 * n);
    if (NULL == z0) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    DOUBLE *z1 = z0 + n;

    c        = sc->temp;
    s1       = c + n;
    s2       = s1 + n;
    s2_ntt   = s2 + n;

    // Obtain pointers to the public key (NTT domain version)
    h        = (SINT16 *) sc->pubkey->key;
    h_ntt    = (SINT16 *) sc->pubkey->key + n;

    bd       = sc->falcon->params->bd;

    const SINT16 *w        = sc->falcon->params->w;
    const SINT16 *r        = sc->falcon->params->r;
    ntt_params_t *ntt      = &sc->falcon->ntt;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    const utils_arith_poly_t *sc_poly  = sc->sc_poly;

restart:

    // Translate the message into a polynomial using a random oracle
#ifdef FALCON_USE_RANDOM_ORACLE_CSPRNG
    oracle_csprng(sc, m, m_len, md);
    h_function_csprng(sc, md, c, n);
#else
    oracle_xof(sc, m, m_len);
    h_function_xof(sc, c, n);
#endif

    for (int i = 0; i < n; i ++) {
		c0[i] = c[i];
		c1[i] = 0;  // NOT NEEDED - SET BELOW
    }

    falcon_FFT(c0, n_bits);
    DOUBLE ni = fpr_inverse_of(q);
    memcpy(c1, c0, n * sizeof *c0);
    falcon_poly_mul_fft(c1, b01, n_bits);
    falcon_poly_mulconst_fft(c1, fpr_neg(ni), n_bits);
    falcon_poly_mul_fft(c0, b11, n_bits);
    falcon_poly_mulconst_fft(c0, ni, n_bits);

    // Increment the trial statistics for signature generation
    sc->stats.sig_num++;
    sc->stats.sig_num_trials++;

    // Generate a sampled polynomial using the polynomial basis
    SINT32 sample_error;
    sample_error = gaussian_lattice_sample_fft(sc, z0, z1, tree, c0, c1, n_bits, tmp, gaussian_flags);
    if (SC_FUNC_FAILURE == sample_error) {
        SC_LOG_ERROR(sc, SC_ERROR);
        goto finish;
    }

	// Get the lattice point corresponding to that tiny vector
	memcpy(c0, z0, n * sizeof *z0);
	memcpy(c1, z1, n * sizeof *z1);
	falcon_poly_mul_fft(z0, b00, n_bits);
	falcon_poly_mul_fft(z1, b10, n_bits);
	falcon_poly_add(z0, z1, n_bits);
	memcpy(z1, c0, n * sizeof *c0);
	falcon_poly_mul_fft(z1, b01, n_bits);

	memcpy(c0, z0, n * sizeof *c0);
	falcon_poly_mul_fft(c1, b11, n_bits);
	falcon_poly_add_fft(c1, z1, n_bits);


	falcon_iFFT(c0, n_bits);
	falcon_iFFT(c1, n_bits);

	/*
	 * Compute the signature.
	 */
	for (int i = 0; i < n; i ++) {
		s1[i] = (SINT32)(c[i] - llrint(c0[i]));
		s2[i] = (SINT32) -llrint(c1[i]);
	}

    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, m_len);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s1", s1, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s2", s2, n);
    sc->sc_ntt->center_32(s1, n, &sc->falcon->ntt);
    sc->sc_ntt->center_32(s2, n, &sc->falcon->ntt);

    if (SC_FUNC_FAILURE == check_norm_bd(bd, s1, s2, n)) {
        SC_PRINT_DEBUG(sc, "Norm failed\n");
        goto finish;//restart;
    }

    // Output an encoded byte stream representing the secret key SK
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
    };
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &coding_raw,
        q_bits * n, NULL, 0, sigret, siglen);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        goto finish;
    }

    // Send s1
    entropy_poly_encode_32(packer, n, s2, q_bits,
        SIGNED_COEFF, sc->coding_signature.type, 3, &sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded);

    sc->stats.components[SC_STAT_SIGNATURE][0].bits += q_bits*n;
    utils_entropy.pack_get_buffer(packer, sigret, siglen);
    utils_entropy.pack_destroy(&packer);

#if 1
    sc_ntt->normalize_32(s1, n, &sc->falcon->ntt);
    sc_ntt->normalize_32(s2, n, &sc->falcon->ntt);

    // Calculate s1 = h*s2 - c0
#if 0
    small_mul_mod_ring(s1, s2, h, n, q, s2_ntt);
#else
    sc_ntt->fwd_ntt_32_16(s2_ntt, ntt, s2, w);
    sc_ntt->mul_32_pointwise_16(s1, ntt, s2_ntt, h_ntt);
    sc_ntt->inv_ntt_32_16(s1, ntt, s1, w, r);
#endif
    sc_poly->sub_32(s1, n, c, s1);
    sc_ntt->center_32(s1, n, ntt);
    sc_ntt->center_32(s2, n, ntt);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s1 (regen) = h*s2 - c0", s1, n);

    if (SC_FUNC_FAILURE == check_norm_bd(bd, s1, s2, n)) {
        goto finish;
    }
#endif

    retval = SC_FUNC_SUCCESS;

finish:
   /* // Free all memory resources
    if (0 == sc->falcon->keep_matrices) {
        if (b) {
            SC_FREE(b, sizeof(SINT32) * 4*n*n);
        }
        if (b_gs) {
            SC_FREE(b_gs, sizeof(GSO_TYPE) * (4*n*n + 2*n));
        }
    }*/



    // Reset the temporary memory
    SC_MEMZERO(sc->temp, 4 * n * sizeof(SINT32));
 SC_FREE(c0, sizeof(DOUBLE) * 2 * n);
 SC_FREE(tmp, sizeof(DOUBLE) * 7 * n);
 SC_FREE(z0, sizeof(DOUBLE) * 2 * n);

	return retval;
}

#endif // DISABLE_SIGNATURES_SERVER

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 falcon_sig_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 *sigbuf, size_t siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 falcon_sig_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
    // WITHOUT message recovery:
    // 1. Hash the received message, t = H(m)
    // 2. Compute the s2 polynomial, s2 = t - h*s1 mod q
    // 3. Compute the norm, ||(s1, s2)||
    //    ACCEPT if norm < B, REJECT otherwise

    size_t i;
    UINT32 n, q, q_bits;
    FLOAT bd;
    SINT16 *h_ntt;
    SINT16 *h;
    SINT32 *s1, *s2, *s2_ntt, *c;
    DOUBLE *C;
    UINT8 md[64];

    // Obtain all the constants and variables
    n        = sc->falcon->params->n;
    q        = sc->falcon->params->q;
    q_bits   = sc->falcon->params->q_bits;
    bd       = sc->falcon->params->bd;

    c        = sc->temp;
    s1       = c + n;
    s2       = s1 + n;
    s2_ntt   = s2 + n;

    // Obtain pointers to the public key (NTT domain version)
    h        = (SINT16 *) sc->pubkey->key;
#if 1
    h_ntt    = (SINT16 *) sc->pubkey->key + n;
#endif

    const SINT16 *w        = sc->falcon->params->w;
    const SINT16 *r        = sc->falcon->params->r;
    ntt_params_t *ntt      = &sc->falcon->ntt;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    const utils_arith_poly_t *sc_poly  = sc->sc_poly;

    // Decompress the signature
    sc_packer_t *ipacker;
    ipacker = utils_entropy.pack_create(sc, &sc->coding_signature,
        0, sigbuf, siglen, NULL, 0);
    if (NULL == ipacker) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Decode s1
    entropy_poly_decode_32(ipacker, n, s2, q_bits,
        SIGNED_COEFF, sc->coding_signature.type, 3);
    sc_ntt->center_32(s2, n, ntt);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received s2", s2, n);

    fprintf(stderr, "s2=\n");
    for (size_t u = 0; u < n; u ++) {
        fprintf(stderr, "%d ", s2[u]);
        if (15 == (u&15)) fprintf(stderr, "\n");
    }

    // Destroy the input packer
    utils_entropy.pack_destroy(&ipacker);

    // Translate the message into a polynomial using a random oracle
#ifdef FALCON_USE_RANDOM_ORACLE_CSPRNG
    oracle_csprng(sc, m, m_len, md);
    h_function_csprng(sc, md, c, n);
#else
    oracle_xof(sc, m, m_len);
    h_function_xof(sc, c, n);
#endif

#if 0
    small_mul_mod_ring(s1, s2, h, n, q, s2_ntt);
#else
    sc_ntt->fwd_ntt_32_16(s2_ntt, ntt, s2, w);
    sc->sc_ntt->mul_32_pointwise_16(s1, ntt, s2_ntt, h_ntt);
    sc_ntt->inv_ntt_32_16(s1, ntt, s1, w, r);
#endif
    sc_poly->sub_32(s1, n, c, s1);
    sc_ntt->center_32(s1, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s1", s1, n);

    fprintf(stderr, "s1=\n");
    for (size_t u = 0; u < n; u ++) {
        fprintf(stderr, "%d ", s1[u]);
        if (15 == (u&15)) fprintf(stderr, "\n");
    }

    if (SC_FUNC_FAILURE == check_norm_bd(bd, s1, s2, n)) {
        sc->stats.sig_num_unverified++;
        goto error_return;
    }

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, 6 * n * sizeof(SINT32));

    sc->stats.sig_num_verified++;
    return SC_FUNC_SUCCESS;

error_return:
    // Reset the temporary memory
    SC_MEMZERO(sc->temp, 6 * n * sizeof(SINT32));

    return SC_FUNC_FAILURE;
}

#endif // DISABLE_SIGNATURES_CLIENT

char * falcon_sig_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I"};
    static char stats[2048];
    snprintf(stats, 2047, "\n%s Signature (%s-%s):\n\
Keys           %8" FMT_LIMB " key-pairs  / %8" FMT_LIMB " trials [%.6f trials per key-pair]\n\
Signatures     %8" FMT_LIMB " signatures / %8" FMT_LIMB " trials [%.6f trials per signature]\n\
Verifications  %8" FMT_LIMB " passed     / %8" FMT_LIMB " failed\n\n\
Sampler:                 %s\n\
PRNG:                    %s\n\
Oracle Hash:             %s\n\n\
Public Key compression:  %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Private Key compression: %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   f       %10.2f%13.2f%16.3f%%\n\
   g       %10.2f%13.2f%16.3f%%\n\
   F       %10.2f%13.2f%16.3f%%\n\
   G       %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Signature compression:   %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   total   %10.2f%13.2f%16.3f%%\n\n",
        "FALCON",
        "FALCON",
        param_set_name[sc->falcon->params->set],
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
        sc_hash_names[sc->falcon->oracle_hash],
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
        sc_entropy_names[(int)sc->coding_signature.type],
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits);
    return stats;
}


#undef FMT_LIMB
