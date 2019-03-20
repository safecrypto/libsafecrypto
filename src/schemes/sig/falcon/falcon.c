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

#include "falcon.h"
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

#include <math.h>

#define FALCON_NUM_TEMP     8
//#define DEBUG_FALCON_SIG

#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif

#define M1_BITS(b)  ((b) - 1)


SC_STRUCT_PACK_START
typedef struct falcon_cfg_t {
    falcon_set_t    *params;
    safecrypto_ntt_e      ntt_optimisation;
    ntt_params_t          ntt;
    sc_entropy_type_e     entropy;
    sc_hash_e             oracle_hash;
    SINT32                keep_matrices;
    SINT32               *b;
#ifdef FALCON_USE_LONGDOUBLE_PREC_FLOATS
    LONGDOUBLE           *b_gs;
    LONGDOUBLE           *b_gs_inv_norm;
#else
#ifdef FALCON_USE_DOUBLE_PREC_FLOATS
    DOUBLE               *b_gs;
    DOUBLE               *b_gs_inv_norm;
#else
    FLOAT                *b_gs;
    FLOAT                *b_gs_inv_norm;
#endif
#endif
} SC_STRUCT_PACKED falcon_cfg_t;
SC_STRUCT_PACK_END



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

    // Allocate memory for ENS/DLP signature configuration
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
    sc->temp_size = (FALCON_NUM_TEMP * n + kappa) * sizeof(SINT32);
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

    SC_PRINT_DEBUG(sc, "ENS/DLP Signature algorithm destroyed");

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

    sc->privkey->len = 4 * n;

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

    UINT32 mask = (1 << q_bits) - 1;
    xof_squeeze(sc->xof, c, n*sizeof(SINT32));

    // Generate polynomial coefficients mod q from the CSPRNG
    for (i=0; i<n; i++) {
        c[i] &= mask;
        c[i] -= (c[i] >= q) * q;
    }
}

// Extract m1 from the ring c and copy it to the message array that already contains m2
static SINT32 recover_msg(safecrypto_t *sc, UINT8 **m, size_t *m_len, SINT32 *c, UINT32 q_bits, size_t n, size_t k)
{
    SINT32 retval = SC_FUNC_FAILURE;
    size_t i, offset;
    UINT32 mask, bound;
    UINT8 *buffer;
    size_t buffer_len = 0;
    offset  = (n - k) * (M1_BITS(q_bits));
    offset -= (offset >> 3) << 3;
    mask    = ((1 << (8 - offset)) - 1) ^ 0xFF;
    bound   = (1 << M1_BITS(q_bits)) - 1;

    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Input m", *m, *m_len);

    // Use packers to obtain a byte array from the first (n-k) input ring coefficients
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
    };
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &coding_raw, (n-k)*(M1_BITS(q_bits)), NULL, 0, &buffer, &buffer_len);
    for (i=0; i<n-k; i++) {
        // Check if the input sample is within bounds
        if (c[i] > bound) {
            utils_entropy.pack_destroy(&packer);
            goto finish;
        }

        // Write M!_BITS to the data stream
        utils_entropy.pack_insert(packer, c[i], M1_BITS(q_bits));
    }
    utils_entropy.pack_insert(packer, 0, 16);
    utils_entropy.pack_get_buffer(packer, &buffer, &buffer_len);
    utils_entropy.pack_destroy(&packer);

    // Extract m1 from the buffer, ORing the last byte with the first few bits of m2
    for (i=0; i<buffer_len-3; i++) {
        (*m)[i] = buffer[i];
    }
    if (0 == offset) {
        (*m)[i] = buffer[buffer_len-3];
    }
    else {
        (*m)[i] &= (mask ^ 0xFF);
        (*m)[i] |= buffer[buffer_len-3] & mask;
    }

    //*m_len = ((*m_len * 8) + (n - k) * (M1_BITS(q_bits))) >> 3;
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Recovered m", *m, *m_len);

    // Free the memory associated with the buffer
    SC_FREE(buffer, buffer_len);

    retval = SC_FUNC_SUCCESS;

finish:
    return retval;
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

static SINT32 get_gso(safecrypto_t *sc, UINT32 n, SINT32 q, gpv_t *gpv, SINT32 **b, GSO_TYPE **b_gs, GSO_TYPE **b_gs_inv_norm)
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
}

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

SINT32 falcon_sig_keygen(safecrypto_t *sc)
{
    SINT32 i, iter;
    SINT32 *f, *g, *F, *G, *h, *h_ntt;
    UINT32 n, q;
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

    SC_PRINT_DEBUG(sc, "ENS/DLP Signature KeyGen\n");

    n      = sc->falcon->params->n;
    q      = sc->falcon->params->q;

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
    gpv.f = f;
    gpv.g = g;
    gpv.F = F;
    gpv.G = G;
    gpv.n = n;

    // Generate the public and private keys
    iter = 0;
restart:
    iter += gpv_gen_basis(sc, f, g, h, n, q,
        sc->sc_gauss, sc->prng_ctx[0], F, G, 0);

    // If short basis generation is unsuccessful then restart
    if (iter < 0) {
        goto restart;
    }

    sc->stats.keygen_num++;
    sc->stats.keygen_num_trials += iter;

    SC_PRINT_DEBUG(sc, "Memory allocation for keys\n");

    // Allocate key pair memory
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(4 * n * sizeof(SINT32));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, 4 * n * sizeof(SINT32));
            sc->privkey->len = 0;
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    // Create the polynomial basis matrices if they are to be maintained in memory
    if (sc->falcon->keep_matrices) {
        create_gpv_matrices(sc, &gpv, q, n);
    }

    // Obtain the Gram Scmidt orthogonalisation of the polynomial basis
    get_gso(sc, n, q, &gpv, &b, &b_gs, &b_gs_inv_norm);

    // Generate a sampled polynomial using the polynomial basis
    sig = 2.0L / b_gs_inv_norm[0];
    for (i=0; i<n; i++) {
        c[i] = q >> 1;
    }

    sample_error = gaussian_lattice_sample(sc, &gpv, b_gs, b_gs_inv_norm,
        c, s1, NULL, q, sig, gaussian_flags);

    // Free memory resources associated with the polynomial basis
    if (0 == sc->falcon->keep_matrices) {
        if (b) {
            SC_FREE(b, sizeof(SINT32) * 4*n*n);
        }
        if (b_gs) {
            SC_FREE(b_gs, sizeof(GSO_TYPE) * (4*n*n + 2*n));
        }
    }

    if (SC_FUNC_FAILURE == sample_error) {
        SC_LOG_ERROR(sc, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Verify that we can correctly sample over the lattice by checking that s1
    // has a standard deviation of not more than 2*1.17*sqrt(q)
    std_dev = get_std_dev(s1, n);
    if (std_dev > n*sig)
    {
        goto restart;
    }

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
#if 0
    sc->sc_ntt->fwd_ntt_32_16_large(h_ntt, &sc->falcon->ntt,
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

    // Clear the temporary memory used for generation
    SC_MEMZERO(f, 6 * n * sizeof(SINT32));
    return SC_FUNC_SUCCESS;

finish_free:
    SC_MEMZERO(f, 6 * n * sizeof(SINT32));
    return SC_FUNC_FAILURE;
}

SINT32 falcon_sig_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len, UINT8 **sigret, size_t *siglen)
{
    // WITHOUT message recovery:
    // 1. Hash the message m, t = H(m)
    // 2. As per IBE Extract, obtain the polynomials s1 and s2 using a
    //    Gaussian sampler and the polynomial basis B such that
    //    hs1 + s2 = t mod q
    // 3. Return the signature (s1, m)

#ifdef DEBUG_FALCON_SIG
    size_t i;
    SINT16 *h, *h_ntt;
    SINT32 *s2, *s1_ntt;
#endif
    UINT32 n, q, q_bits;
    SINT32 *f, *g, *F, *G;
    SINT32 *c, *s1;
    UINT8 md[64];
    SINT32 retval = SC_FUNC_FAILURE;
    gpv_t gpv;
    UINT32 gaussian_flags = 0;
#if defined(FALCON_USE_EFFICIENT_GAUSSIAN_SAMPLING)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_EFFICIENT;
#elif defined(FALCON_GAUSSIAN_SAMPLE_MW_BOOTSTRAP)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP;
#endif

    // Obtain all the constants and variables
    n        = sc->falcon->params->n;
    q        = sc->falcon->params->q;
    q_bits   = sc->falcon->params->q_bits;

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
    s1       = c + n;
#ifdef DEBUG_FALCON_SIG
    s2       = s1 + n;
    s1_ntt   = s2 + n;

    // Obtain pointers to the public key (NTT domain version)
    h        = (SINT16 *) sc->pubkey->key;
    h_ntt    = (SINT16 *) sc->pubkey->key + n;
#endif

#ifdef DEBUG_FALCON_SIG
    const SINT16 *w        = sc->falcon->params->w;
    const SINT16 *r        = sc->falcon->params->r;
    ntt_params_t *ntt      = &sc->falcon->ntt;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    const utils_arith_poly_t *sc_poly  = sc->sc_poly;
#endif

    // Translate the message into a polynomial using a random oracle
#ifdef FALCON_USE_RANDOM_ORACLE_CSPRNG
    oracle_csprng(sc, m, m_len, md);
    h_function_csprng(sc, md, c, n);
#else
    oracle_xof(sc, m, m_len);
    h_function_xof(sc, c, n);
#endif

    // Obtain the Gram Scmidt orthogonalisation of the polynomial basis
    SINT32 *b = NULL;
    GSO_TYPE *b_gs = NULL;
    GSO_TYPE *b_gs_inv_norm = NULL;
    GSO_TYPE sig;
    get_gso(sc, n, q, &gpv, &b, &b_gs, &b_gs_inv_norm);

    // Increment the trial statistics for signature generation
    sc->stats.sig_num++;
    sc->stats.sig_num_trials++;

    // Generate a sampled polynomial using the polynomial basis
    sig = 2.0L / b_gs_inv_norm[0];
    SC_PRINT_DEBUG(sc, "Sign() sigma = %3.6f\n", sig);
    SINT32 sample_error;
    sample_error = gaussian_lattice_sample(sc, &gpv, b_gs, b_gs_inv_norm,
        c, s1, NULL, q, sig, gaussian_flags);
    if (SC_FUNC_FAILURE == sample_error) {
        SC_LOG_ERROR(sc, SC_ERROR);
        goto finish;
    }
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, m_len);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s1", s1, n);
    sc->sc_ntt->center_32(s1, n, &sc->falcon->ntt);

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
    entropy_poly_encode_32(packer, n, s1, q_bits,
        SIGNED_COEFF, sc->coding_signature.type, 3, &sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded);

    sc->stats.components[SC_STAT_SIGNATURE][0].bits += q_bits*n;
    utils_entropy.pack_get_buffer(packer, sigret, siglen);
    utils_entropy.pack_destroy(&packer);

#ifdef DEBUG_FALCON_SIG
    // Calculate s2 = t - h*s1 mod q
    sc_ntt->fwd_ntt_32_16_large(s1_ntt, ntt, s1, w);
    sc->sc_ntt->mul_32_pointwise_16(s2, ntt, s1_ntt, h_ntt);
    sc_ntt->inv_ntt_32_16_large(s2, ntt, s2, w, r);
    sc_poly->sub_32(s2, n, c, s2);
    sc_ntt->center_32(s2, n, ntt);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s2 = t - h*s1 mod q", s2, n);
#endif

    retval = SC_FUNC_SUCCESS;

finish:
    // Free all memory resources
    if (0 == sc->falcon->keep_matrices) {
        if (b) {
            SC_FREE(b, sizeof(SINT32) * 4*n*n);
        }
        if (b_gs) {
            SC_FREE(b_gs, sizeof(GSO_TYPE) * (4*n*n + 2*n));
        }
    }

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, 4 * n * sizeof(SINT32));

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

    return (norm >= bd)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}

SINT32 falcon_sig_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
    // WITHOUT message recovery:
    // 1. Hash the received message, t = H(m)
    // 2. Compute the s2 polynomial, s2 = t - h*s1 mod q
    // 3. Compute the norm, ||(s1, s2)||
    //    ACCEPT if norm < B, REJECT otherwise

    UINT32 n, q, q_bits;
    FLOAT bd;
#ifdef DEBUG_FALCON_SIG
    SINT16 *h_ntt;
#endif
    SINT16 *h;
    SINT32 *c, *s1, *s2, *s1_ntt;
    UINT8 md[64];

    // Obtain all the constants and variables
    n        = sc->falcon->params->n;
    q        = sc->falcon->params->q;
    q_bits   = sc->falcon->params->q_bits;
    bd       = sc->falcon->params->bd;

    c        = sc->temp;
    s1       = c + n;
    s2       = s1 + n;
    s1_ntt   = s2 + n;

    // Obtain pointers to the public key (NTT domain version)
    h        = (SINT16 *) sc->pubkey->key;
#ifdef DEBUG_FALCON_SIG
    h_ntt    = (SINT16 *) sc->pubkey->key + n;
#endif

#ifdef DEBUG_FALCON_SIG
    const SINT16 *w        = sc->falcon->params->w;
    const SINT16 *r        = sc->falcon->params->r;
#endif
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
    entropy_poly_decode_32(ipacker, n, s1, q_bits,
        SIGNED_COEFF, sc->coding_signature.type, 3);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received s1", s1, n);

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

#if 1
    small_mul_mod_ring(s2, s1, h, n, q, s1_ntt);
#else
    sc_ntt->fwd_ntt_32_16(s1_ntt, ntt, s1, w);
    sc->sc_ntt->mul_32_pointwise_16(s2, ntt, s1_ntt, h_ntt);
    sc_ntt->inv_ntt_32_16(s2, ntt, s2, w, r);
#endif
    sc_poly->sub_32(s2, n, c, s2);
    sc_ntt->center_32(s2, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s2", s2, n);

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
