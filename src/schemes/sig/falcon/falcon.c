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

#include "utils/arith/falcon_fft.h"
#include "utils/arith/falcon_ldl.h"
#include "utils/arith/falcon_keygen.h"

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

    SC_PRINT_DEBUG(sc, "FALCON");

    // Initialise the SAFEcrypto struct with the specified Falcon signature parameter set
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

    // Set a flag to indicate if the B and B_gs matrices (and the norm of
    // each B_gs row) are to be computed and stored.
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

    // Create pointers for the arithmetic functions used by Falcon
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
    sc->temp_size = (FALCON_NUM_TEMP * n) * sizeof(SINT32) + 4 * n * sizeof(DOUBLE);
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
	UINT16 n;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->falcon->params->n;

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

    utils_crypto_hash_destroy(sc->hash);
    utils_crypto_xof_destroy(sc->xof);

    if (sc->falcon) {
        SC_FREE(sc->falcon, sizeof(falcon_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "FALCON Signature algorithm destroyed");

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
    FLOAT norm = 0;
    for (i=n; i--;) {
        norm += s1[i] * s1[i] + s2[i] * s2[i];
    }
    norm = sqrtf(norm);

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
    const UINT32 q        = sc->falcon->params->q;
    const SINT32 q_bits   = sc->falcon->params->q_bits;
    const SINT32 buf_size = 32;
    UINT32       mask     = (1 << q_bits) - 1;
    SINT32      *x        = c;
    size_t       xof_len  = buf_size * sizeof(SINT32);

    SINT32 c_tmp[buf_size];

    for (int j=0; j < n/buf_size; j++){
	    //SINT32 c_tmp[buf_size];
        xof_squeeze(sc->xof, c_tmp, xof_len);

        // Generate polynomial coefficients mod q from the CSPRNG
        for (i=0; i<buf_size; i++) {
            UINT32 y = c_tmp[i] & mask;
            y -= ((SINT32)(q - y) >> 31) * q;
	        *x++ = y;
        }
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


#if !defined(DISABLE_SIGNATURES_SERVER) || !defined(DISABLE_SIGNATURES_CLIENT)
// Translate a message of arbitrary length to a unique polynomial ring
static inline void map_message_to_ring(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    SINT32 *c, size_t c_len)
{
    UINT8 md[64];
#ifdef FALCON_USE_RANDOM_ORACLE_CSPRNG
    oracle_csprng(sc, m, m_len, md);
    h_function_csprng(sc, md, c, c_len);
#else
    oracle_xof(sc, m, m_len);
    h_function_xof(sc, c, c_len);
#endif
}
#endif


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

    load_skey(sk, q, f, g, F, G, logn, 0, tmp);

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
    sc->sc_ntt->fwd_ntt_32_16(h_ntt, &sc->falcon->ntt,
        h, sc->falcon->params->w);
    sc->sc_ntt->normalize_32(h_ntt, n, &sc->falcon->ntt);
    for (i=n; i--;) {
        pubkey[i + n] = h_ntt[i];
    }

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
 	SINT32 *s2;	
    size_t i;
    SINT16 *h, *h_ntt;
    SINT32 *s2_ntt;
    UINT32 n, q, q_bits, n_bits;
    SINT32 *f, *g, *F, *G, *c;
    SINT32 *s1;
    SINT32 retval = SC_FUNC_FAILURE;
    gpv_t gpv;
    UINT32 gaussian_flags = 0;
#if defined(FALCON_USE_EFFICIENT_GAUSSIAN_SAMPLING)
    gaussian_flags = GPV_GAUSSIAN_SAMPLE_EFFICIENT;
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

    // Increment the trial statistics for signature generation
    sc->stats.sig_num++;
    sc->stats.sig_num_trials++;

    // Translate the message into a polynomial using a random oracle
    map_message_to_ring(sc, m, m_len, c, n);

    // Gaussian sampling over the basis vector to generate the signature polynomials
    gaussian_sample_with_tree(sc, sc->falcon->sk, n, q, n_bits, c, gaussian_flags, s1, s2);

    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, m_len);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s1", s1, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s2", s2, n);

    // Centre s2 around 0 for output as a signed integer with a Gaussian distribution
    sc->sc_ntt->center_32(s2, n, &sc->falcon->ntt);

    if (SC_FUNC_FAILURE == check_norm_bd(bd, s1, s2, n)) {
        SC_PRINT_DEBUG(sc, "Norm failed\n");
        goto finish;//restart;
    }

    // Output an encoded byte stream representing the signature
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
    entropy_poly_encode_32(packer, n, s2, q_bits-2,
        SIGNED_COEFF, sc->coding_signature.type, 3, &sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded);

    sc->stats.components[SC_STAT_SIGNATURE][0].bits += (q_bits-2)*n;
    utils_entropy.pack_get_buffer(packer, sigret, siglen);
    utils_entropy.pack_destroy(&packer);

#if 0
    // Verification of the signature as a countermeasure to fault attack

    // Calculate s1 = h*s2 - c0
    /// @todo Why do we have to reverse the sign here - is f/F not negated somewhere?
    sc_ntt->normalize_32(s2, n, &sc->falcon->ntt);
    sc_ntt->fwd_ntt_32_16(s2_ntt, ntt, s2, w);
    sc_ntt->mul_32_pointwise_16(s1, ntt, s2_ntt, h_ntt);
    sc_ntt->inv_ntt_32_16(s1, ntt, s1, w, r);
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

SINT32 falcon_sig_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
    size_t i;
    UINT32 n, q, q_bits;
    FLOAT bd;
    SINT16 *h_ntt;
    SINT16 *h;
    SINT32 *s1, *s2, *s2_ntt, *c;
    DOUBLE *C;

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
    h_ntt    = (SINT16 *) sc->pubkey->key + n;

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
    entropy_poly_decode_32(ipacker, n, s2, q_bits-2,
        SIGNED_COEFF, sc->coding_signature.type, 3);
    sc_ntt->center_32(s2, n, ntt);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received s2", s2, n);

    // Destroy the input packer
    utils_entropy.pack_destroy(&ipacker);

    // Translate the message into a polynomial using a random oracle
    map_message_to_ring(sc, m, m_len, c, n);

    // Compute s1 = s2*h  - c
    /// @todo Why do we have to reverse the sign here - is f/F not negated somewhere?
    sc_ntt->fwd_ntt_32_16(s2_ntt, ntt, s2, w);
    sc->sc_ntt->mul_32_pointwise_16(s1, ntt, s2_ntt, h_ntt);
    sc_ntt->inv_ntt_32_16(s1, ntt, s1, w, r);
    sc_poly->sub_32(s1, n, c, s1);
    sc_ntt->center_32(s1, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s1", s1, n);

    // Verify that the l2 norm of the two signature polynomials lies below
    // the required threshold
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
    static const char* param_set_name[] = {"0", "1", "2"};
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
