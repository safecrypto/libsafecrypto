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

#include "ring_tesla.h"

#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/arith/arith.h"
#include "utils/arith/ntt.h"
#include "utils/arith/sc_math.h"
#include "utils/entropy/packer.h"
#include "utils/entropy/entropy.h"
#include "utils/sampling/sampling.h"
#include "random_oracle.h"
#include "ring_tesla_params.h"


#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif


SINT32 ring_tesla_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 2, 3, 2, 0, 0, 0)) {
        return SC_FUNC_FAILURE;
    }

    // Precomputation for entropy coding
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_pub_key.entropy_coder    = NULL;
    sc->coding_priv_key.type            = SC_ENTROPY_NONE;
    sc->coding_priv_key.entropy_coder   = NULL;
    sc->coding_signature.type           = SC_ENTROPY_NONE;
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

    // Allocate memory for ring-TESLA configuration
    sc->ring_tesla = SC_MALLOC(sizeof(ring_tesla_cfg_t));
    if (NULL == sc->ring_tesla) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified ring-TESLA parameter set
    switch (set)
    {
        case 0:  sc->ring_tesla->params = &param_ring_tesla_0;
                 sc->ring_tesla->entropy = sc->coding_signature.type;
                 break;
        case 1:  sc->ring_tesla->params = &param_ring_tesla_1;
                 sc->ring_tesla->entropy = sc->coding_signature.type;
                 break;
        default: SC_FREE(sc->ring_tesla, sizeof(ring_tesla_cfg_t));
                 return SC_FUNC_FAILURE;
    }

    UINT16 n = sc->ring_tesla->params->n;

    // Initialise the reduction scheme
    sc->ring_tesla->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->ring_tesla->ntt, n, sc->ring_tesla->params->q);

    // Create pointers for the arithmetic functions used by ring-TESLA
    sc->sc_ntt = utils_arith_ntt(sc->ring_tesla->ntt_optimisation);
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
            sc->ring_tesla->oracle_hash = (512 == hash_length)? SC_HASH_BLAKE2_512 :
                                          (384 == hash_length)? SC_HASH_BLAKE2_384 :
                                          (256 == hash_length)? SC_HASH_BLAKE2_256 :
                                                                SC_HASH_BLAKE2_224;
        } break;
        case SC_FLAG_0_HASH_SHA2:
        {
            sc->ring_tesla->oracle_hash = (512 == hash_length)? SC_HASH_SHA2_512 :
                                          (384 == hash_length)? SC_HASH_SHA2_384 :
                                          (256 == hash_length)? SC_HASH_SHA2_256 :
                                                                SC_HASH_SHA2_224;
        } break;
        case SC_FLAG_0_HASH_SHA3:
        {
            sc->ring_tesla->oracle_hash = (512 == hash_length)? SC_HASH_SHA3_512 :
                                          (384 == hash_length)? SC_HASH_SHA3_384 :
                                          (256 == hash_length)? SC_HASH_SHA3_256 :
                                                                SC_HASH_SHA3_224;
        } break;
        case SC_FLAG_0_HASH_WHIRLPOOL:
        {
            sc->ring_tesla->oracle_hash = SC_HASH_WHIRLPOOL_512;
        } break;
        case SC_FLAG_0_HASH_FUNCTION_DEFAULT:
        default:
        {
            sc->ring_tesla->oracle_hash = sc->ring_tesla->params->oracle_hash;
        }
    }

    // Create the hash to be used by the random oracle
    sc->hash = utils_crypto_hash_create(sc->ring_tesla->oracle_hash);
    if (NULL == sc->hash) {
        return SC_FUNC_FAILURE;
    }

    // Retrieve the Gaussian Sampler standard deviation
    FLOAT sig = sc->ring_tesla->params->sig;

    // Initialise the random distribution sampler
    sc->sc_gauss = create_sampler(sc->sampling,
        sc->sampling_precision, sc->blinding, n, SAMPLING_DISABLE_BOOTSTRAP,
        sc->prng_ctx[0], sc->ring_tesla->params->bound/sig, sig);

#ifdef USE_RUNTIME_NTT_TABLES
    // Dynamically allocate memory for the necessary NTT tables
    SINT32 *temp = (SINT32*) SC_MALLOC(sizeof(SINT32) * 2 * n);
    sc->ring_tesla->params->w = temp;
    sc->ring_tesla->params->r = temp + n;
    roots_of_unity_s32(sc->ring_tesla->params->w, sc->ring_tesla->params->r,
        n, sc->ring_tesla->params->q, sc->ring_tesla->params->prim_root);
#endif

    // Dynamically allocate memory for temporary storage
    sc->temp_size = (6 * n) * sizeof(SINT32);
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            destroy_sampler(&sc->sc_gauss);
            SC_FREE(sc->ring_tesla, sizeof(ring_tesla_cfg_t));
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT32) * 2 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 ring_tesla_destroy(safecrypto_t *sc)
{
    UINT16 n;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->ring_tesla->params->n;

    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->ring_tesla->params->w, sizeof(SINT32) * 2 * n);
#endif

    destroy_sampler(&sc->sc_gauss);

    // Free all resources associated with key-pair and signature
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 3 * n * sizeof(SINT16));
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT32));
        sc->pubkey->len = 0;
    }

    if (sc->ring_tesla) {
        SC_FREE(sc->ring_tesla, sizeof(ring_tesla_cfg_t));
    }

#ifdef SC_THREADPOOLS
    const utils_threading_t *threading = utils_threading();
    threading->pool_destroy(threadpool, THREADPOOL_GRACEFUL_EXIT);
#endif

    SC_PRINT_DEBUG(sc, "ring-TESLA algorithm destroyed");

    return SC_FUNC_SUCCESS;
}

static SINT32 sig_entropy_init(safecrypto_t *sc, SINT32 set, sc_entropy_t *coding_pub_key,
    sc_entropy_t *coding_priv_key, sc_entropy_t *coding_signature)
{
    (void) sc;
    (void) set;
    (void) coding_signature;

    /*switch (coding_signature->type)
    {
    case SC_ENTROPY_BAC:
        switch (set)
        {
        case 4:
            if (!bliss_bac_code_4.initialized) {
                bliss_sig_destroy_bac(&bliss_bac_code_1);
                bliss_sig_destroy_bac(&bliss_bac_code_3);
                if (SC_FUNC_FAILURE == bliss_sig_create_bac(&bliss_bac_code_4)) {
                    return SC_FUNC_FAILURE;
                }
                coding_signature->entropy_coder = (void *) &bliss_bac_code_4;
            } break;
        case 3:
            if (!bliss_bac_code_3.initialized) {
                bliss_sig_destroy_bac(&bliss_bac_code_1);
                bliss_sig_destroy_bac(&bliss_bac_code_4);
                if (SC_FUNC_FAILURE == bliss_sig_create_bac(&bliss_bac_code_3)) {
                    return SC_FUNC_FAILURE;
                }
                coding_signature->entropy_coder = (void *) &bliss_bac_code_3;
            } break;
        case 1:
            if (!bliss_bac_code_1.initialized) {
                bliss_sig_destroy_bac(&bliss_bac_code_3);
                bliss_sig_destroy_bac(&bliss_bac_code_4);
                if (SC_FUNC_FAILURE == bliss_sig_create_bac(&bliss_bac_code_1)) {
                    return SC_FUNC_FAILURE;
                }
                coding_signature->entropy_coder = (void *) &bliss_bac_code_1;
            } break;
        }
        break;
    case SC_ENTROPY_STRONGSWAN:
        switch (set)
        {
            case 1:
                bliss_sig_destroy_bac(&bliss_bac_code_1);
                bliss_sig_destroy_bac(&bliss_bac_code_3);
                bliss_sig_destroy_bac(&bliss_bac_code_4);
                coding_signature->entropy_coder = (void *) &bliss_huffman_code_1;
                break;
            case 3:
                bliss_sig_destroy_bac(&bliss_bac_code_1);
                bliss_sig_destroy_bac(&bliss_bac_code_3);
                bliss_sig_destroy_bac(&bliss_bac_code_4);
                coding_signature->entropy_coder = (void *) &bliss_huffman_code_3;
                break;
            case 4:
                bliss_sig_destroy_bac(&bliss_bac_code_1);
                bliss_sig_destroy_bac(&bliss_bac_code_3);
                bliss_sig_destroy_bac(&bliss_bac_code_4);
                coding_signature->entropy_coder = (void *) &bliss_huffman_code_4;
                break;
        }
        break;
    default:
        bliss_sig_destroy_bac(&bliss_bac_code_1);
        bliss_sig_destroy_bac(&bliss_bac_code_3);
        bliss_sig_destroy_bac(&bliss_bac_code_4);
        coding_signature->entropy_coder = NULL;
    }*/

    switch (coding_pub_key->type)
    {
    default:
        coding_pub_key->type = SC_ENTROPY_NONE;
        coding_pub_key->entropy_coder = NULL;
    }

    switch (coding_priv_key->type)
    {
    default:
        coding_priv_key->type = SC_ENTROPY_NONE;
        coding_priv_key->entropy_coder = NULL;
    }

    return SC_FUNC_SUCCESS;
}

/// Extract a signed key polynomial from a byte stream
static SINT32 extract_signed_key(safecrypto_t *sc, SINT16 *sc_key,
    sc_entropy_t *coding, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, q_bits;
    SINT32 q_min, q_max;
    UINT32 sign, sign_extension, value;
    SINT32 s;

    n              = sc->ring_tesla->params->n;
    q_bits         = sc->ring_tesla->params->q_bits;
    sign           = 1 << (q_bits - 1);
    q_min          = -sign;
    q_max          = sign - 1;
    sign_extension = ((1 << (32 - q_bits)) - 1) << q_bits;

    sc_packer_t *packer = utils_entropy.pack_create(sc, coding,
        n * q_bits, key, key_len, NULL, 0);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    for (i=0; i<n; i++) {
        utils_entropy.pack_decode(packer, &value, q_bits);
        s = (value & sign)? sign_extension | value : value;
        if (s < q_min || s > q_max) {
            utils_entropy.pack_destroy(&packer);
            SC_LOG_ERROR(sc, SC_ERROR);
            return SC_FUNC_FAILURE;
        }
        sc_key[i] = s;
    }

    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

SINT32 ring_tesla_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    sig_entropy_init(sc, sc->ring_tesla->params->set, &sc->coding_pub_key,
        &sc->coding_priv_key, &sc->coding_signature);

    n = sc->ring_tesla->params->n;
    q_bits = sc->ring_tesla->params->q_bits;

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT32));
    }
    sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT32));
    if (NULL == sc->pubkey->key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Create a bit packer to extract the public key from the buffer
    SINT32 *pubkey = (SINT32 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, key, key_len, NULL, 0);
    if (NULL == packer) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT32));
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    for (i=0; i<2*n; i++) {
        UINT32 value;
        utils_entropy.pack_decode(packer, &value, q_bits);
        pubkey[i] = value;
    }
    utils_entropy.pack_destroy(&packer);
    sc->pubkey->len = 2 * n;

    return SC_FUNC_SUCCESS;
}

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 ring_tesla_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 ring_tesla_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    SINT16 *privkey;
    UINT16 n;

    n = sc->ring_tesla->params->n;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 3 * n * sizeof(SINT16));
    }
    sc->privkey->key = SC_MALLOC(3 * n * sizeof(SINT16));
    if (NULL == sc->privkey->key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Assign pointers to buffers
    privkey = (SINT16 *) sc->privkey->key;

    sc->coding_pub_key.type = SC_ENTROPY_NONE;
    sig_entropy_init(sc, sc->ring_tesla->params->set,
        &sc->coding_pub_key, &sc->coding_priv_key, &sc->coding_signature);

    // Extract the private key
    extract_signed_key(sc, privkey, &sc->coding_priv_key, key, key_len);
    sc->privkey->len = 3 * n;

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_CLIENT

#ifdef DISABLE_SIGNATURES_SERVER

SINT32 ring_tesla_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 ring_tesla_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 ring_tesla_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->ring_tesla->params->n;
    q_bits = sc->ring_tesla->params->q_bits;

    // Create a bit packer to compress the public key
    SINT32 *pubkey = (SINT32 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        2 * n * q_bits, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    sc->coding_pub_key.type = SC_ENTROPY_NONE;
    entropy_poly_encode_32(packer, n, pubkey, q_bits,
        SIGNED_COEFF, sc->coding_pub_key.type, 0, &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);
    entropy_poly_encode_32(packer, n, pubkey + n, q_bits,
        SIGNED_COEFF, sc->coding_pub_key.type, 0, &sc->stats.components[SC_STAT_PUB_KEY][1].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += n * q_bits;
    sc->stats.components[SC_STAT_PUB_KEY][1].bits += n * q_bits;
    sc->stats.components[SC_STAT_PUB_KEY][2].bits += 2 * n * q_bits;
    sc->stats.components[SC_STAT_PUB_KEY][2].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

SINT32 ring_tesla_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    UINT16 n, e_bits;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->ring_tesla->params->n;
    e_bits = sc->ring_tesla->params->e_bits;

    // Create a bit packer to compress the private key polynomial f
    SINT16 *privkey = (SINT16 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        3 * n * e_bits, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_16(packer, n, privkey, e_bits,
        SIGNED_COEFF, sc->coding_priv_key.type, 1, &packer->sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);
    entropy_poly_encode_16(packer, n, privkey + n, e_bits,
        SIGNED_COEFF, sc->coding_priv_key.type, 1, &packer->sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded);
    entropy_poly_encode_16(packer, n, privkey + 2*n, e_bits,
        SIGNED_COEFF, sc->coding_priv_key.type, 1, &packer->sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded);

    // Extract the buffer with the polynomial f and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += n * e_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][1].bits += n * e_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][2].bits += n * e_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][3].bits += 3 * n * e_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][3].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

#endif // DISABLE_SIGNATURES_SERVER

/// If the omega largest absolute values of coefficients from e sum to more
/// than L then return with failure.
static SINT32 check_e(safecrypto_t *sc, const SINT32 *e, UINT16 n)
{
    size_t i, j;
    UINT16 bound = sc->ring_tesla->params->bound;
    UINT16 omega = sc->ring_tesla->params->omega;

    // NOTE: This memory is used elsewhere but not yet ...
    SINT32 *vals = sc->temp + 3 * n;

    // Obtain the absolute coefficients of all polynomial elements
    for (i=0; i<n; i++) {
        vals[i] = (e[i] < 0)? -e[i] : e[i];
    }

    // Find the sum of the omega largest absolute coefficients
    UINT64 thresh = 0;
    for (i=0; i<omega; i++ ) {
        SINT32 max = 0;
        size_t pos = 0;
        for (j=0; j<(size_t)n; j++ ) {
            if (vals[j] > max) {
                max = vals[j];
                pos = j;
            }
        }

        vals[pos] = 0;
        thresh += (UINT64) max;
    }

    // If the sum of the absolute largest values exceeds a
    // predefined threshold then fail the check.
    if (thresh > bound) {
        SC_PRINT_DEBUG(sc, "checkE bound exceeded: %d > %d", thresh, bound);
        return SC_FUNC_FAILURE;
    }
    else {
        SC_PRINT_DEBUG(sc, "checkE bound is valid: %d > %d", thresh, bound);
        return SC_FUNC_SUCCESS;
    }
}

static SINT32 test_w(safecrypto_t *sc, SINT32 *w)
{
    size_t i;
    SINT32 left, right, val;
    UINT16 n      = sc->ring_tesla->params->n;
    UINT32 q      = sc->ring_tesla->params->q;
    UINT16 d      = sc->ring_tesla->params->d;
    UINT16 bound  = sc->ring_tesla->params->bound;
    UINT32 d_mask = (1 << d) - 1;
    SINT32 d_sub  = 1 << (d - 1);

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ring_tesla->ntt;

    right = d_sub - bound;

    for (i=0; i<n; i++)
    {
        val = sc_ntt->modn_32(w[i], ntt);
        if (val < 0) {
            val += q;
        }

        left = val & d_mask;
        left -= d_sub;
        left++;
        if (left < 0) left = -left;

        if (left > right)
        {
            SC_PRINT_DEBUG(sc, "i=%d [w=%d, val=%d], abs(left) > right, [%d > %d]\n",
                i, w[i], val, left, right);
            return 1;
        }
    }
    return 0;
}

static SINT32 test_rejection(safecrypto_t *sc, SINT32 *z)
{
    size_t i;
    UINT16 n = sc->ring_tesla->params->n;
    UINT32 b = sc->ring_tesla->params->b;
    UINT16 u = sc->ring_tesla->params->u;
    SINT32 thresh = b - u;

    for (i=n; i--;) {
        if (z[i] < -thresh || z[i] > thresh) {
            SC_PRINT_DEBUG(sc, "rejection: z[%d] = %d, thresh = %d\n", i, z[i], thresh);
            return 1;
        }
    }
    return 0;
}

SINT32 ring_tesla_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv)
{
    return SC_FUNC_FAILURE;
}


SINT32 ring_tesla_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv)
{
    return SC_FUNC_FAILURE;
}

#ifdef DISABLE_SIGNATURES_SERVER

SINT32 ring_tesla_keygen(safecrypto_t *sc)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

SINT32 ring_tesla_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 ring_tesla_keygen(safecrypto_t *sc)
{
    SINT32 i;
    SINT32 *s, *e1, *e2, *t1, *t2;
    UINT16 n;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "ring-TESLA KeyGen\n");

    n = sc->ring_tesla->params->n;

    // Allocate temporary memory
    s = sc->temp;
    if (NULL == s) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    e1 = s + n;
    e2 = s + 2 * n;
    t1 = s + 3 * n;
    t2 = s + 4 * n;

    sc->stats.keygen_num++;
    sc->stats.keygen_num_trials++;

    const SINT32 *w = sc->ring_tesla->params->w;
    const SINT32 *r = sc->ring_tesla->params->r;

    // Set pointers to the publicly shared constants a1 and a2
    const SINT32 *a1 = (0 == sc->ring_tesla->params->set)? a1_0 : a1_1;
    const SINT32 *a2 = (0 == sc->ring_tesla->params->set)? a2_0 : a2_1;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    utils_sampling_t* sc_gauss = sc->sc_gauss;
    ntt_params_t *ntt = &sc->ring_tesla->ntt;

    // Generate e1 and e2 from a discrete Gaussian distribution and
    // verify that the checkE() conditions are met
    // Generating e1
    do {
        get_vector_32(sc_gauss, e1, n, 0);
    } while (SC_FUNC_FAILURE == check_e(sc, e1, n));
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "e1", e1, n);

    // Generating e2
    do {
        get_vector_32(sc_gauss, e2, n, 0);
    } while (SC_FUNC_FAILURE == check_e(sc, e2, n));
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "e2", e2, n);

    // Generate s from a discrete Gaussian distribution
    // Generating s
    get_vector_32(sc_gauss, s, n, 0);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s", s, n);

    // Allocate key pair memory
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(3 * n * sizeof(SINT16));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT32));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, 2 * n * sizeof(SINT32));
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    // Store the secret key s
    SINT16 *key_priv;
    key_priv = (SINT16 *) sc->privkey->key;
    for (i=n; i--;) {
        key_priv[i] = s[i];
    }

    // Generate the public key as T = AS + E.
    // (Translate s to the NTT domain as it's already stored).
    sc_ntt->fwd_ntt_32_32(s, ntt, s, w);

    // Calculate t1' = a1 * s + e1
    sc_ntt->mul_32_pointwise(t1, ntt, s, a1);
    sc_ntt->inv_ntt_32_32(t1, ntt, t1, w, r);
    sc_poly->add_single_32(t1, n, e1);
    sc_ntt->center_32(t1, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t1", t1, n);

    // Calculate t2' = a2 * s + e2
    sc_ntt->mul_32_pointwise(t2, ntt, s, a2);
    sc_ntt->inv_ntt_32_32(t2, ntt, t2, w, r);
    sc_poly->add_single_32(t2, n, e2);
    sc_ntt->center_32(t2, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t2", t2, n);

    // Transfer the intermediate key pairs to the dedicated memory resource
    for (i=n; i--;) {
        key_priv[n+i] = e1[i];
        key_priv[2*n+i] = e2[i];
    }
    SINT32 *key = (SINT32 *) sc->pubkey->key;
    for (i=n; i--;) {
        key[i] = t1[i];
        key[n+i] = t2[i];
    }
    sc->privkey->len = 3 * n;
    sc->pubkey->len = 2 * n;

    SC_MEMZERO(s, 5 * n * sizeof(SINT32));
    SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 32);
    return SC_FUNC_SUCCESS;

finish_free:
    SC_MEMZERO(s, 5 * n * sizeof(SINT32));
    return SC_FUNC_FAILURE;
}

SINT32 ring_tesla_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
    SINT32 i, iter;
    SINT32 *t, *v1, *v2, *y, *z, *c;
    SINT16 *s, *e1, *e2;
    UINT16 n, q_bits, b_bits, omega;
    UINT32 b;
    UINT8 md[64];
    const SINT32 *w, *r;

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Assign values to commonly used variables
    n         = sc->ring_tesla->params->n;
    q_bits    = sc->ring_tesla->params->q_bits;
    omega     = sc->ring_tesla->params->omega;
    b         = sc->ring_tesla->params->b;
    b_bits    = sc->ring_tesla->params->b_bits;
    w         = sc->ring_tesla->params->w;
    r         = sc->ring_tesla->params->r;

    SC_PRINT_DEBUG(sc, "Initialising ring-TESLA signature variables\n");

    // Ensure that the entropy coders are initialized
    /*sc->coding_signature.type = (sc_entropy_type_e) entropy;
    sig_entropy_init(sc, sc->ring_tesla->params->set, &sc->coding_pub_key,
        &sc->coding_priv_key, &sc->coding_signature);*/

    // Allocate temporary memory
    t = sc->temp;
    if (NULL == t) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    c     = t + n;
    v1    = t + 2 * n;
    v2    = t + 3 * n;
    y     = t + 4 * n; // NOTE: Also used for oracle intermediate array
    z     = t + 5 * n;
    s     = (SINT16 *) sc->privkey->key;
    e1    = s + n;
    e2    = s + 2 * n;

    // Check for uninitialised keys
    if (NULL == s || NULL == e1 || NULL == e2) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Set pointers to the publicly shared constants a1 and a2
    const SINT32 *a1 = (0 == sc->ring_tesla->params->set)? a1_0 : a1_1;
    const SINT32 *a2 = (0 == sc->ring_tesla->params->set)? a2_0 : a2_1;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ring_tesla->ntt;

    sc->stats.sig_num++;

    // Trial to find a signature
    for (iter=0; iter<9999; iter++) {
        sc->stats.sig_num_trials++;

        SC_PRINT_DEBUG(sc, "Attempting to generate signature ...\n");

        // y is chosen to be uniformly random
        i = 0;
        do {
            SINT32 temp = prng_32(sc->prng_ctx[0]) & ((1 << (b_bits+1)) - 1);
            y[i++] = temp - b;
        } while (i < n);

        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "y", y, n);

        // Convert y  to the NTT domain
        sc_ntt->fwd_ntt_32_32(z, ntt, y, w);

        // Calculate v1 = INTT(y * a1)
        sc_ntt->mul_32_pointwise(v1, ntt, z, a1);
        sc_ntt->inv_ntt_32_32(v1, ntt, v1, w, r);

        // Calculate v2 = INTT(y * a2)
        sc_ntt->mul_32_pointwise(v2, ntt, z, a2);
        sc_ntt->inv_ntt_32_32(v2, ntt, v2, w, r);

        sc_ntt->center_32(v1, n, ntt);
        sc_ntt->center_32(v2, n, ntt);

        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v1", v1, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v2", v2, n);

        // Use a random oracle to generate c from the random
        // polynomials v1 and v2 and the input message m.
        oracle(sc, v1, v2, t, n, m, m_len, md);
        f_function(sc, md, t, c);

        SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "c'", md, 64);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "c", c, omega);

        // Check if the weight polynomials are sufficiently small
        sc_ntt->mul_32_sparse_16(z, n, omega, e1, c);
        sc_poly->sub_single_32(v1, n, z);
        sc_ntt->normalize_32(v1, n, ntt);
        if (test_w(sc, v1)) {
            continue;
        }
        sc_ntt->mul_32_sparse_16(z, n, omega, e2, c);
        sc_poly->sub_single_32(v2, n, z);
        sc_ntt->normalize_32(v2, n, ntt);
        if (test_w(sc, v2)) {
            continue;
        }

        // Calculate the signature z = y + s*c using sparse
        // polynomial multiplication
        sc_ntt->mul_32_sparse_16(z, n, omega, s, c);
        sc_poly->add_single_32(z, n, y);
        sc_ntt->center_32(z, n, ntt);
        if (test_rejection(sc, z)) {
            continue;
        }

        // Create a bit packer to compress the signature
        SC_PRINT_DEBUG(sc, "Signature compression after %d attempts\n", iter);
        sc_packer_t *packer;
        packer = utils_entropy.pack_create(sc, &sc->coding_signature,
            n * q_bits + 64 * 8, NULL, 0, sigret, siglen);
        if (NULL == packer) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            break;
        }
        entropy_poly_encode_32(packer, n, z, q_bits,
            SIGNED_COEFF, sc->coding_signature.type, 2, &sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded);
        entropy_poly_encode_8(packer, 64, md, 8,
            UNSIGNED_COEFF, SC_ENTROPY_NONE, 2, &sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded);
        utils_entropy.pack_get_buffer(packer, sigret, siglen);
        utils_entropy.pack_destroy(&packer);
        sc->stats.components[SC_STAT_SIGNATURE][0].bits += n * q_bits;
        sc->stats.components[SC_STAT_SIGNATURE][1].bits += 64 * 8;
        sc->stats.components[SC_STAT_SIGNATURE][2].bits += n * q_bits + 64 * 8;
        sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded += *siglen * 8;

        SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Compressed signature", *sigret, *siglen);

        SC_MEMZERO(sc->temp, 6 * n * sizeof(SINT32));
        return SC_FUNC_SUCCESS;
    }


    SC_MEMZERO(sc->temp, 6 * n * sizeof(SINT32));
    return SC_FUNC_FAILURE;
}

#endif // DISABLE_SIGNATURES_SERVER

#ifdef DISABLE_SIGNATURES_CLIENT

SINT32 ring_tesla_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 *sigbuf, size_t siglen)
{
    SC_LOG_ERROR(sc, SC_DISABLED_AT_COMPILE);
    return SC_FUNC_FAILURE;
}

#else

SINT32 ring_tesla_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
    SINT32 i;
    SINT32 *t, *z, *c, *w1, *w2;
    SINT32 *t1, *t2;
    UINT16 n, q_bits, omega;
    const SINT32 *w, *r;
    UINT8 md[64], sigmd[64];

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Initialising ring-TESLA verification variables\n");

    // Assign values to commonly used variables
    n         = sc->ring_tesla->params->n;
    q_bits    = sc->ring_tesla->params->q_bits;
    omega     = sc->ring_tesla->params->omega;
    w         = sc->ring_tesla->params->w;
    r         = sc->ring_tesla->params->r;

    // Set pointers to the publicly shared constants a1 and a2
    const SINT32 *a1 = (0 == sc->ring_tesla->params->set)? a1_0 : a1_1;
    const SINT32 *a2 = (0 == sc->ring_tesla->params->set)? a2_0 : a2_1;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ring_tesla->ntt;

    // Allocate temporary memory
    // NOTE: t + 4*n is also used for an oracle intermediate array
    t = sc->temp;
    if (NULL == t) {
        sc->stats.sig_num_unverified++;
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    z = t + n;
    c = t + 2 * n;
    w1 = t + 3 * n;
    w2 = t + 4 * n;
    t1 = (SINT32 *) sc->pubkey->key;
    t2 = t1 + n;

    // Check for an unitialised public key
    if (NULL == t1 || NULL == t2) {
        sc->stats.sig_num_unverified++;
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Compressed signature",
        sigbuf, siglen);

    // Decompress the signature
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_signature, 0,
        sigbuf, siglen, NULL, 0);
    if (NULL == packer) {
        sc->stats.sig_num_unverified++;
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    UINT32 value;
    entropy_poly_decode_32(packer, n, z, q_bits,
        SIGNED_COEFF, sc->coding_signature.type, 2);
    entropy_poly_decode_8(packer, 64, sigmd, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 3);
    utils_entropy.pack_destroy(&packer);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received z", z, n);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Received c'", sigmd, 64);

    // Verify that z is valid
    if (test_rejection(sc, z)) {
        SC_PRINT_ERROR(sc, "ring-TESLA signature error - z'\n");
        goto verification_early_failure;
    }

    // Generate the sparse polynomial c (as an index array)
    f_function(sc, sigmd, t, c);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "c", c, omega);

    // Translate z to the NTT domain
    sc_ntt->fwd_ntt_32_32(z, ntt, z, w);

    // Calculate w1' = a1 * z - t1 * c (mod q)
    sc_ntt->mul_32_pointwise(w1, ntt, z, a1);
    sc_ntt->inv_ntt_32_32(w1, ntt, w1, w, r);
    sc_ntt->mul_32_sparse(t, n, omega, t1, c);
    sc_poly->sub_single_32(w1, n, t);
    sc_ntt->normalize_32(w1, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received w1", w1, n);

    // Calculate w2' = a2 * z - t2 * c (mod q)
    sc_ntt->mul_32_pointwise(w2, ntt, z, a2);
    sc_ntt->inv_ntt_32_32(w2, ntt, w2, w, r);
    sc_ntt->mul_32_sparse(t, n, omega, t2, c);
    sc_poly->sub_single_32(w2, n, t);
    sc_ntt->normalize_32(w2, n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Received w2", w2, n);

    // Regenerate the random oracle output
    oracle(sc, w1, w2, t, n, m, m_len, md);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "c'", md, 64);

    for (i = 0; i < 64; i++) {
        if (md[i] != sigmd[i]) {
            goto verification_failure;
        }
    }

    SC_MEMZERO(sc->temp, 5 * n * sizeof(SINT32));

    sc->stats.sig_num_verified++;

    return SC_FUNC_SUCCESS;

verification_failure:
verification_early_failure:
    sc->stats.sig_num_unverified++;
    SC_LOG_ERROR(sc, SC_ERROR);
    return SC_FUNC_FAILURE;
}

#endif // DISABLE_SIGNATURES_CLIENT

char * ring_tesla_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I", "II", "III", "G-0", "G-I", "G-II", "G-III"};
    static char stats[2048];
    snprintf(stats, 2047, "\nRing-TESLA Signature (RING_TESLA-%s):\n\
Keys           %8" FMT_LIMB " key-pairs  / %8" FMT_LIMB " trials [%.6f trials per key-pair]\n\
Signatures     %8" FMT_LIMB " signatures / %8" FMT_LIMB " trials [%.6f trials per signature]\n\
Verifications  %8" FMT_LIMB " passed     / %8" FMT_LIMB " failed\n\n\
Sampler:                 %s\n\
PRNG:                    %s\n\
Oracle Hash:             %s\n\n\
Public Key compression:  %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   t1      %10.2f%13.2f%16.3f%%\n\
   t2      %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Private Key compression: %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   s       %10.2f%13.2f%16.3f%%\n\
   e1      %10.2f%13.2f%16.3f%%\n\
   e2      %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Signature compression:   %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   z       %10.2f%13.2f%16.3f%%\n\
   h       %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n",
        param_set_name[sc->ring_tesla->params->set],
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
        sc_hash_names[sc->ring_tesla->oracle_hash],
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
        sc_entropy_names[(int)sc->coding_signature.type],
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][0].bits,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][1].bits,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits/(DOUBLE)sc->stats.sig_num,
        (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded/(DOUBLE)sc->stats.sig_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_SIGNATURE][2].bits);
    return stats;
}


#undef FMT_LIMB
