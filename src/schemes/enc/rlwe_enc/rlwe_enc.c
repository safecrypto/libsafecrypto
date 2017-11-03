/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "rlwe_enc.h"
#include "rlwe_enc_params.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/prng.h"
#include "utils/arith/arith.h"
#include "utils/arith/sc_math.h"
#include "utils/entropy/packer.h"
#include "utils/entropy/entropy.h"
#include "utils/sampling/sampling.h"

#include <string.h>
#include <math.h>


#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif


SC_STRUCT_PACK_START
typedef struct rlwe_enc_cfg_t {
    rlwe_set_t *params;
    safecrypto_ntt_e ntt_optimisation;
    ntt_params_t ntt;
    sc_entropy_type_e  entropy;
} SC_STRUCT_PACKED rlwe_enc_cfg_t;
SC_STRUCT_PACK_END

SINT32 rlwe_enc_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    FLOAT sig;
    UINT16 n;

    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 2, 1, 0, 0, 2, 0)) {
        return SC_FUNC_FAILURE;
    }

    // Precomputation for entropy coding
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_priv_key.type            = SC_ENTROPY_NONE;
    sc->coding_encryption.type          = SC_ENTROPY_NONE;

    // Allocate memory for Ring-LWE Encryption configuration
    sc->rlwe_enc = SC_MALLOC(sizeof(rlwe_enc_cfg_t));
    if (NULL == sc->rlwe_enc) {
        return SC_FUNC_FAILURE;
    }

    // Check that the parameter set is valid
    if (set < 0 || set > 1) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified RLWE Encryption parameter set
    switch (set)
    {
        case 0: sc->rlwe_enc->params = &param_rlwe_enc_0;
                sc->rlwe_enc->entropy = flags[0] & 0xF;
                break;
        case 1: sc->rlwe_enc->params = &param_rlwe_enc_1;
                sc->rlwe_enc->entropy = flags[0] & 0xF;
                break;
        default:;
    }

    // Obtain the size of the polynomials
    n = sc->rlwe_enc->params->n;

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

    // Retrieve the Gaussian Sampler standard deviation
    sig = sc->rlwe_enc->params->sig;

    sc->rlwe_enc->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_BARRETT)?   SC_NTT_BARRETT :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->rlwe_enc->ntt, n, sc->rlwe_enc->params->q);

    sc->sc_ntt = utils_arith_ntt(sc->rlwe_enc->ntt_optimisation);
    sc->sc_poly = utils_arith_poly();

    // Initialise the random distribution sampler
    sc->sc_gauss = create_sampler(sc->sampling,
        sc->sampling_precision, sc->blinding, n, SAMPLING_DISABLE_BOOTSTRAP,
        sc->prng_ctx[0], 13.0, sig);

#ifdef USE_RUNTIME_NTT_TABLES
    // Dynamically allocate memory for the necessary NTT tables
    SINT16 *temp = (SINT16*) SC_MALLOC(sizeof(SINT16) * 2 * n);
    sc->rlwe_enc->params->w = temp;
    sc->rlwe_enc->params->r = temp + n;
    roots_of_unity_s16(sc->rlwe_enc->params->w, sc->rlwe_enc->params->r,
        n, sc->rlwe_enc->params->q, 0);
#endif

    // Dynamically allocate memory for temporary storage
    sc->temp_size = 6 * n * sizeof(SINT32);
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            destroy_sampler(&sc->sc_gauss);
            SC_FREE(sc->rlwe_enc, sizeof(rlwe_enc_cfg_t));
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT16) * 2 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

    return SC_FUNC_SUCCESS;
}


SINT32 rlwe_enc_destroy(safecrypto_t *sc)
{
    UINT16 n;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->rlwe_enc->params->n;

    // Free resources associated with temporary variable storage
    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

    // Free resources associated with the Gaussian sampler
    destroy_sampler(&sc->sc_gauss);

    // Free all resources associated with the key-pair
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, n * sizeof(SINT16));
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT16));
        sc->pubkey->len = 0;
    }

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->rlwe_enc->params->w, sizeof(SINT16) * 2 * n);
#endif

    if (sc->rlwe_enc) {
        SC_FREE(sc->rlwe_enc, sizeof(rlwe_enc_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "Ring-LWE Encryption algorithm destroyed");

    return SC_FUNC_SUCCESS;
}

static void a_gen(safecrypto_t *sc, SINT32 *a, ntt_params_t *p)
{
    UINT32 i, r;
    const SINT16 *w;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;

    w = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->w_rev : sc->rlwe_enc->params->w;

    // a is uniformly random
    for (i = 0; i < p->n >> 1; i++) {
        r = prng_32(sc->prng_ctx[0]);
        a[2 * i] = sc_ntt->modn_32(r & 0xffff, p);
        a[2 * i + 1] = sc_ntt->modn_32(r >> 16, p);
    }

    // Forward NTT transform
    sc_ntt->fwd_ntt_32_16(a, p, a, w);

    // Place the vector coefficients within range of the modulus
    sc_ntt->normalize_32(a, p->n, p);
}

static void r1_gen(safecrypto_t *sc, SINT32 *r1, ntt_params_t *p)
{
    const SINT16 *w;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    utils_sampling_t *sc_gauss = sc->sc_gauss;

    w = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->w_rev : sc->rlwe_enc->params->w;

    // r1 has a generated from a discretized Gaussian distribution
    get_vector_32(sc_gauss, r1, p->n, 0);

    // Forward NTT transform
    sc_ntt->fwd_ntt_32_16(r1, p, r1, w);

    // Place the vector coefficients within range of the modulus
    sc_ntt->normalize_32(r1, p->n, p);
}

static void r2_gen(safecrypto_t *sc, SINT32 *r2, ntt_params_t *p)
{
    UINT16 i, j, bit, sign;
    UINT32 r;
    SINT32 n = p->n;
    const SINT16 *w;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;

    w = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->w_rev : sc->rlwe_enc->params->w;

#if 0
    // r2 has a generated from a discretized Gaussian distribution
    get_vector_32(sc->sc_gauss, r2, n, 0);
#else
    // r2 is generated from a random uniform distribution with binary coefficients
    for (i=0; i<n;) {
        r = prng_32(sc->prng_ctx[0]);

        for (j = 0; j < 16; j++) {
            bit = r & 1;
            sign = (r >> 1) & 1;
            if (1 == sign && 1 == bit)
                bit = (p->u.ntt32.q - 1);
            r2[i++] = bit;
            r = r >> 2;
        }
    }
#endif

    // Forward NTT transform
    sc_ntt->fwd_ntt_32_16(r2, p, r2, w);

    // Place the vector coefficients within range of the modulus
    sc_ntt->normalize_32(r2, n, p);
}

SINT32 rlwe_enc_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n = sc->rlwe_enc->params->n;
    q_bits = sc->rlwe_enc->params->q_bits;

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * n * sizeof(SINT16));
    }
    sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
    if (NULL == sc->pubkey->key) {
        return SC_FUNC_FAILURE;
    }

    // Create a bit packer to extract the public key from the buffer
    SINT16 *pubkey = (SINT16 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        2 * n * q_bits, key, key_len, NULL, 0);
    entropy_poly_decode_16(packer, n, pubkey, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0);
    entropy_poly_decode_16(packer, n, pubkey + n, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0);
    utils_entropy.pack_destroy(&packer);

    sc->pubkey->len = 2 * n;

    return SC_FUNC_SUCCESS;
}

SINT32 rlwe_enc_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    UINT16 n, q_bits;

    n = sc->rlwe_enc->params->n;
    q_bits = sc->rlwe_enc->params->q_bits;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, n * sizeof(SINT16));
    }
    sc->privkey->key = SC_MALLOC(n * sizeof(SINT16));
    if (NULL == sc->privkey->key) {
        return SC_FUNC_FAILURE;
    }

    // Create a bit packer to extract the private key polynomial from the buffer
    SINT16 *privkey = (SINT16 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        n * q_bits, key, key_len, NULL, 0);
    entropy_poly_decode_16(packer, n, privkey, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0);
    utils_entropy.pack_destroy(&packer);

    sc->privkey->len = n;

    return SC_FUNC_SUCCESS;
}

SINT32 rlwe_enc_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n = sc->rlwe_enc->params->n;
    q_bits = sc->rlwe_enc->params->q_bits;

    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += n * q_bits;
    sc->stats.components[SC_STAT_PUB_KEY][1].bits += n * q_bits;
    sc->stats.components[SC_STAT_PUB_KEY][2].bits += 2 * n * q_bits;

    // Create a bit packer to compress the public key
    SINT16 *pubkey = (SINT16 *) sc->pubkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        2 * n * q_bits, NULL, 0, key, key_len);
    entropy_poly_encode_16(packer, n, pubkey, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);
    entropy_poly_encode_16(packer, n, pubkey + n, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_PUB_KEY][1].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PUB_KEY][2].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

SINT32 rlwe_enc_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    UINT16 n, q_bits;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n = sc->rlwe_enc->params->n;
    q_bits = sc->rlwe_enc->params->q_bits;

    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += n * q_bits;

    // Create a bit packer to compress the private key polynomial f
    SINT16 *privkey = (SINT16 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        n * q_bits, NULL, 0, key, key_len);
    entropy_poly_encode_16(packer, n, privkey, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);

    // Extract the buffer with the polynomial f and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

SINT32 rlwe_enc_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv)
{
    return SC_FUNC_FAILURE;
}


SINT32 rlwe_enc_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv)
{
    return SC_FUNC_FAILURE;
}

SINT32 rlwe_enc_keygen(safecrypto_t *sc)
{
    size_t i;
    SINT32 *r2, *a, *r1;
    SINT16 *r2_16, *a_16, *r1_16;
    UINT16 n;
    ntt_params_t *ntt;
    const utils_arith_ntt_t *sc_ntt;
    const utils_arith_poly_t *sc_poly;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Ring-LWE Encryption KeyGen\n");

    n       = sc->rlwe_enc->params->n;
    ntt     = &sc->rlwe_enc->ntt;
    sc_ntt  = sc->sc_ntt;
    sc_poly = sc->sc_poly;

    // Allocate key pair memory
    SC_PRINT_DEBUG(sc, "Memory allocation for keys\n");
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(n * sizeof(SINT16));
        if (NULL == sc->privkey->key) {
            goto finish_free;
        }
    }
    sc->privkey->len = n;
    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, n * sizeof(SINT16));
            goto finish_free;
        }
    }
    sc->pubkey->len = 2 * n;

    // Gather statistics
    sc->stats.keygen_num++;

    // Assign pointers to the key-pair memory
    r2    = sc->temp;
    a     = sc->temp + n;
    r1    = sc->temp + 2 * n;
    r2_16 = (SINT16*) sc->privkey->key;
    a_16  = (SINT16*) sc->pubkey->key;
    r1_16 = (SINT16*) (sc->pubkey->key + n * sizeof(SINT16));

    // Generate random polynomial a
    a_gen(sc, a, ntt);

    // Generate r1 using Gaussian sampling
    r1_gen(sc, r1, ntt);

    // Generate r2 using random binary bits
    r2_gen(sc, r2, ntt);

    // Calculate r1 = r1 - a * r2
    for (i = 0; i < n; i++) {
        a_16[i] = a[i];
        r2_16[i] = r2[i];
    }
    sc_ntt->mul_32_pointwise(a, ntt, a, r2);
    sc_poly->sub_single_32(r1, n, a);
    sc_ntt->normalize_32(r1, n, ntt);
    for (i = 0; i < n; i++) {
        r1_16[i] = r1[i];
    }

    SC_PRINT_DEBUG(sc, "Print keys\n");
    SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 16);
    return SC_FUNC_SUCCESS;

finish_free:
    return SC_FUNC_FAILURE;
}

SINT32 rlwe_enc_encrypt(safecrypto_t *sc, size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    SINT32 i;
    UINT16 n, q_bits, m_scale;
    SINT32 *e1, *e2, *e3;
    SINT32 *c1, *c2;
    SINT16 *a, *p;
    SINT32 *enc_m;
    const SINT16 *w, *w_inv, *r;
    const UINT8 *in = from;
    ntt_params_t *ntt;
    const utils_arith_ntt_t *sc_ntt;
    const utils_arith_poly_t *sc_poly;
    utils_sampling_t *sc_gauss;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Increment the statistics for encryption
    sc->stats.encrypt_num++;

    // Assign values to commonly used variables
    n        = sc->rlwe_enc->params->n;
    q_bits   = sc->rlwe_enc->params->q_bits;
    m_scale  = sc->rlwe_enc->params->m_scale;
    w        = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->w_rev : sc->rlwe_enc->params->w;
    w_inv    = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->w_inv : sc->rlwe_enc->params->w;
    r        = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->r_inv : sc->rlwe_enc->params->r;
    ntt      = &sc->rlwe_enc->ntt;
    sc_ntt   = sc->sc_ntt;
    sc_poly  = sc->sc_poly;
    sc_gauss = sc->sc_gauss;

    // Verify that the message is N bits in length
    if (flen != (n>>3)) {
        return SC_FUNC_FAILURE;
    }

    // Obtain pointers to temporary storage variables
    e1       = sc->temp;
    e2       = sc->temp + n;
    e3       = sc->temp + 2 * n;
    enc_m    = sc->temp + 3 * n;
    c1       = sc->temp + 4 * n;
    c2       = sc->temp + 5 * n;

    // Obtain pointers to the public key
    a        = (SINT16 *) sc->pubkey->key;
    p        = (SINT16 *) sc->pubkey->key + n;

    // Create the bit packer used to create the output stream
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_encryption,
        2 * n * q_bits, NULL, 0, to, tlen);

    // Encoding of message
    SC_PRINT_DEBUG(sc, "Encoding %d bits\n", n);
    for (i = 0; i < n; i+=8) {
        enc_m[i  ] = ((*in >> 7) & 0x1) * m_scale;
        enc_m[i+1] = ((*in >> 6) & 0x1) * m_scale;
        enc_m[i+2] = ((*in >> 5) & 0x1) * m_scale;
        enc_m[i+3] = ((*in >> 4) & 0x1) * m_scale;
        enc_m[i+4] = ((*in >> 3) & 0x1) * m_scale;
        enc_m[i+5] = ((*in >> 2) & 0x1) * m_scale;
        enc_m[i+6] = ((*in >> 1) & 0x1) * m_scale;
        enc_m[i+7] = ((*in     ) & 0x1) * m_scale;
        in++;
    }

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Plaintext", enc_m, n);

    // Gaussian sampling of error vectors
    get_vector_32(sc_gauss, e1, n, 0);
    get_vector_32(sc_gauss, e2, n, 0);
    get_vector_32(sc_gauss, e3, n, 0);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Error distribution e1", e1, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Error distribution e2", e2, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Error distribution e3", e3, n);

    // NTT of error vectors e1 and e2
    sc_ntt->fwd_ntt_32_16(e1, ntt, e1, w);
    sc_ntt->fwd_ntt_32_16(e2, ntt, e2, w);

    // Calculate c1 = a * e1 + e2
    sc->sc_ntt->mul_32_pointwise_16(c1, ntt, e1, a);
    sc_poly->add_single_32(c1, n, e2);
#ifndef RLWE_ENC_ENABLE_NTT_TRANSMISSION
    sc_ntt->inv_ntt_32_16(c1, ntt, c1, w_inv, r);
#endif
    sc_ntt->normalize_32(c1, n, ntt);

    // Calculate c2 = INTT(p * e1) + e3 + Encode(m)
    sc_ntt->mul_32_pointwise_16(c2, ntt, e1, p);
    sc_ntt->inv_ntt_32_16(c2, ntt, c2, w_inv, r);
    sc_poly->add_single_32(c2, n, enc_m);
    sc_poly->add_single_32(c2, n, e3);
    sc_ntt->normalize_32(c2, n, ntt);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encrypt c1", c1, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Encrypt c2", c2, n);

    // Bit packing
    entropy_poly_encode_32(packer, n, c1, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_ENCRYPT][0].bits_coded);
    sc->stats.components[SC_STAT_ENCRYPT][0].bits += q_bits*n;
    entropy_poly_encode_32(packer, n, c2, q_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_ENCRYPT][1].bits_coded);
    sc->stats.components[SC_STAT_ENCRYPT][1].bits += q_bits*n;

    // Extracting buffer
    utils_entropy.pack_get_buffer(packer, to, tlen);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Ciphertext", *to, *tlen);
    utils_entropy.pack_destroy(&packer);
    sc->stats.components[SC_STAT_ENCRYPT][2].bits += q_bits*n*2;
    sc->stats.components[SC_STAT_ENCRYPT][2].bits_coded += *tlen * 8;

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, 6 * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;
}

SINT32 rlwe_enc_decrypt(safecrypto_t *sc, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
    size_t i;
    UINT16 n, q_bits, o_scale_0, o_scale_1;
    SINT32 *c1, *c2;
    SINT16 *r2;
    const SINT16 *w, *w_inv, *r;
    ntt_params_t *ntt;
    const utils_arith_ntt_t *sc_ntt;
    const utils_arith_poly_t *sc_poly;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Increment the statistics for encryption
    sc->stats.decrypt_num++;

    // Assign values to commonly used variables
    n         = sc->rlwe_enc->params->n;
    q_bits    = sc->rlwe_enc->params->q_bits;
    o_scale_0 = sc->rlwe_enc->params->o_scale_0;
    o_scale_1 = sc->rlwe_enc->params->o_scale_1;
    w         = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->w_rev : sc->rlwe_enc->params->w;
    w_inv     = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->w_inv : sc->rlwe_enc->params->w;
    r         = (sc->rlwe_enc->ntt_optimisation >= SC_NTT_REFERENCE_REV)? sc->rlwe_enc->params->r_inv : sc->rlwe_enc->params->r;
    ntt       = &sc->rlwe_enc->ntt;
    sc_ntt    = sc->sc_ntt;
    sc_poly   = sc->sc_poly;

    // Obtain pointers to temporary storage variables
    c1 = sc->temp;
    c2 = sc->temp + n;
    r2 = (SINT16 *) sc->privkey->key;

    // Create packers to obtain the data from the byte stream
    size_t message_length = (8 * flen) / (2 * q_bits);
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
    };
    sc_packer_t *ipacker, *opacker;
    ipacker  = utils_entropy.pack_create(sc, &sc->coding_encryption,
        0, from, flen, NULL, 0);
    opacker = utils_entropy.pack_create(sc, &coding_raw,
        message_length, NULL, 0, to, tlen);

    // Decode the data and decrypt it
    if (utils_entropy.pack_is_data_avail(ipacker)) {
        entropy_poly_decode_32(ipacker, n, c1, q_bits,
            UNSIGNED_COEFF, SC_ENTROPY_NONE, 0);
        entropy_poly_decode_32(ipacker, n, c2, q_bits,
            UNSIGNED_COEFF, SC_ENTROPY_NONE, 0);

        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Decrypt c1", c1, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Decrypt c2", c2, n);

        // INTT(c1 * r2)
#ifndef RLWE_ENC_ENABLE_NTT_TRANSMISSION
        sc_ntt->fwd_ntt_32_16(c1, ntt, c1, w);
#endif
        sc_ntt->mul_32_pointwise_16(c1, ntt, c1, r2);
        sc_ntt->inv_ntt_32_16(c1, ntt, c1, w_inv, r);

        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "INTT(c1*r2)", c1, n);

        sc_poly->add_single_32(c2, n, c1);
        sc_ntt->normalize_32(c2, n, ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "INTT(c1*r2) + c2", c2, n);

        // Decode the binary symbols and reconstitute the message
        for (i = 0; i < n; i++) {
            c2[i] = (c2[i] > o_scale_0 && c2[i] < o_scale_1)? 1 : 0;
        }
        entropy_poly_encode_32(opacker, n, c2, 1,
            UNSIGNED_COEFF, SC_ENTROPY_NONE, 0, NULL);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Deciphered message", c2, n);
    }

    // Release all resources associated with the packers and obtain the
    // buffer with the plaintext byte stream
    utils_entropy.pack_destroy(&ipacker);
    utils_entropy.pack_get_buffer(opacker, to, tlen);
    utils_entropy.pack_destroy(&opacker);

    SC_MEMZERO(sc->temp, 2 * n * sizeof(SINT32));
    return SC_FUNC_SUCCESS;
}

char * rlwe_enc_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I"};
    static char stats[2048];
    snprintf(stats, 2047, "\nRLWE Encryption (RLWE_ENC-%s):\n\
Keys           %8" FMT_LIMB " key-pairs\n\
Encryptions    %8" FMT_LIMB "\n\
Decryptions    %8" FMT_LIMB "\n\n\
Sampler:                 %s\n\
PRNG:                    %s\n\
Public Key compression:  %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   a       %10.2f%13.2f%16.3f%%\n\
   r1      %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Private Key compression: %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Encryption compression:   %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   c1      %10.2f%13.2f%16.3f%%\n\
   c2      %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n",
        param_set_name[sc->rlwe_enc->params->set],
        sc->stats.keygen_num,
        sc->stats.encrypt_num,
        sc->stats.decrypt_num,
        sc_sampler_names[sc->sampling],
        safecrypto_prng_names[(int)prng_get_type(sc->prng_ctx[0])],
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
        sc_entropy_names[(int)sc->coding_encryption.type],
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits/(DOUBLE)sc->stats.encrypt_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits_coded/(DOUBLE)sc->stats.encrypt_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][0].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits/(DOUBLE)sc->stats.encrypt_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits_coded/(DOUBLE)sc->stats.encrypt_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][1].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits/(DOUBLE)sc->stats.encrypt_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits_coded/(DOUBLE)sc->stats.encrypt_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCRYPT][2].bits);

    return stats;
}


#undef FMT_LIMB
