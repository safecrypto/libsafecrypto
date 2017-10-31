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

#include "kyber_kem.h"
#include "kyber_kem_params.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/arith/arith.h"
#include "utils/arith/module_lwe.h"
#include "utils/arith/ntt.h"
#include "utils/arith/sc_math.h"
#include "utils/entropy/packer.h"
#include "utils/entropy/entropy.h"

#include <string.h>
#include <math.h>


#if __WORDSIZE == 64
#define FMT_LIMB    "lu"
#else
#define FMT_LIMB    "d"
#endif


#define KYBER_KEM_PRIVKEY_SIZE    ((2 + KYBER_KEM_STORE_NTT_T) * k * n * sizeof(SINT32) + 32*8*2)
#define KYBER_KEM_PUBKEY_SIZE     ((1 + KYBER_KEM_STORE_NTT_T) * k * n * sizeof(SINT32) + 32)

#ifdef KYBER_KEM_USE_CSPRNG_SAM
#define KYBER_KEM_CSPRNG_ENABLED   MODULE_LWE_ENC_CSPRNG_ENABLED
#else
#define KYBER_KEM_CSPRNG_ENABLED   MODULE_LWE_ENC_CSPRNG_DISABLED
#endif


SINT32 kyber_kem_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    UINT32 n, k;

    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 1, 1, 0, 0, 0, 3)) {
        return SC_FUNC_FAILURE;
    }

    // Precomputation for entropy coding
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_pub_key.entropy_coder    = NULL;
    sc->coding_priv_key.type            = SC_ENTROPY_NONE;
    sc->coding_priv_key.entropy_coder   = NULL;
    sc->coding_encryption.type          = SC_ENTROPY_NONE;
    sc->coding_encryption.entropy_coder = NULL;

    // Allocate memory for KYBER-KEM configuration
    sc->kyber = SC_MALLOC(sizeof(kyber_cfg_t));
    if (NULL == sc->kyber) {
        return SC_FUNC_FAILURE;
    }

    // Check that the parameter set is valid
    if (set < 0 || set > 3) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified RLWE Encryption parameter set
    switch (set)
    {
        case 0: sc->kyber->params = &param_kyber_kem_0;
                sc->kyber->entropy = flags[0] & 0xF;
                break;
        case 1: sc->kyber->params = &param_kyber_kem_1;
                sc->kyber->entropy = flags[0] & 0xF;
                break;
        case 2: sc->kyber->params = &param_kyber_kem_2;
                sc->kyber->entropy = flags[0] & 0xF;
                break;
        default:;
    }

    n = sc->kyber->params->n;
    k = sc->kyber->params->k;

    // Initialise the reduction scheme
    sc->kyber->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_BARRETT)?   SC_NTT_BARRETT :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->kyber->ntt, n, sc->kyber->params->q);

    // Create pointers for the arithmetic functions used by Whole KEM
    sc->sc_ntt = utils_arith_ntt(sc->kyber->ntt_optimisation);
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
            sc->kyber->oracle_hash = (512 == hash_length)? SC_HASH_BLAKE2_512 :
                                     (384 == hash_length)? SC_HASH_BLAKE2_384 :
                                     (256 == hash_length)? SC_HASH_BLAKE2_256 :
                                                           SC_HASH_BLAKE2_224;
        } break;
        case SC_FLAG_0_HASH_SHA2:
        {
            sc->kyber->oracle_hash = (512 == hash_length)? SC_HASH_SHA2_512 :
                                     (384 == hash_length)? SC_HASH_SHA2_384 :
                                     (256 == hash_length)? SC_HASH_SHA2_256 :
                                                           SC_HASH_SHA2_224;
        } break;
        case SC_FLAG_0_HASH_SHA3:
        {
            sc->kyber->oracle_hash = (512 == hash_length)? SC_HASH_SHA3_512 :
                                     (384 == hash_length)? SC_HASH_SHA3_384 :
                                     (256 == hash_length)? SC_HASH_SHA3_256 :
                                                           SC_HASH_SHA3_224;
        } break;
        case SC_FLAG_0_HASH_WHIRLPOOL:
        {
            sc->kyber->oracle_hash = SC_HASH_WHIRLPOOL_512;
        } break;
        case SC_FLAG_0_HASH_FUNCTION_DEFAULT:
        default:
        {
            sc->kyber->oracle_hash = sc->kyber->params->oracle_hash;
        }
    }

    // Create the hash to be used by the random oracle
    sc->hash = utils_crypto_hash_create(sc->kyber->oracle_hash);
    if (NULL == sc->hash) {
        return SC_FUNC_FAILURE;
    }

    // Create the XOF to be used by the random oracle
    sc->xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128);
    if (NULL == sc->xof) {
        return SC_FUNC_FAILURE;
    }

#ifdef USE_RUNTIME_NTT_TABLES
    // Dynamically allocate memory for the necessary NTT tables
    SINT16 *temp = (SINT16*) SC_MALLOC(sizeof(SINT16) * 2 * n);
    sc->kyber->params->w = temp;
    sc->kyber->params->r = temp + n;
    roots_of_unity_s16(sc->kyber->params->w, sc->kyber->params->r,
        n, sc->kyber->params->q, 0);
#endif

    // Dynamically allocate memory for temporary storage
    sc->temp_size = (5 * k + 2) * n * sizeof(SINT32) + 6*32;
    if (!sc->temp_external_flag) {    
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            utils_crypto_hash_destroy(sc->hash);
            SC_FREE(sc->temp, (5 * k + 2) * n * sizeof(SINT32) + 6*32);
            SC_FREE(sc->kyber, sizeof(kyber_cfg_t));
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT16) * 2 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

    return SC_FUNC_SUCCESS;
}


SINT32 kyber_kem_destroy(safecrypto_t *sc)
{
    UINT32 n, k;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->kyber->params->n;
    k = sc->kyber->params->k;

    // Free resources associated with temporary variable storage
    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

    // Free all resources associated with the key-pair
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, KYBER_KEM_PRIVKEY_SIZE);
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, KYBER_KEM_PUBKEY_SIZE);
        sc->pubkey->len = 0;
    }

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->kyber->params->w, sizeof(SINT16) * 2 * n);
#endif

    if (sc->kyber) {
        utils_crypto_hash_destroy(sc->hash);
        utils_crypto_xof_destroy(sc->xof);
        SC_FREE(sc->kyber, sizeof(kyber_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "KYBER-KEM scheme destroyed\n");

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_kem_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT32 n, k, dt_bits, q;
    SINT32 *t;
#if KYBER_KEM_STORE_NTT_T == 1
    SINT32 *t_ntt;
#endif
    UINT8 *rho;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n = sc->kyber->params->n;
    k = sc->kyber->params->k;
    dt_bits = sc->kyber->params->d_t;
    q = sc->kyber->params->q;

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, KYBER_KEM_PUBKEY_SIZE);
    }
    sc->pubkey->key = SC_MALLOC(KYBER_KEM_PUBKEY_SIZE);
    if (NULL == sc->pubkey->key) {
        return SC_FUNC_FAILURE;
    }

    t     = (SINT32 *) sc->pubkey->key;
#if KYBER_KEM_STORE_NTT_T == 1
    t_ntt = t + k*n;
    rho   = (UINT8 *)(t_ntt + k*n);
#else
    rho   = (UINT8 *)(t + k*n);
#endif

    // Create a bit packer to extract the public key from the buffer
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        0, key, key_len, NULL, 0);
    entropy_poly_decode_32(packer, k * n, t, dt_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    entropy_poly_decode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    utils_entropy.pack_destroy(&packer);

    sc->pubkey->len = k * n + 32;

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    mlwe_decompress(t, n, k, dt_bits, q);
    sc_ntt->normalize_32(t, k*n, ntt);

#if KYBER_KEM_STORE_NTT_T == 1
    // If t is stored in the NTT domain it must be converted to the normal domain
    const SINT16 *ntt_w = sc->kyber->params->w;
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(t_ntt + i*n, ntt, t + i*n, ntt_w);
    }
    sc_ntt->center_32(t_ntt, k*n, ntt);
#endif

    /*fprintf(stderr, "load t: ");
    for (i=0; i<n*k; i++) {
        fprintf(stderr, "%d ", t[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "load t_ntt: ");
    for (i=0; i<n*k; i++) {
        fprintf(stderr, "%d ", t_ntt[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "load rho: ");
    for (i=0; i<32; i++) {
        fprintf(stderr, "%d ", rho[i]);
    }
    fprintf(stderr, "\n");*/

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_kem_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT32 n, k, dt_bits, eta_bits, q, q_inv, q_norm;
    SINT32 *s, *t;
#if KYBER_KEM_STORE_NTT_T == 1
    SINT32 *t_ntt;
#endif
    UINT8 *z, *rho;

    n        = sc->kyber->params->n;
    k        = sc->kyber->params->k;
    dt_bits  = sc->kyber->params->d_t;
    eta_bits = sc->kyber->params->eta_bits;
    q        = sc->kyber->params->q;
    q_inv    = sc->kyber->params->q_inv;
    q_norm   = sc->kyber->params->q_norm;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, KYBER_KEM_PRIVKEY_SIZE);
    }
    sc->privkey->key = SC_MALLOC(KYBER_KEM_PRIVKEY_SIZE);
    if (NULL == sc->privkey->key) {
        return SC_FUNC_FAILURE;
    }

    // Assign pointers to the key parameters
    s     = (SINT32 *) sc->privkey->key;
    t     = s + k*n;
#if KYBER_KEM_STORE_NTT_T == 1
    t_ntt = t + k*n;
    z     = (UINT8 *)(t_ntt + k*n);
#else
    z     = (UINT8 *)(t + k*n);
#endif
    rho   = z + 32;

    // Create a bit packer to extract the private key polynomial from the buffer
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        0, key, key_len, NULL, 0);
    entropy_poly_decode_32(packer, k * n, s, eta_bits,
        SIGNED_COEFF, sc->coding_priv_key.type);
    entropy_poly_decode_8(packer, 32, z, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    entropy_poly_decode_32(packer, k * n, t, dt_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    entropy_poly_decode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    utils_entropy.pack_destroy(&packer);

    sc->privkey->len = 2 * k * n + 64;

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    mlwe_decompress(t, n, k, dt_bits, q);
    sc_ntt->normalize_32(t, k*n, ntt);

#if KYBER_KEM_STORE_NTT_T == 1 || KYBER_KEM_STORE_NTT_S == 1
    const SINT16 *ntt_w = sc->kyber->params->w;
#endif

#if KYBER_KEM_STORE_NTT_T == 1
    // If t is stored in the NTT domain it must be converted from the normal domain
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(t_ntt + i*n, ntt, t + i*n, ntt_w);
    }
    sc_ntt->center_32(t_ntt, k*n, ntt);
#endif

#if KYBER_KEM_STORE_NTT_S == 1
    // If s is stored in the NTT domain it must be converted from the normal domain
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(s + i*n, ntt, s + i*n, ntt_w);
    }
    sc_ntt->center_32(s, k*n, ntt);
#endif

    return SC_FUNC_SUCCESS;

load_failure:
    SC_FREE(sc->privkey->key, KYBER_KEM_PRIVKEY_SIZE);
    return SC_FUNC_FAILURE;
}

SINT32 kyber_kem_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT32 n, k, dt_bits, q, q_inv, q_norm;
    SINT32 *t;
#if KYBER_KEM_STORE_NTT_T == 1
    SINT32 *t_ntt;
#endif
    UINT8 *rho;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n        = sc->kyber->params->n;
    k        = sc->kyber->params->k;
    dt_bits  = sc->kyber->params->d_t;
    q        = sc->kyber->params->q;
    q_inv    = sc->kyber->params->q_inv;
    q_norm   = sc->kyber->params->q_norm;

    t     = (SINT32 *) sc->pubkey->key;
#if KYBER_KEM_STORE_NTT_T == 1
    t_ntt = t + k*n;
    rho   = (UINT8 *)(t_ntt + k*n);
#else
    rho   = (UINT8 *)(t + k*n);
#endif

    /*fprintf(stderr, "t: ");
    for (i=0; i<n*k; i++) {
        fprintf(stderr, "%d ", t[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "t_ntt: ");
    for (i=0; i<n*k; i++) {
        fprintf(stderr, "%d ", t_ntt[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "rho: ");
    for (i=0; i<32; i++) {
        fprintf(stderr, "%d ", rho[i]);
    }
    fprintf(stderr, "\n");*/

    SINT32 *temp = sc->temp;
    for (i=0; i<k*n; i++) {
        temp[i] = t[i];
    }
    mlwe_compress(temp, n, k, dt_bits, q, q_inv, q_norm);

    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += k * n * dt_bits;
    sc->stats.components[SC_STAT_PUB_KEY][1].bits += 32 * 8;
    sc->stats.components[SC_STAT_PUB_KEY][2].bits += k * n * dt_bits + 32 * 8;

    // Create a bit packer to compress the public key
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        (k * n * dt_bits) + 32*8, NULL, 0, key, key_len);
    entropy_poly_encode_32(packer, k * n, temp, dt_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);
    entropy_poly_encode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_PUB_KEY][1].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PUB_KEY][2].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_kem_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT32 k, n, q, q_inv, q_norm, eta_bits, dt_bits;
    SINT32 *s, *t;
#if KYBER_KEM_STORE_NTT_T == 1
    SINT32 *t_ntt;
#endif
    UINT8 *z, *rho;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    // Define the constants defining the size of the rings and coefficients
    n = sc->kyber->params->n;
    k = sc->kyber->params->k;
    eta_bits = sc->kyber->params->eta_bits;
    dt_bits = sc->kyber->params->d_t;
    q        = sc->kyber->params->q;
    q_inv    = sc->kyber->params->q_inv;
    q_norm   = sc->kyber->params->q_norm;

    // Assign pointers to the key parameters
    s     = (SINT32 *) sc->privkey->key;
    t     = s + k*n;
#if KYBER_KEM_STORE_NTT_T == 1
    t_ntt = t + k*n;
    z     = (UINT8 *)(t_ntt + k*n);
#else
    z     = (UINT8 *)(t + k*n);
#endif
    rho   = z + 32;

#if KYBER_KEM_STORE_NTT_S == 1
    SINT32 *sk_s = sc->temp;
    const SINT16 *ntt_w = sc->kyber->params->w;
    const SINT16 *ntt_r = sc->kyber->params->r;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    for (i=0; i<k; i++) {
        sc_ntt->inv_ntt_32_16(sk_s + i*n, ntt, s + i*n, ntt_w, ntt_r);
    }
    sc_ntt->center_32(sk_s, k*n, ntt);
#else
    SINT32 *sk_s = s;
#endif

    SINT32 *temp = sc->temp + k*n;
    for (i=0; i<k*n; i++) {
        temp[i] = t[i];
    }
    mlwe_compress(temp, n, k, dt_bits, q, q_inv, q_norm);

    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += k * n * eta_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][1].bits += 32 * 8;
    sc->stats.components[SC_STAT_PRIV_KEY][2].bits += k * n * dt_bits;
    sc->stats.components[SC_STAT_PRIV_KEY][3].bits += 32 * 8;
    sc->stats.components[SC_STAT_PRIV_KEY][4].bits += k * n * (eta_bits + dt_bits) + 2 * 32 * 8;

    // Create a bit packer to compress the private key polynomial f
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        k * n * (eta_bits + dt_bits) + 2*32*8, NULL, 0, key, key_len);
    entropy_poly_encode_32(packer, k*n, sk_s, eta_bits,
        SIGNED_COEFF, sc->coding_priv_key.type, &sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);
    entropy_poly_encode_8(packer, 32, z, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_PRIV_KEY][1].bits_coded);
    entropy_poly_encode_32(packer, k*n, temp, dt_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_PRIV_KEY][2].bits_coded);
    entropy_poly_encode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_PRIV_KEY][3].bits_coded);

    // Extract the buffer with the polynomial f and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PRIV_KEY][4].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_kem_keygen(safecrypto_t *sc)
{
    size_t i;
    SINT32 *t, *s, *e, *c, *temp, *t2;
    UINT32 n, q, q_bits, k, dt;
    UINT8 *rho, *z, *rho2;
#if KYBER_KEM_STORE_NTT_T == 1
    SINT32 *t_ntt, *t2_ntt;
#endif

    if (NULL == sc) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Kyber KeyGen\n");

    n        = sc->kyber->params->n;
    q        = sc->kyber->params->q;
    k        = sc->kyber->params->k;
    dt       = sc->kyber->params->d_t;

    // Allocate temporary memory
    e    = sc->temp;
    if (NULL == e) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    c    = e + k * n;
    temp = c + (1 + k) * n;

    // Allocate key pair memory
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(KYBER_KEM_PRIVKEY_SIZE);
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(KYBER_KEM_PUBKEY_SIZE);
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, KYBER_KEM_PRIVKEY_SIZE);
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    s      = (SINT32 *) sc->privkey->key;
    t2     = s + k*n;
#if KYBER_KEM_STORE_NTT_T == 1
    t2_ntt = t2 + k*n;
    z      = (UINT8 *)(t2_ntt + k*n);
#else
    z      = (UINT8 *)(t2 + k*n);
#endif
    rho2   = z + 32;
    t      = (SINT32 *) sc->pubkey->key;
#if KYBER_KEM_STORE_NTT_T == 1
    t_ntt  = t + k*n;
    rho    = (UINT8 *)(t_ntt + k*n);
#else
    rho    = (UINT8 *)(t + k*n);
#endif

    kyber_cpa_keygen(sc, KYBER_KEM_CSPRNG_ENABLED, KYBER_KEM_STORE_NTT_S, rho, s, e, t, c);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s", s, k*n);

#if KYBER_KEM_STORE_NTT_T == 1
    const SINT16 *ntt_w = sc->kyber->params->w;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(t_ntt + i*n, ntt, t + i*n, ntt_w);
    }
    sc_ntt->center_32(t_ntt, k*n, ntt);
#endif

    // Store pseudorandum 256-bit secret with the private key
    prng_mem(sc->prng_ctx[0], z, 32);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "z", z, 32);

    // Store the public key with the private key (including Decompress(t))
#if KYBER_KEM_STORE_NTT_T == 1
    SC_MEMCOPY(t2_ntt, t_ntt, k * n * sizeof(SINT32));
#endif
    SC_MEMCOPY(t2, t, k * n * sizeof(SINT32));
    SC_MEMCOPY(rho2, rho, 32);

    // Clear the temporary memory resources
    SC_MEMZERO(e, (2 * k + 1) * n * sizeof(SINT32) + 32);

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "KeyGen s", s, k*n);

    return SC_FUNC_SUCCESS;

finish_free:
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, KYBER_KEM_PRIVKEY_SIZE);
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, KYBER_KEM_PUBKEY_SIZE);
    }

    // Clear the temporary memory resources
    SC_MEMZERO(e, (2 * k + 1) * n * sizeof(SINT32) + 32);

    return SC_FUNC_FAILURE;
}

static void kem_h_function(safecrypto_t *sc, const UINT8 * SC_RESTRICT big_k, const SINT32 * SC_RESTRICT u,
    const SINT32 * SC_RESTRICT v, const UINT8 * SC_RESTRICT d, size_t n, size_t k, UINT8 * SC_RESTRICT md, SINT32 * SC_RESTRICT heap)
{
    size_t i, j;
    UINT8 *b = (UINT8*)((size_t)heap + (32 - (size_t)heap % 32));
    UINT8 *p = b;

    // Add K to the hash
    SC_MEMCOPY(p, big_k, 32);
    p += 32;

    // Add u to the hash
    for (i = 0; i < k*n; i++) {
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
        *p++ = *u >> 8;
        *p++ = *u++ & 0xFF;
#else
        *p++ = *u & 0xFF;
        *p++ = *u++ >> 8;
#endif
    }

    // Add v to the hash
    for (i = 0; i < n; i++) {
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
        *p++ = *v >> 8;
        *p++ = *v++ & 0xFF;
#else
        *p++ = *v & 0xFF;
        *p++ = *v++ >> 8;
#endif
    }

    // Add d to the hash
    SC_MEMCOPY(p, d, 32);

#ifdef KYBER_KEM_USE_H_FUNC_XOF
    // Initialise the XOF function
    xof_init(sc->xof);

    // Update the XOF with the message bytes
    xof_absorb(sc->xof, b, k*n*2 + n*2 + 32*2);
    xof_final(sc->xof);

    // Create num_weight_bytes sign bits in an array of bytes
    xof_squeeze(sc->xof, md, 32);
#else
    // Initialise the hash function
    hash_init(sc->hash);

    // Update the hash with the message bytes
    hash_update(sc->hash, b, k*n*2 + n*2 + 32*2);

    // Obtain the message digest
    hash_final(sc->hash, md);
#endif
}

#ifndef KYBER_KEM_USE_H_FUNC_XOF

// Create a random oracle output from a hash function
static void kyber_oracle_bytes(safecrypto_t *sc, const UINT8 *md, size_t md_len,
    UINT8 *c, size_t n)
{
    // Use the message digest as an IV for a csprng
    prng_ctx_t *csprng = create_csprng(sc, md, md_len);

    // Create num_weight_bytes sign bits in an array of bytes
    prng_mem(csprng, c, n);

    // Destroy the CSPRNG
    prng_destroy(csprng);
}

#endif

static void kem_g_function(safecrypto_t *sc, const UINT8 * SC_RESTRICT rho, const SINT32 * SC_RESTRICT t, const UINT8 * SC_RESTRICT m,
    size_t n, size_t k, UINT8 * SC_RESTRICT md, UINT8 *c, SINT32 * SC_RESTRICT heap)
{
    size_t i, j;
    UINT8 *b = (UINT8*) heap;
    UINT8 *p = b;

    // Add rho to the hash
    SC_MEMCOPY(p, rho, 32);
    p += 32;

    // Add t to the hash
    for (i = 0; i < k*n; i++) {
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
        *p++ = *t >> 8;
        *p++ = *t++ & 0xFF;
#else
        *p++ = *t & 0xFF;
        *p++ = *t++ >> 8;
#endif
    }

    // Add the message to the hash
    SC_MEMCOPY(p, m, 32);

#ifdef KYBER_KEM_USE_H_FUNC_XOF
    // Initialise the XOF function
    xof_init(sc->xof);

    // Update the XOF with the message bytes
    xof_absorb(sc->xof, b, k*n*2 + 32 + 32);
    xof_final(sc->xof);

    // Create num_weight_bytes sign bits in an array of bytes
    xof_squeeze(sc->xof, c, 3*(n>>3));
#else
    // Initialise the hash function
    hash_init(sc->hash);

    // Update the hash with the message bytes
    hash_update(sc->hash, b, k*n*2 + 32 + 32);

    // Retrieve the message digest
    hash_final(sc->hash, md);

    // Map the message digest to the random oracle output
    kyber_oracle_bytes(sc, md, 32, c, 3*(n>>3));
#endif
}

SINT32 kyber_kem_encapsulation(safecrypto_t *sc,
    UINT8 **c, size_t *c_len,
    UINT8 **k, size_t *k_len)
{
    size_t i;
    UINT32 n, q, q_bits, du_bits, dv_bits, param_k;
    SINT32 *t, *t_rand, *u, *v, *heap;
    UINT8 *big_k, *r, *d, *rho, *m, *md;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;

    SC_PRINT_DEBUG(sc, "KYBER-KEM Encapsulation\n");

    // Assign values to commonly used variables
    n        = sc->kyber->params->n;
    q        = sc->kyber->params->q;
    q_bits   = sc->kyber->params->q_bits;
    du_bits  = sc->kyber->params->d_u;
    dv_bits  = sc->kyber->params->d_v;
    param_k  = sc->kyber->params->k;

    // Obtain pointers to temporary storage variables
    u        = sc->temp;
    v        = u + param_k * n;
    heap     = v + n;
    big_k    = (UINT8*) (heap + (1 + 4 * param_k) * n);
    r        = big_k + 32;
    d        = r     + 32;
    m        = d     + 32;
    md       = m     + 32;

    // Obtain pointers to the public key
    t        = (SINT32 *) sc->pubkey->key;
#if KYBER_KEM_STORE_NTT_T == 1
    t_rand   = t + param_k*n;
#else
    t_rand   = t;
#endif
    rho      = (UINT8*)(t_rand + param_k*n);

    // Increment the statistics for encapsulation
    sc->stats.encapsulate_num++;

    // Generate the 256-bit random value to be encapsulated
    prng_mem(sc->prng_ctx[0], m, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, 32);

    // Hash the public key and m and create a (K,r,d)
    kem_g_function(sc, rho, t, m, n, param_k, md, big_k, heap);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Kb", big_k, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "r", big_k + 32, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "d", big_k + 64, 32);

    // Kyber CPA Encryption of the public key
    kyber_cpa_enc(sc, KYBER_KEM_CSPRNG_ENABLED, u, v, t_rand, KYBER_KEM_STORE_NTT_T, rho, n, param_k, m, big_k + 32, heap);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "u", u, param_k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v", v, n);

    // K = H(K_bar, c), where c = (u, v, d)
    kem_h_function(sc, big_k, u, v, d, n, param_k, md, heap);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "K", md, 32);

    // Create the bit packer used to create the output ciphertext
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_encryption, 2 * param_k * n * q_bits + 32*8,
        NULL, 0, c, c_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_32(packer, param_k*n, u, du_bits,
        UNSIGNED_COEFF, sc->coding_encryption.type, &sc->stats.components[SC_STAT_ENCAPSULATE][0].bits_coded);
    entropy_poly_encode_32(packer, n, v, dv_bits,
        UNSIGNED_COEFF, sc->coding_encryption.type, &sc->stats.components[SC_STAT_ENCAPSULATE][1].bits_coded);
    entropy_poly_encode_8(packer, 32, d, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_ENCAPSULATE][2].bits_coded);
    utils_entropy.pack_get_buffer(packer, c, c_len);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Ciphertext", *c, *c_len);
    utils_entropy.pack_destroy(&packer);
    sc->stats.components[SC_STAT_ENCAPSULATE][0].bits += param_k*n * du_bits;
    sc->stats.components[SC_STAT_ENCAPSULATE][1].bits += n * dv_bits;
    sc->stats.components[SC_STAT_ENCAPSULATE][2].bits += 32 * 8;
    sc->stats.components[SC_STAT_ENCAPSULATE][4].bits_coded += *c_len * 8;

    // Create the packer used to create the output key
    packer = utils_entropy.pack_create(sc, &sc->coding_encryption, 32*8,
        NULL, 0, k, k_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_8(packer, 32, md, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_ENCAPSULATE][3].bits_coded);
    utils_entropy.pack_get_buffer(packer, k, k_len);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Master Key", *k, *k_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_ENCAPSULATE][3].bits += 32 * 8;
    sc->stats.components[SC_STAT_ENCAPSULATE][4].bits += param_k*n * du_bits + n * dv_bits + 32 * 8 * 2;
    sc->stats.components[SC_STAT_ENCAPSULATE][4].bits_coded += *k_len * 8;

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, (1 + 5 * param_k) * n * sizeof(SINT32) + 6*32);

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_kem_decapsulation(safecrypto_t *sc,
    const UINT8 *c, size_t c_len,
    UINT8 **k, size_t *k_len)
{
    size_t i;
    UINT32 n, q, q_bits, du_bits, dv_bits, param_k;
    SINT32 *s, *t, *t_rand, *u, *v, *heap;
    UINT8 *big_k, *r, *d, *rho, *z, *m, *md;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;

    SC_PRINT_DEBUG(sc, "KYBER-KEM Decapsulation\n");

    // Increment the statistics for decapsulation
    sc->stats.decapsulate_num++;

    // Assign values to commonly used variables
    n       = sc->kyber->params->n;
    q       = sc->kyber->params->q;
    q_bits  = sc->kyber->params->q_bits;
    du_bits = sc->kyber->params->d_u;
    dv_bits = sc->kyber->params->d_v;
    param_k = sc->kyber->params->k;

    // Obtain pointers to temporary storage variables
    u        = sc->temp;
    v        = u + param_k * n;
    heap     = v + n;
    big_k    = (UINT8*) (heap + 4 * param_k * n);
    r        = big_k + 32;
    d        = r     + 32;
    m        = d     + 32;
    md       = m     + 32;

    // Obtain pointers to the public key
    s = (SINT32 *) sc->privkey->key;
    t = s + param_k*n;
#if KYBER_KEM_STORE_NTT_T == 1
    t_rand   = t + param_k*n;
#else
    t_rand   = t;
#endif
    z = (UINT8 *)(t_rand + param_k*n);
    rho = z + 32;
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Decap s", s, param_k*n);

    // Create packers to obtain the data from the byte stream
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
        .entropy_coder = NULL
    };
    sc_packer_t *ipacker, *opacker;
    ipacker  = utils_entropy.pack_create(sc, &sc->coding_encryption,
        0, c, c_len, NULL, 0);
    if (NULL == ipacker) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        goto clean_finish;
    }
    opacker = utils_entropy.pack_create(sc, &coding_raw,
        n, NULL, 0, k, k_len);
    if (NULL == opacker) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        goto clean_finish;
    }

    // Decode the data and decapsulate the key
    entropy_poly_decode_32(ipacker, param_k*n, u, du_bits,
        UNSIGNED_COEFF, sc->coding_encryption.type);
    entropy_poly_decode_32(ipacker, n, v, dv_bits,
        UNSIGNED_COEFF, sc->coding_encryption.type);
    entropy_poly_decode_8(ipacker, 32, d, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);

    // Generate the 256-bit random value to be encapsulated
    kyber_cpa_dec(sc, u, v, KYBER_KEM_STORE_NTT_S, s, n, param_k, m);

    // Hash the public key and m and create a (K,r,d)
    kem_g_function(sc, rho, t, m, n, param_k, md, big_k, heap);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Kb", big_k, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "r", big_k + 32, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "d", big_k + 64, 32);

    // Kyber CPA Encryption of the public key
    kyber_cpa_enc(sc, KYBER_KEM_CSPRNG_ENABLED, u, v, t_rand, KYBER_KEM_STORE_NTT_T, rho, n, param_k, m, big_k + 32, heap);

    // K = H(K_bar, c), where c = (u, v, d)
    kem_h_function(sc, big_k, u, v, d, n, param_k, md, heap);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "K", md, 32);

    entropy_poly_encode_8(opacker, 32, md, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, NULL);

    // Release all resources associated with the packers and obtain the
    // buffer with the plaintext byte stream
    utils_entropy.pack_destroy(&ipacker);
    utils_entropy.pack_get_buffer(opacker, k, k_len);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Master Key", *k, *k_len);
    utils_entropy.pack_destroy(&opacker);

    SC_MEMZERO(sc->temp, (1 + 5 * param_k) * n * sizeof(SINT32) + 4*32);
    return SC_FUNC_SUCCESS;
decapsulation_error:
    utils_entropy.pack_destroy(&ipacker);
    utils_entropy.pack_destroy(&opacker);
clean_finish:
    SC_MEMZERO(sc->temp, (1 + 5 * param_k) * n * sizeof(SINT32) + 4*32);
    return SC_FUNC_FAILURE;
}

char * kyber_kem_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I", "II"};
    static char stats[2048];
    snprintf(stats, 2047, "\nKYBER-%s\n\
    KeyGen       %8" FMT_LIMB " key-pairs  / %8" FMT_LIMB " trials\n\
    Encryption   %8" FMT_LIMB "\n\
    Decryption   %8" FMT_LIMB "\n\n\
    Hash:            %s\n\
    Oracle:          %s\n\
    PRNG:            %s\n\n\
    Public Key compression:      %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       t       %10.2f%13.2f%16.3f%%\n\
       rho     %10.2f%13.2f%16.3f%%\n\
       total   %10.2f%13.2f%16.3f%%\n\n\
    Private Key compression:     %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       s       %10.2f%13.2f%16.3f%%\n\
       z       %10.2f%13.2f%16.3f%%\n\
       t       %10.2f%13.2f%16.3f%%\n\
       rho     %10.2f%13.2f%16.3f%%\n\
       total   %10.2f%13.2f%16.3f%%\n\n\
    Encapsulation compression:   %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       u       %10.2f%13.2f%16.3f%%\n\
       v       %10.2f%13.2f%16.3f%%\n\
       d       %10.2f%13.2f%16.3f%%\n\
       K       %10.2f%13.2f%16.3f%%\n\
       total   %10.2f%13.2f%16.3f%%\n\n",
        param_set_name[sc->kyber->params->set],
        sc->stats.keygen_num,
        sc->stats.keygen_num_trials,
        sc->stats.encapsulate_num,
        sc->stats.decapsulate_num,
        sc_hash_names[sc->kyber->oracle_hash],
        (KYBER_KEM_CSPRNG_ENABLED)? "CSPRNG" : "SHAKE128",
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
        sc_entropy_names[(int)sc->coding_encryption.type],
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][3].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][3].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][3].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][3].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][4].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][4].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][4].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][4].bits);
    return stats;
}


#undef FMT_LIMB
