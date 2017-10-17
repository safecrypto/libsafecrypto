/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "kyber_enc.h"
#include "kyber_enc_params.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/hash.h"
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

#define KYBER_ENC_PRIVKEY_SIZE    ((1 + KYBER_ENC_STORE_NTT_T) * k * n * sizeof(SINT32))
#define KYBER_ENC_PUBKEY_SIZE     ((1 + KYBER_ENC_STORE_NTT_T) * k * n * sizeof(SINT32) + 32)

#ifdef KYBER_ENC_USE_CSPRNG_SAM
#define KYBER_ENC_CSPRNG_ENABLED   MODULE_LWE_ENC_CSPRNG_ENABLED
#else
#define KYBER_ENC_CSPRNG_ENABLED   MODULE_LWE_ENC_CSPRNG_DISABLED
#endif


SINT32 kyber_enc_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    size_t i;
    UINT32 n, k;

    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 2, 1, 0, 0, 2, 0)) {
        return SC_FUNC_FAILURE;
    }

    // Precomputation for entropy coding
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_pub_key.entropy_coder    = NULL;
    sc->coding_priv_key.type            = SC_ENTROPY_NONE;
    sc->coding_priv_key.entropy_coder   = NULL;
    sc->coding_encryption.type          = SC_ENTROPY_NONE;
    sc->coding_encryption.entropy_coder = NULL;

    // Allocate memory for Ring-LWE Encryption configuration
    sc->kyber = SC_MALLOC(sizeof(kyber_cfg_t));
    if (NULL == sc->kyber) {
        return SC_FUNC_FAILURE;
    }

    // Check that the parameter set is valid
    if (set < 0 || set > 2) {
        SC_FREE(sc->kyber, sizeof(kyber_cfg_t));
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified RLWE Encryption parameter set
    switch (set)
    {
        case 0: sc->kyber->params = &param_kyber_enc_0;
                sc->kyber->entropy = flags[0] & 0xF;
                break;
        case 1: sc->kyber->params = &param_kyber_enc_1;
                sc->kyber->entropy = flags[0] & 0xF;
                break;
        case 2: sc->kyber->params = &param_kyber_enc_2;
                sc->kyber->entropy = flags[0] & 0xF;
                break;
        default:;
    }

    // Obtain the size of the polynomials
    n = sc->kyber->params->n;
    k = sc->kyber->params->k;

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

    sc->sc_ntt = utils_arith_ntt(sc->kyber->ntt_optimisation);
    sc->sc_poly = utils_arith_poly();

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
    sc->temp_size = 6 * k * n * sizeof(SINT32);
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
            SC_FREE(sc->kyber, sizeof(kyber_cfg_t));
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT16) * 2 * n);
#endif
            return SC_FUNC_FAILURE;
        }
    }

    SC_PRINT_DEBUG(sc, "Kyber CPA Encryption algorithm created");
    return SC_FUNC_SUCCESS;
}


SINT32 kyber_enc_destroy(safecrypto_t *sc)
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
        SC_FREE(sc->privkey->key, KYBER_ENC_PRIVKEY_SIZE);
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, KYBER_ENC_PUBKEY_SIZE);
        sc->pubkey->len = 0;
    }

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->kyber->params->w, sizeof(SINT16) * 2 * n);
#endif

    if (sc->kyber) {
        utils_crypto_xof_destroy(sc->xof);
        SC_FREE(sc->kyber, sizeof(kyber_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "Kyber CPA Encryption algorithm destroyed");

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_enc_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT32 n, k, dt_bits, q;
    SINT32 *t;
#if KYBER_ENC_STORE_NTT_T == 1
    SINT32 *t_ntt;
#endif
    UINT8 *rho;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n       = sc->kyber->params->n;
    k       = sc->kyber->params->k;
    dt_bits = sc->kyber->params->d_t;
    q       = sc->kyber->params->q;

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, KYBER_ENC_PUBKEY_SIZE);
    }
    sc->pubkey->key = SC_MALLOC(KYBER_ENC_PUBKEY_SIZE);
    if (NULL == sc->pubkey->key) {
        return SC_FUNC_FAILURE;
    }

    t     = (SINT32 *) sc->pubkey->key;
#if KYBER_ENC_STORE_NTT_T == 1
    t_ntt = t + k*n;
    rho   = (UINT8 *)(t_ntt + k*n);
#else
    rho   = (UINT8 *)(t + k*n);
#endif

    // Create a bit packer to extract the public key from the buffer
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        k * n * dt_bits + 32*8, key, key_len, NULL, 0);
    entropy_poly_decode_32(packer, k * n, t, dt_bits,
        SIGNED_COEFF, SC_ENTROPY_NONE);
    entropy_poly_decode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE);
    utils_entropy.pack_destroy(&packer);

    sc->pubkey->len = k*n + 8;

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    mlwe_decompress(t, n, k, dt_bits, q);
    sc_ntt->normalize_32(t + n*i, k*n, ntt);

#if KYBER_ENC_STORE_NTT_T == 1
    // If t is stored in the NTT domain it must be converted to the normal domain
    const SINT16 *ntt_w = sc->kyber->params->w;
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(t_ntt + i*n, ntt, t + i*n, ntt_w);
    }
    sc_ntt->center_32(t_ntt, k*n, ntt);
#endif

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_enc_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT32 n, k, eta_bits;

    n        = sc->kyber->params->n;
    k        = sc->kyber->params->k;
    eta_bits = sc->kyber->params->eta_bits;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, KYBER_ENC_PRIVKEY_SIZE);
    }
    sc->privkey->key = SC_MALLOC(KYBER_ENC_PRIVKEY_SIZE);
    if (NULL == sc->privkey->key) {
        return SC_FUNC_FAILURE;
    }

    // Create a bit packer to extract the private key polynomial from the buffer
    SINT32 *s = (SINT32 *) sc->privkey->key;
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        k * n * eta_bits, key, key_len, NULL, 0);
    entropy_poly_decode_32(packer, k * n, s, eta_bits,
        SIGNED_COEFF, sc->coding_priv_key.type);
    utils_entropy.pack_destroy(&packer);

    sc->privkey->len = n;

#if KYBER_ENC_STORE_NTT_S == 1
    const SINT16 *ntt_w = sc->kyber->params->w;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(s + i*n, ntt, s + i*n, ntt_w);
    }
    sc_ntt->center_32(s, k*n, ntt);
#endif

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_enc_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT32 n, k, dt_bits, q, q_inv, q_norm;
    SINT32 *t;
#if KYBER_ENC_STORE_NTT_T == 1
    SINT32 *t_ntt;
#endif
    UINT8 *rho;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n       = sc->kyber->params->n;
    k       = sc->kyber->params->k;
    dt_bits = sc->kyber->params->d_t;
    q       = sc->kyber->params->q;
    q_inv   = sc->kyber->params->q_inv;
    q_norm  = sc->kyber->params->q_norm;

    t     = (SINT32 *) sc->pubkey->key;
#if KYBER_ENC_STORE_NTT_T == 1
    t_ntt = t + k*n;
    rho   = (UINT8 *)(t_ntt + k*n);
#else
    rho   = (UINT8 *)(t + k*n);
#endif

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
        SIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);
    entropy_poly_encode_8(packer, 32, rho, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_PUB_KEY][1].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    sc->stats.components[SC_STAT_PUB_KEY][2].bits_coded += *key_len * 8;

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_enc_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT32 k, n, eta_bits;
    SINT32 *temp;

    if (NULL == sc || NULL == key) {
        return SC_FUNC_FAILURE;
    }

    n        = sc->kyber->params->n;
    k        = sc->kyber->params->k;
    eta_bits = sc->kyber->params->eta_bits;

    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += k * n * eta_bits;

    SINT32 *s = (SINT32 *) sc->privkey->key;

#if KYBER_ENC_STORE_NTT_S == 1
    temp = sc->temp;
    const SINT16 *ntt_w = sc->kyber->params->w;
    const SINT16 *ntt_r = sc->kyber->params->r;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    for (i=0; i<k; i++) {
        sc_ntt->inv_ntt_32_16(temp + i*n, ntt, s + i*n, ntt_w, ntt_r);
    }
    sc_ntt->center_32(temp, k*n, ntt);
#else
    temp = s;
#endif

    // Create a bit packer to compress the private key polynomial f
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        k * n * eta_bits, NULL, 0, key, key_len);
    entropy_poly_encode_32(packer, k*n, temp, eta_bits,
        SIGNED_COEFF, sc->coding_priv_key.type, &sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);

    // Extract the buffer with the polynomial f and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_enc_keygen(safecrypto_t *sc)
{
    size_t i;
    SINT32 *t, *s, *e, *c, *temp;
    UINT32 n, q, q_bits, q_inv, q_norm, eta, eta_bits, k, dt;
    UINT8 *rho;
#if KYBER_ENC_STORE_NTT_T == 1
    SINT32 *t_ntt;
#endif

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Kyber Encryption KeyGen\n");

    n       = sc->kyber->params->n;
    q       = sc->kyber->params->q;
    q_inv   = sc->kyber->params->q_inv;
    q_norm  = sc->kyber->params->q_norm;
    k       = sc->kyber->params->k;
    dt      = sc->kyber->params->d_t;

    // Allocate key pair memory
    SC_PRINT_DEBUG(sc, "Memory allocation for keys\n");
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(KYBER_ENC_PRIVKEY_SIZE);
        if (NULL == sc->privkey->key) {
            goto finish_free;
        }
    }
    sc->privkey->len = n;
    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(KYBER_ENC_PUBKEY_SIZE);
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, KYBER_ENC_PRIVKEY_SIZE);
            goto finish_free;
        }
    }
    sc->pubkey->len = n;

    // Gather statistics
    sc->stats.keygen_num++;

    // Allocate temporary memory
    e    = sc->temp;
    if (NULL == e) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    c    = e + k * n;
    temp = c + k * n;

    // Assign pointers to the key-pair memory
    s    = sc->privkey->key;
    t    = sc->pubkey->key;
#if KYBER_ENC_STORE_NTT_T == 1
    t_ntt  = t + k*n;
    rho    = (UINT8 *)(t_ntt + k*n);
#else
    rho    = (UINT8 *)(t + k*n);
#endif

    // Perform key generation, 
    kyber_cpa_keygen(sc, KYBER_ENC_CSPRNG_ENABLED, KYBER_ENC_STORE_NTT_S,
        rho, s, e, t, c);
    SC_PRINT_DEBUG(sc, "Print keys\n");
    SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 16);

#if KYBER_ENC_STORE_NTT_T == 1
    const SINT16 *ntt_w = sc->kyber->params->w;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(t_ntt + i*n, ntt, t + i*n, ntt_w);
    }
#endif

    SC_MEMZERO(sc->temp, (1 + 2 * k) * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;

finish_free:
    SC_MEMZERO(sc->temp, (1 + 2 * k) * n * sizeof(SINT32));

    return SC_FUNC_FAILURE;
}

SINT32 kyber_enc_encrypt(safecrypto_t *sc, size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    (void) flen;

    SINT32 i;
    UINT32 n, q_bits, du_bits, dv_bits, k;
    SINT32 *u, *v, *t, *t_enc, *enc_heap;
    UINT8 *rho, *rand_r;
    const SINT16 *w, *r;
    const UINT8 *in = from;
    ntt_params_t *ntt;
    const utils_arith_ntt_t *sc_ntt;
    const utils_arith_poly_t *sc_poly;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Increment the statistics for encryption
    sc->stats.encrypt_num++;

    // Assign values to commonly used variables
    n        = sc->kyber->params->n;
    q_bits   = sc->kyber->params->q_bits;
    du_bits  = sc->kyber->params->d_u;
    dv_bits  = sc->kyber->params->d_v;
    k        = sc->kyber->params->k;
    w        = sc->kyber->params->w;
    r        = sc->kyber->params->r;
    ntt      = &sc->kyber->ntt;
    sc_ntt   = sc->sc_ntt;
    sc_poly  = sc->sc_poly;

    // Obtain pointers to temporary storage variables
    u        = sc->temp;
    v        = u + k * n;
    enc_heap = v + n;
    rand_r   = (UINT8*) (enc_heap + 4 * k * n);

    // Obtain pointers to the public key
    t        = ((SINT32 *) sc->pubkey->key);
#if KYBER_ENC_STORE_NTT_T == 1
    t_enc    = t + k*n;
#else
    t_enc    = t;
#endif
    rho      = (UINT8 *) (t_enc + k * n);

    // Generate a random 256-bit value and pass it to the Kyber CPA
    // encryption routine
    prng_mem(sc->prng_ctx[0], rand_r, 32);
    kyber_cpa_enc(sc, KYBER_ENC_CSPRNG_ENABLED, u, v, t_enc, KYBER_ENC_STORE_NTT_T, rho, n, k, from, rand_r, enc_heap);

    // Create the bit packer used to create the output stream
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_encryption,
        du_bits*k*n + dv_bits*n, NULL, 0, to, tlen);

    // Bit packing
    entropy_poly_encode_32(packer, k*n, u, du_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_ENCRYPT][0].bits_coded);
    sc->stats.components[SC_STAT_ENCRYPT][0].bits += du_bits*n*k;
    entropy_poly_encode_32(packer, n, v, dv_bits,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, &sc->stats.components[SC_STAT_ENCRYPT][1].bits_coded);
    sc->stats.components[SC_STAT_ENCRYPT][1].bits += dv_bits*n;

    // Extracting buffer
    utils_entropy.pack_get_buffer(packer, to, tlen);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Ciphertext", *to, *tlen);
    utils_entropy.pack_destroy(&packer);
    sc->stats.components[SC_STAT_ENCRYPT][2].bits += du_bits*k*n + dv_bits*n;
    sc->stats.components[SC_STAT_ENCRYPT][2].bits_coded += *tlen * 8;

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, (5*k + 1) * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_enc_decrypt(safecrypto_t *sc, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
    size_t i;
    UINT32 n, k, q_bits, du_bits, dv_bits;
    UINT32 value;
    SINT32 *u, *v, *s;
    UINT8 *m;
    size_t message_length;
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
        .entropy_coder = NULL
    };
    sc_packer_t *ipacker, *opacker;
    const SINT16 *w, *r;
    ntt_params_t *ntt;
    const utils_arith_ntt_t *sc_ntt;
    const utils_arith_poly_t *sc_poly;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Increment the statistics for encryption
    sc->stats.decrypt_num++;

    // Assign values to commonly used variables
    n        = sc->kyber->params->n;
    k        = sc->kyber->params->k;
    q_bits   = sc->kyber->params->q_bits;
    du_bits  = sc->kyber->params->d_u;
    dv_bits  = sc->kyber->params->d_v;
    w        = sc->kyber->params->w;
    r        = sc->kyber->params->r;
    ntt      = &sc->kyber->ntt;
    sc_ntt   = sc->sc_ntt;
    sc_poly  = sc->sc_poly;

    message_length = (8 * flen) / (2 * q_bits);


    // Obtain pointers to temporary storage variables
    u        = sc->temp;
    v        = sc->temp + k * n;
    m        = (UINT8*) (v + n);
    s        = (SINT32 *) sc->privkey->key;

    // Create packers to obtain the data from the byte stream
    ipacker  = utils_entropy.pack_create(sc, &sc->coding_encryption,
        0, from, flen, NULL, 0);

    // Decode the data and decrypt it
    if (utils_entropy.pack_is_data_avail(ipacker)) {
        entropy_poly_decode_32(ipacker, k*n, u, du_bits,
            UNSIGNED_COEFF, SC_ENTROPY_NONE);
        entropy_poly_decode_32(ipacker, n, v, dv_bits,
            UNSIGNED_COEFF, SC_ENTROPY_NONE);

        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Decrypt u", u, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Decrypt v", v, n);
    }

    // Destroy the input packer instance
    utils_entropy.pack_destroy(&ipacker);

    // Create a packer to generate the output message
    opacker = utils_entropy.pack_create(sc, &coding_raw,
        message_length, NULL, 0, to, tlen);

    // Perform Kyber CPA Decryption of the output message
    kyber_cpa_dec(sc, u, v, KYBER_ENC_STORE_NTT_S, s, n, k, m);
    entropy_poly_encode_8(opacker, 32, m, 8,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, NULL);

    // Release all resources associated with the packers and obtain the
    // buffer with the plaintext byte stream
    utils_entropy.pack_get_buffer(opacker, to, tlen);
    utils_entropy.pack_destroy(&opacker);

    SC_MEMZERO(sc->temp, (k + 1) * n * sizeof(SINT32) + 32);
    return SC_FUNC_SUCCESS;

decryption_early_failure:
    SC_MEMZERO(sc->temp, (k + 1) * n * sizeof(SINT32) + 32);
    return SC_FUNC_FAILURE;
}

char * kyber_enc_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I", "II"};
    static char stats[2048];
    snprintf(stats, 2047, "\nKyber Encryption (KYBER-ENC-%s):\n\
Keys           %8" FMT_LIMB " key-pairs\n\
Encryptions    %8" FMT_LIMB "\n\
Decryptions    %8" FMT_LIMB "\n\n\
Sampler:                 %s\n\
PRNG:                    %s\n\
Public Key compression:  %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   t       %10.2f%13.2f%16.3f%%\n\
   rho     %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Private Key compression: %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   total   %10.2f%13.2f%16.3f%%\n\n\
Encryption compression:   %s\n\
           Uncoded bits   Coded bits   Compression Ratio\n\
   u       %10.2f%13.2f%16.3f%%\n\
   v       %10.2f%13.2f%16.3f%%\n\
   total   %10.2f%13.2f%16.3f%%\n\n",
        param_set_name[sc->kyber->params->set],
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
