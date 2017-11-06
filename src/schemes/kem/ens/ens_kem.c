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

#include "ens_kem.h"
#include "ens_kem_params.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/prng.h"
#include "utils/arith/arith.h"
#include "utils/arith/ntt.h"
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
typedef struct ens_kem_cfg_t {
    ens_kem_set_t            *params;
    safecrypto_ntt_e          ntt_optimisation;
    ntt_params_t              ntt;
    sc_entropy_type_e         entropy;
} SC_STRUCT_PACKED ens_kem_cfg_t;
SC_STRUCT_PACK_END


SINT32 ens_kem_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    FLOAT sig;
    UINT16 n;

    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are free at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 1, 1, 0, 0, 0, 3)) {
        return SC_FUNC_FAILURE;
    }

    // Precomputation for entropy coding
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_priv_key.type            = SC_ENTROPY_NONE;
    sc->coding_encryption.type          = SC_ENTROPY_NONE;

    // Allocate memory for NTRU-KEM configuration
    sc->ens_kem = SC_MALLOC(sizeof(ens_kem_cfg_t));
    if (NULL == sc->ens_kem) {
        return SC_FUNC_FAILURE;
    }

    // Check that the parameter set is valid
    if (set < 0 || set > 3) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified RLWE Encryption parameter set
    switch (set)
    {
        case 0: sc->ens_kem->params = &param_ens_kem_0; 
                sc->ens_kem->entropy = flags[0] & 0xF;
                break;
        case 1: sc->ens_kem->params = &param_ens_kem_1; 
                sc->ens_kem->entropy = flags[0] & 0xF;
                break;
        case 2: sc->ens_kem->params = &param_ens_kem_2; 
                sc->ens_kem->entropy = flags[0] & 0xF;
                break;
        case 3: sc->ens_kem->params = &param_ens_kem_3; 
                sc->ens_kem->entropy = flags[0] & 0xF;
                break;
        default:;
    }

    n = sc->ens_kem->params->n;

    // Initialise the reduction scheme
    sc->ens_kem->ntt_optimisation =
        (flags[0] & SC_FLAG_0_REDUCTION_REFERENCE)? SC_NTT_REFERENCE :
        (flags[0] & SC_FLAG_0_REDUCTION_BARRETT)?   SC_NTT_BARRETT :
        (flags[0] & SC_FLAG_0_REDUCTION_FP)?        SC_NTT_FLOATING_POINT :
#ifdef HAVE_AVX2
                                                    SC_NTT_AVX;
#else
                                                    SC_NTT_FLOATING_POINT;
#endif
    init_reduce(&sc->ens_kem->ntt, n, sc->ens_kem->params->q);

    // Create pointers for the arithmetic functions used by Whole KEM
    sc->sc_ntt = utils_arith_ntt(sc->ens_kem->ntt_optimisation);
    sc->sc_poly = utils_arith_poly();
    sc->sc_vec = utils_arith_vectors();

    // Retrieve the Gaussian Sampler standard deviation
    sig = sc->ens_kem->params->sig;

#ifdef USE_RUNTIME_NTT_TABLES
    // Dynamically allocate memory for the necessary NTT tables
    SINT16 *temp = (SINT16*) SC_MALLOC(sizeof(SINT16) * 2 * n);
    sc->ens_kem->params->w = temp;
    sc->ens_kem->params->r = temp + n;
    roots_of_unity_s16(sc->ens_kem->params->w, sc->ens_kem->params->r,
        n, sc->ens_kem->params->q, 0);
#endif

    // Dynamically allocate memory for temporary storage
    sc->temp_size = 6 * n * sizeof(SINT32);
    if (!sc->temp_external_flag) {
        sc->temp = SC_MALLOC(sc->temp_size);
        if (NULL == sc->temp) {
#ifdef USE_RUNTIME_NTT_TABLES
            SC_FREE(temp, sizeof(SINT16) * 2 * n);
#endif
            SC_FREE(sc->ens_kem, sizeof(ens_kem_cfg_t));
            return SC_FUNC_FAILURE;
        }
    }

    return SC_FUNC_SUCCESS;
}


SINT32 ens_kem_destroy(safecrypto_t *sc)
{
    UINT16 n;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    n = sc->ens_kem->params->n;

    // Free resources associated with temporary variable storage
    if (!sc->temp_external_flag) {
        SC_FREE(sc->temp, sc->temp_size);
    }

    // Free all resources associated with the key-pair
    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 2 * n * sizeof(SINT16));
        sc->privkey->len = 0;
    }
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, n * sizeof(SINT16));
        sc->pubkey->len = 0;
    }

#ifdef USE_RUNTIME_NTT_TABLES
    SC_FREE(sc->ens_kem->params->w, sizeof(SINT16) * 2 * n);
#endif

    if (sc->ens_kem) {
        SC_FREE(sc->ens_kem, sizeof(ens_kem_cfg_t));
    }

    SC_PRINT_DEBUG(sc, "NTRU-KEM scheme destroyed\n");

    return SC_FUNC_SUCCESS;
}

/// Consume a binary polynomial stored in a SINT32 array that represents
/// the multiplicative inverse, perform bit reversal of the polynomial,
/// then pack into an array of 32-bit words. This allows for efficient
/// convolution when performing decapsulation.
static void reverse_and_pack_inv_g(SINT32 *t, size_t n, UINT32 *inv_g)
{
    // NOTE: It is assumed that n is a factor of 32
    size_t i, j;

    // Bit reverse the mod 2 inverse polynomial (in-place)
    for (i=0, j=n-1; i<n>>1; i++, j--) {
        UINT32 temp = t[i];
        t[i] = t[j];
        t[j] = temp;
    }

    // Pack the inverse private key g into 32-bit words
    for (i=0, j=0; i<n; i++) {
        UINT32 mask  = i & 0x1F;
        UINT32 shift = 31 - mask;
        inv_g[j] = (mask == 0)? (UINT32)t[i] << 31 :
                                inv_g[j] | (t[i] << shift);
        j += (0x1F == mask);
    }
}

/// Configure the entropy coding scheme
static SINT32 sig_entropy_init(safecrypto_t *sc, SINT32 set,
    sc_entropy_t *coding_pub_key, sc_entropy_t *coding_priv_key)
{
    (void) sc;
    (void) set;

    switch (coding_pub_key->type)
    {
    default:
        coding_pub_key->type = SC_ENTROPY_NONE;
    }

    return SC_FUNC_SUCCESS;
}

/// Extract a signed key polynomial from a byte stream
static SINT32 extract_signed_key(safecrypto_t *sc, SINT32 *sc_key,
    sc_entropy_t *coding, SINT32 bits, const UINT8 *key, size_t key_len)
{
    UINT32 n;

    n = sc->ens_kem->params->n;

    sc_packer_t *packer = utils_entropy.pack_create(sc, coding,
        n * bits, key, key_len, NULL, 0);
    if (NULL == packer) {
        return SC_FUNC_FAILURE;
    }

    entropy_poly_decode_32(packer, n, sc_key, bits,
        SIGNED_COEFF, coding->type, 0);

    utils_entropy.pack_destroy(&packer);

    return SC_FUNC_SUCCESS;
}

#ifdef ENS_KEM_USE_SPARSE_MULTIPLICATION
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
        if (b_sparse[j]) {
            for (k=0; k<n; k++) {
                sparse[j+k] += a[k] * b_sparse[j];
            }
        }
    }

    // Perform the ring modular reduction
    for (j=n; j--;) {
        r[j] = sparse[j] - sparse[j + n];
    }
}
#endif

/// Calculate the ciphertext, t = 2hr + e mod q
static SINT32 generate_ciphertext(safecrypto_t *sc, SINT16 *h, SINT32 *r, SINT32 *e,
    SINT32 *t, SINT32 n, SINT32 q)
{
    size_t i;
    const SINT16 *ntt_w   = sc->ens_kem->params->w;
    const SINT16 *ntt_r   = sc->ens_kem->params->r;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ens_kem->ntt;

#ifdef ENS_KEM_USE_SPARSE_MULTIPLICATION
    sparse_mul_mod_ring(t, t, r, n);
#else
    // Forward NTT of r
    sc_ntt->fwd_ntt_32_16(t, ntt, r, ntt_w);

    // Calculate product of r and h in the NTT domain (h is already
    // in the domain)
    sc_ntt->mul_32_pointwise_16(t, ntt, t, h);

    // Inverse NTT
    sc_ntt->inv_ntt_32_16(t, ntt, t, ntt_w, ntt_r);
#endif

    // Shift hr to -(q/2) to (q/2)
    for (i=0; i<(size_t)n; i++) {
        t[i] = (t[i] > (q/2))? t[i] - q : t[i];
    }

    // Multiply by two and add the message e
    sc_poly->mul_32_scalar(t, n, 2);
    sc_poly->add_32(t, n, t, e);

    // Shift into 0 to q-1 range
    sc_ntt->normalize_32(t, n, ntt);

    return SC_FUNC_SUCCESS;
}

SINT32 ens_kem_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    const SINT16 *w;
    SINT32 *t, *u;
    UINT16 n, q, q_bits;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    sig_entropy_init(sc, sc->ens_kem->params->set,
        &sc->coding_pub_key, &sc->coding_priv_key);

    n      = sc->ens_kem->params->n;
    q      = sc->ens_kem->params->q;
    q_bits = sc->ens_kem->params->q_bits;
    w      = sc->ens_kem->params->w;

    // Configure reduction optimisation
    safecrypto_ntt_e ntt_optimisation = SC_NTT_BARRETT;
    ntt_params_t ntt;
    if (SC_NTT_BARRETT == ntt_optimisation) {
        ntt.n = n;
        ntt.u.ntt32.q = q;
        barrett_init(&ntt);
    }
    else {
        ntt.n = n;
        ntt.u.ntt32.q = q;
    }

    // Allocate resources for the private key
    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, n * sizeof(SINT16));
    }
    sc->pubkey->key = SC_MALLOC(n * sizeof(SINT16));
    if (NULL == sc->pubkey->key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Assign pointers for interim storage
    t = sc->temp;
    u = sc->temp + 2 * n;

    // Extract the public key
    SINT16 *pubkey = (SINT16 *) sc->pubkey->key;
    sc->coding_pub_key.type = SC_ENTROPY_NONE;
    extract_signed_key(sc, u, &sc->coding_pub_key, q_bits, key, key_len);
    sc->pubkey->len = n;

    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(ntt_optimisation);

#ifndef ENS_KEM_USE_SPARSE_MULTIPLICATION
    // Convert public key h to the NTT domain
    sc_ntt->fwd_ntt_32_16(t, &ntt, u, w);
    sc_ntt->center_32(t, n, &ntt);
    for (i=n; i--;) {
        pubkey[i] = t[i];
    }
#endif

    return SC_FUNC_SUCCESS;
}

SINT32 ens_kem_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t i;
    UINT16 n, q;
    const SINT16 *w;
    SINT32 *t, *u, *h;
    SINT16 *privkey;
    UINT32 *inv_g;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ens_kem->ntt;

    n = sc->ens_kem->params->n;
    q = sc->ens_kem->params->q;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, 2 * n * sizeof(SINT16));
    }
    sc->privkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
    if (NULL == sc->privkey->key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Assign pointers to buffers
    privkey = (SINT16 *) sc->privkey->key;
    inv_g = (UINT32*)(sc->privkey->key + n * sizeof(SINT16));
    t = sc->temp;
    u = sc->temp + 2 * n;
    h = sc->temp + 3 * n;
    w = sc->ens_kem->params->w;

    sig_entropy_init(sc, sc->ens_kem->params->set,
        &sc->coding_pub_key, &sc->coding_priv_key);

    // Extract the private key
    extract_signed_key(sc, u, &sc->coding_priv_key, 5, key, key_len);
    sc->privkey->len = 2 * n;

    // Convert private key g to the NTT domain
    sc_ntt->fwd_ntt_32_16(t, ntt, u, w);

    // Compute the inverse of g in a bit reversed and packed format
    sc_ntt->normalize_32(t, n, ntt);
    for (i=0; i<n; i++) {
        privkey[i] = (t[i] > (q>>1))? t[i] - q: t[i];
        u[i] = u[i] & 0x1;
    }
    if (SC_FUNC_FAILURE == sc_poly->bin_inv_32(t, u, h, n)) {
        SC_PRINT_DEBUG(sc, "g is not invertible in Z2\n");
        SC_LOG_ERROR(sc, SC_ERROR);
        goto load_failure;
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "1/g mod 2", t, n);
    reverse_and_pack_inv_g(t, n, inv_g);

    SC_MEMZERO(t, 5 * n * sizeof(SINT32));
    return SC_FUNC_SUCCESS;

load_failure:
    SC_FREE(sc->privkey->key, 2 * n * sizeof(SINT16));
    SC_MEMZERO(t, 5 * n * sizeof(SINT32));
    return SC_FUNC_FAILURE;
}

SINT32 ens_kem_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT16 n, q_bits;
    SINT32 *t;
    SINT16 *pubkey;
    const SINT16 *w, *r;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    n      = sc->ens_kem->params->n;
    q_bits = sc->ens_kem->params->q_bits;
    w      = sc->ens_kem->params->w;
    r      = sc->ens_kem->params->r;

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ens_kem->ntt;

    t = sc->temp;
    pubkey = (SINT16 *) sc->pubkey->key;

    // Convert from NTT domain
    for (i=0; i<n; i++) {
        t[i] = pubkey[i];
    }
    sc_ntt->inv_ntt_32_16(t, ntt, t, w, r);
    sc_ntt->center_32(t, n, ntt);

    // Create a bit packer to compress the public key
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_pub_key,
        n * q_bits, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_SUCCESS;
    }
    entropy_poly_encode_32(packer, n, t, q_bits,
        SIGNED_COEFF, SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded);

    // Extract the buffer with the public key and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);
    sc->stats.pub_keys_encoded++;
    sc->stats.components[SC_STAT_PUB_KEY][0].bits += n * q_bits;

    return SC_FUNC_SUCCESS;
}

SINT32 ens_kem_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t i;
    UINT16 n, q_bits;
    const SINT16 *w, *r;

    n      = sc->ens_kem->params->n;
    q_bits = sc->ens_kem->params->q_bits;
    w      = sc->ens_kem->params->w;
    r      = sc->ens_kem->params->r;

    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ens_kem->ntt;

    SINT16 *privkey = (SINT16 *) sc->privkey->key;
    SINT32 *t = sc->temp;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Convert from NTT domain
    for (i=0; i<n; i++) {
        t[i] = privkey[i];
    }
    sc_ntt->inv_ntt_32_16(t, ntt, t, w, r);
    sc_ntt->center_32(t, n, ntt);

    // Create a bit packer to compress the private key polynomial
    sc_packer_t *packer = utils_entropy.pack_create(sc, &sc->coding_priv_key,
        n * q_bits, NULL, 0, key, key_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_32(packer, n, t, 5,
        SIGNED_COEFF, sc->coding_priv_key.type, 0, &sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded);

    // Extract the buffer with the polynomial f and release the packer resources
    utils_entropy.pack_get_buffer(packer, key, key_len);
    utils_entropy.pack_destroy(&packer);
    sc->stats.priv_keys_encoded++;
    sc->stats.components[SC_STAT_PRIV_KEY][0].bits += n * 5;

    return SC_FUNC_SUCCESS;
}

SINT32 ens_kem_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv)
{
    return SC_FUNC_FAILURE;
}


SINT32 ens_kem_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv)
{
    return SC_FUNC_FAILURE;
}

SINT32 ens_kem_keygen(safecrypto_t *sc)
{
    size_t i, iter;
    SINT32 *f, *g, *h, *u, *t;
    SINT16 *kg, *kh;
    UINT32 *inv_g;
    const SINT16 *w;
    UINT16 n, q;
    UINT16 coeff_ones = 0;

    if (NULL == sc)
        return SC_FUNC_FAILURE;

    SC_PRINT_DEBUG(sc, "NTRU-KEM KeyGen\n");

    n      = sc->ens_kem->params->n;
    q      = sc->ens_kem->params->q;
    w      = sc->ens_kem->params->w;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_vec_t *sc_vec = sc->sc_vec;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ens_kem->ntt;

    // Allocate key pair memory
    SC_PRINT_DEBUG(sc, "Memory allocation for keys\n");
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(2 * n * sizeof(SINT16));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }
    sc->privkey->len = 2 * n;
    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(n * sizeof(SINT16));
        if (NULL == sc->pubkey->key) {
            SC_FREE(sc->privkey->key, 2 * n * sizeof(SINT16));
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }
    sc->pubkey->len = n;

    // Assign pointers to the key-pair memory
    kg = (SINT16*) sc->privkey->key;
    kh = (SINT16*) sc->pubkey->key;

    // Assign pointers for intermediate and temporary storage
    f = sc->temp;
    g = sc->temp + n;
    t = sc->temp + 2 * n;
    u = sc->temp + 4 * n;
    h = sc->temp + 5 * n;
    inv_g = (UINT32*)(sc->privkey->key + n * sizeof(SINT16));

    // Calculate the number of non-zero coefficients in Z2
    for (i=0; i<13; i+=2) {
        coeff_ones += sc->ens_kem->params->coeff_rnd[i];
    }

    // Trial to find an invertible f
    for (iter=0; iter<99999; iter++) {

        // Generate random sparse polynomials with small coefficients
        // to act as the private key (Gaussian distirbution with a predefined
        // number of values according to the parameter set)
        sc_poly->uniform_32(sc->prng_ctx[0], g, n, sc->ens_kem->params->coeff_rnd, 12);
        // Obtain the inverse of g mod 2
        for (i=0; i<n; i++) {
            u[i] = g[i] & 0x1;
        }
        if (SC_FUNC_FAILURE == sc_poly->bin_inv_32(t, u, h, n)) {
            SC_PRINT_DEBUG(sc, "g is not invertible in Z2\n");
            continue;
        }
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "1/g mod 2", t, n);

        sc_poly->uniform_32(sc->prng_ctx[0], f, n, sc->ens_kem->params->coeff_rnd, 12);

        DOUBLE valid_norm = pow(sc->ens_kem->params->sk_norm, 2);
        SINT32 norm_v = sc_vec->scalar_32(f, f, n);
        SINT32 norm_w = sc_vec->scalar_32(g, g, n);
        DOUBLE valid_norm_max = valid_norm * 1.0025f;
        DOUBLE valid_norm_min = valid_norm * 0.9975f;
        SC_PRINT_DEBUG(sc, "Norm is %d / %3.3f [%3.3f^2]\n", norm_v + norm_w, valid_norm, sc->ens_kem->params->sk_norm);
        if ((norm_v+norm_w >= valid_norm_max) &&
            (norm_v+norm_w <= valid_norm_min)) {
            SC_PRINT_DEBUG(sc, "Error - Norm is %3.3f\n", norm_v + norm_w);
            continue;
        }

#if 0
        for (i=0; i<n; i++) {
            u[i] = f[i] & 0x1;
        }
        if (SC_FUNC_FAILURE == sc_poly->bin_inv_32(t, u, h, n)) {
            fprintf(stderr, "f is not invertible in Z2\n");
            continue;
        }
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "1/f mod 2", t, n);
        {
            SINT32 c[2*1024];
            sc_poly->field2n_mul_32(c, n, f, t);
            SINT32 pq[2*1024], pr[2*1024];
            SINT32 ip[2*1024] = {0};
            ip[0] = 1;
            ip[n] = 1;
            sc_poly->field2n_div_32(pq, pr, 2*n, c, ip);
            if (1 != pr[0]) {
                fprintf(stderr, "1/f[0] is not 1\n");
                continue;
            }
            for (i=1; i<n; i++) {
                if (0 != pr[i]) break;
            }
            if (i < n) {
                fprintf(stderr, "1/f[1:n-1] is not 0\n");
                continue;
            }
            SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "(f mod 2) * 1/(f mod 2)", pr, n);
        }
#endif

#if 0
        {
            SINT32 c[2*1024];
            sc_poly->field2n_mul_32(c, n, g, t);
            SINT32 pq[2*1024], pr[2*1024];
            SINT32 ip[2*1024] = {0};
            ip[0] = 1;
            ip[n] = 1;
            sc_poly->field2n_div_32(pq, pr, 2*n, c, ip);
            if (1 != pr[0]) {
                fprintf(stderr, "1/g[0] is not 1\n");
                continue;
            }
            for (i=1; i<n; i++) {
                if (0 != pr[i]) break;
            }
            if (i < n) {
                fprintf(stderr, "1/g[1:n-1] is not 0\n");
                continue;
            }
            SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "(g mod 2) * 1/(g mod 2)", pr, n);
        }
#endif

        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "f", f, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "g", g, n);

        // Attempt to invert g in Zq[x]/(x +- 1)
        sc_ntt->fwd_ntt_32_16(g, ntt, g, w);

        for (i=0; i<n; i++) {
            SINT32 x = sc_ntt->modn_32(g[i], ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_32(x, q - 2, ntt);
            u[i] = x;
        }
        if (i < n) {
            SC_PRINT_DEBUG(sc, "Could NOT invert g\n");
            SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "ntt(g)", g, n);
            continue;
        }

        SC_PRINT_DEBUG(sc, "Inversion after %d attempts\n", iter);

        // Convert f to the NTT domain
        // NOTE: Testing f for invertibility does not seem to be necessary
        sc_ntt->fwd_ntt_32_16(f, ntt, f, w);

#if 0
        // Check that g is invertible in Zq
        sc_ntt->mul_32_pointwise(h, &ntt, g, u);
        sc_ntt->fft_32_16(h, &ntt, w);
        sc_ntt->mul_32_pointwise_16(h, &ntt, h, r);
        sc_ntt->flip_32(h, &ntt);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "g * 1/g mod q", h, n);
#endif

        // Calculate h = f/g mod q
        sc_ntt->mul_32_pointwise(h, ntt, f, u);

        // Normalize h, g and 1/g
        sc_ntt->normalize_32(h, n, ntt);
        sc_ntt->normalize_32(g, n, ntt);

        for (i=0; i<n; i++) {
            h[i] = (h[i] > (q>>1))? h[i] - q : h[i];
            g[i] = (g[i] > (q>>1))? g[i] - q : g[i];
        }

        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "h", h, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "g", g, n);
        SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "1/g (mod 2)", t, n);

        // Store the public and private keys and the inverses of g
        for (i=n; i--;) {
            kg[i] = g[i];
            kh[i] = h[i];
        }
        reverse_and_pack_inv_g(t, n, inv_g);
        SC_PRINT_1D_UINT32_HEX(sc, SC_LEVEL_DEBUG, "inv_g", inv_g, n>>5);

        SC_PRINT_DEBUG(sc, "Print keys\n");
        SC_PRINT_KEYS(sc, SC_LEVEL_DEBUG, 16);

        SC_MEMZERO(f, 6 * n * sizeof(SINT32));
        return SC_FUNC_SUCCESS;
    }

finish_free:
    SC_MEMZERO(sc->temp, 6 * n * sizeof(SINT32));
    SC_FREE(sc->privkey->key, 2 * n * sizeof(SINT16));
    SC_FREE(sc->pubkey->key, n * sizeof(SINT16));
    return SC_FUNC_FAILURE;
}

SINT32 ens_kem_encapsulation(safecrypto_t *sc,
    UINT8 **c, size_t *c_len,
    UINT8 **k, size_t *k_len)
{
    size_t i;
    UINT16 n, q, q_bits;
    SINT16 *h;
    SINT32 *r, *e, *t;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;

    SC_PRINT_DEBUG(sc, "NTRU-KEM Encapsulation\n");

    // Assign values to commonly used variables
    n       = sc->ens_kem->params->n;
    q       = sc->ens_kem->params->q;
    q_bits  = sc->ens_kem->params->q_bits;

    // Obtain pointers to temporary storage variables
    r = sc->temp;
    e = sc->temp + n;
    t = sc->temp + 2 * n;

    // Obtain pointers to the public key
    h = (SINT16 *) sc->pubkey->key;

    // Increment the statistics for encapsulation
    sc->stats.encapsulate_num++;

    SC_PRINT_DEBUG(sc, "Encapsulating the error elements\n");

    // Generate the sparse random gaussian distributions
    sc_poly->uniform_32(sc->prng_ctx[0], r, n, sc->ens_kem->params->coeff_rnd, 12);
    sc_poly->uniform_32(sc->prng_ctx[0], e, n, sc->ens_kem->params->coeff_rnd, 12);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "r", r, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "e", e, n);

    // Calculate the ciphertext, t = 2hr + e mod q
    generate_ciphertext(sc, h, r, e, t, n, q);

    // Create the bit packer used to create the output ciphertext
    sc_packer_t *packer;
    packer = utils_entropy.pack_create(sc, &sc->coding_encryption, n * q_bits,
        NULL, 0, c, c_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_32(packer, n, t, q_bits,
        UNSIGNED_COEFF, sc->coding_encryption.type, 1, &sc->stats.components[SC_STAT_ENCAPSULATE][0].bits_coded);
    utils_entropy.pack_get_buffer(packer, c, c_len);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Ciphertext", *c, *c_len);
    utils_entropy.pack_destroy(&packer);
    sc->stats.components[SC_STAT_ENCAPSULATE][0].bits += n * q_bits;

    for (i=0; i<n; i++) {
        e[i] = e[i] & 0x1;
    }

    // Create the bit packer used to create the output master key
    packer = utils_entropy.pack_create(sc, &sc->coding_encryption, n,
        NULL, 0, k, k_len);
    if (NULL == packer) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    entropy_poly_encode_32(packer, n, e, 1,
        UNSIGNED_COEFF, SC_ENTROPY_NONE, 0, &sc->stats.components[SC_STAT_ENCAPSULATE][1].bits_coded);
    utils_entropy.pack_get_buffer(packer, k, k_len);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Master Key", *k, *k_len);
    utils_entropy.pack_destroy(&packer);
    sc->stats.components[SC_STAT_ENCAPSULATE][1].bits += n;

    sc->stats.components[SC_STAT_ENCAPSULATE][2].bits += (q_bits + 1) * n;
    sc->stats.components[SC_STAT_ENCAPSULATE][2].bits_coded += (*c_len + *k_len) * 8;

    // Reset the temporary memory
    SC_MEMZERO(sc->temp, 4 * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;
}

SINT32 ens_kem_decapsulation(safecrypto_t *sc,
    const UINT8 *c, size_t c_len,
    UINT8 **k, size_t *k_len)
{
    size_t i, j;
    UINT16 n, q, q_bits;
    SINT32 *t;
    UINT32 *x, *e, *inv_g;
    SINT16 *g;
    const SINT16 *ntt_w, *ntt_r;

    SC_PRINT_DEBUG(sc, "NTRU-KEM Decapsulation\n");

    // Increment the statistics for decapsulation
    sc->stats.decapsulate_num++;

    // Assign values to commonly used variables
    n         = sc->ens_kem->params->n;
    q         = sc->ens_kem->params->q;
    q_bits    = sc->ens_kem->params->q_bits;
    ntt_w     = sc->ens_kem->params->w;
    ntt_r     = sc->ens_kem->params->r;

    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ens_kem->ntt;

    // Obtain pointers to temporary storage variables
    t = sc->temp;
    e = (UINT32 *)(sc->temp + 2 * n);
    x = e + (n>>5);
    g = (SINT16 *) sc->privkey->key;
    inv_g = (UINT32*)(sc->privkey->key + n * sizeof(SINT16));

    // Create packers to obtain the data from the byte stream
    sc_entropy_t coding_raw = {
        .type = SC_ENTROPY_NONE,
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

    // Decode the data and decrypt it
    while (utils_entropy.pack_is_data_avail(ipacker)) {
        entropy_poly_decode_32(ipacker, n, t, q_bits,
            UNSIGNED_COEFF, sc->coding_encryption.type, 1);
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Ciphertext", t, n);

    // Calculate gt mod q mod 2
    sc_ntt->fwd_ntt_32_16(t, ntt, t, ntt_w);
    sc_ntt->mul_32_pointwise_16(t, ntt, t, g);
    sc_ntt->inv_ntt_32_16(t, ntt, t, ntt_w, ntt_r);

    SINT32 mask;
    for (i=0, j=0; i<n; i++) {
        mask = i & 0x1F;
        t[i] = (t[i] > (q>>1))? t[i] - q : t[i];
        t[i] = t[i] & 0x1;
        x[j] = (mask == 0)? (UINT32)t[i] << 31 :
                            x[j] | (t[i] << (31 - mask));
        j += (0x1F == mask);
    }
    SC_PRINT_1D_UINT32_HEX(sc, SC_LEVEL_DEBUG, "1/g", inv_g, n>>5);
    SC_PRINT_1D_UINT32_HEX(sc, SC_LEVEL_DEBUG, "x", x, n>>5);

    // Calculate (gt mod q mod 2 / g) mod 2
    sc_poly->z2_conv(x, inv_g, n, e);
    SC_PRINT_1D_UINT32_HEX(sc, SC_LEVEL_DEBUG, "e", e, n>>5);
    for (i=0; i<n>>5; i++) {
        utils_entropy.pack_insert(opacker, e[i] >> 16, 16);
        utils_entropy.pack_insert(opacker, e[i] & 0xFFFF, 16);
    }

    // Release all resources associated with the packers and obtain the
    // buffer with the plaintext byte stream
    utils_entropy.pack_destroy(&ipacker);
    utils_entropy.pack_get_buffer(opacker, k, k_len);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "Master Key", *k, *k_len);
    utils_entropy.pack_destroy(&opacker);

    SC_MEMZERO(sc->temp, 3 * n * sizeof(SINT32));
    return SC_FUNC_SUCCESS;
clean_finish:
    SC_MEMZERO(sc->temp, 3 * n * sizeof(SINT32));
    return SC_FUNC_FAILURE;
}

char * ens_kem_stats(safecrypto_t *sc)
{
    static const char* param_set_name[] = {"0", "I", "II", "III"};
    static char stats[2048];
    snprintf(stats, 2047, "\nENS-KEM-%s\n\
    KeyGen       %8" FMT_LIMB " key-pairs  / %8" FMT_LIMB " trials\n\
    Encryption   %8" FMT_LIMB "\n\
    Decryption   %8" FMT_LIMB "\n\n\
    PRNG:            %s\n\n\
    Public Key compression:      %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       total   %10.2f%13.2f%16.3f%%\n\n\
    Private Key compression:     %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       total   %10.2f%13.2f%16.3f%%\n\n\
    Encryption compression:      %s\n\
               Uncoded bits   Coded bits   Compression Ratio\n\
       t       %10.2f%13.2f%16.3f%%\n\
       key     %10.2f%13.2f%16.3f%%\n\
       total   %10.2f%13.2f%16.3f%%\n\n",
        param_set_name[sc->ens_kem->params->set],
        sc->stats.keygen_num,
        sc->stats.keygen_num_trials,
        sc->stats.encapsulate_num,
        sc->stats.decapsulate_num,
        safecrypto_prng_names[(int)prng_get_type(sc->prng_ctx[0])],
        sc_entropy_names[(int)sc->coding_pub_key.type],
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.pub_keys_encoded : 0,
        sc->stats.pub_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PUB_KEY][0].bits : 0,
        sc_entropy_names[(int)sc->coding_priv_key.type],
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded/(DOUBLE)sc->stats.priv_keys_encoded : 0,
        sc->stats.priv_keys_encoded? 100 * (DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_PRIV_KEY][0].bits : 0,
        sc_entropy_names[(int)sc->coding_encryption.type],
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][0].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][1].bits,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits/(DOUBLE)sc->stats.encapsulate_num,
        (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits_coded/(DOUBLE)sc->stats.encapsulate_num,
        100 * (DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits_coded/(DOUBLE)sc->stats.components[SC_STAT_ENCAPSULATE][2].bits);
    return stats;
}


#undef FMT_LIMB
