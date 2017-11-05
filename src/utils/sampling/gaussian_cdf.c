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

#include "gaussian_cdf.h"
#include "sampling.h"
#include "safecrypto_private.h"
#include "utils/crypto/prng.h"
#include "utils/arith/sc_math.h"

#include <math.h>
#if 0
#include "utils/arith/sc_mpf128.h"
#else
#include "utils/arith/sc_mpf.h"
#endif


/// A union used to store up to 256-bit values
typedef struct _u256 {
#if 32 == SC_LIMB_BITS
    sc_ulimb_t w[8];
#else
    sc_ulimb_t w[4];
#endif
} u256_t;

/// A union used to store up to 256-bit values
typedef struct _u192 {
#if 32 == SC_LIMB_BITS
    sc_ulimb_t w[6];
#else
    sc_ulimb_t w[3];
#endif
} u192_t;

/// A union used to store up to 256-bit values
typedef struct _u128 {
#if 32 == SC_LIMB_BITS
    sc_ulimb_t w[4];
#else
    sc_ulimb_t w[2];
#endif
} u128_t;


#if !defined(DISABLE_HIGH_PREC_GAUSSIAN)
SC_STRUCT_PACK_START
typedef struct _gauss_cdf_high {
    u256_t *cdf_256;
    u192_t *cdf_192;
    u128_t *cdf_128;
    SINT32 cdf_size;
    SINT32 k;
    SINT32 use_kl_divergence;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_cdf_high_t;
SC_STRUCT_PACK_END
#endif

SC_STRUCT_PACK_START
typedef struct _gauss_cdf_64 {
    UINT64 *cdf;
    SINT32 cdf_size;
    SINT32 k;
    SINT32 use_kl_divergence;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_cdf_64_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct _gauss_cdf_32 {
    UINT32 *cdf;
    SINT32 cdf_size;
    SINT32 k;
    SINT32 use_kl_divergence;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_cdf_32_t;
SC_STRUCT_PACK_END


static size_t find_kldiv_k(size_t max_lut_bytes, FLOAT tail, FLOAT *sigma)
{
    size_t k = 0;
    size_t sigma_1 = (*sigma) / sqrt(1 + k*k);
    size_t bits = sc_ceil_log2(tail * sigma_1);
    size_t lut_size = (1 << bits) * sizeof(UINT64);
    while (lut_size > max_lut_bytes) {
        k++;
        sigma_1 = (*sigma) / sqrt(1 + k*k);
        bits = sc_ceil_log2(tail * sigma_1);
        lut_size = (1 << bits) * sizeof(UINT64);
    }
    *sigma = sigma_1;
    return k;
}

#if !defined(DISABLE_HIGH_PREC_GAUSSIAN)
static SINT32 compare_ge_prec(volatile const sc_ulimb_t *x, volatile const sc_ulimb_t *y, size_t prec)
{
#if 32 == SC_LIMB_BITS
    const size_t num_words = prec >> 5;
#else
    const size_t num_words = prec >> 6;
#endif
    size_t i;
    volatile sc_ulimb_t retval = 1;
    for (i=0; i<num_words; i++) {
        sc_ulimb_t a      = x[i];
        sc_ulimb_t b      = y[i];
        sc_ulimb_t equal  = !(a ^ b);
        sc_ulimb_t x_lt_y = sc_const_time_lessthan(a, b);
        retval = !x_lt_y || (equal && retval);
    }
    return retval;
}

static SINT32 binary_search_128(u128_t x, const u128_t *l, SINT32 n)
{
    // Given the table l of length n, return the address in the table
    // that satisfies the condition x >= l[b]

    SINT32 a;
    SINT32 st = n >> 1;

    a = 0;
    while (st > 0) {
        SINT32 b = a + st;
        if (b < n && compare_ge_prec(x.w, (sc_ulimb_t *)l[b].w, 128)) {
            a = b;
        }
        st >>= 1;
    }
    return a;
}

static SINT32 binary_search_192(u192_t x, const u192_t *l, SINT32 n)
{
    // Given the table l of length n, return the address in the table
    // that satisfies the condition x >= l[b]

    SINT32 a;
    SINT32 st = n >> 1;

    a = 0;
    while (st > 0) {
        SINT32 b = a + st;
        if (b < n && compare_ge_prec(x.w, (sc_ulimb_t *)l[b].w, 192)) {
            a = b;
        }
        st >>= 1;
    }
    return a;
}

static SINT32 binary_search_256(u256_t x, const u256_t *l, SINT32 n)
{
    // Given the table l of length n, return the address in the table
    // that satisfies the condition x >= l[b]

    SINT32 a;
    SINT32 st = n >> 1;

    a = 0;
    while (st > 0) {
        SINT32 b = a + st;
        if (b < n && compare_ge_prec(x.w, (sc_ulimb_t *)l[b].w, 256)) {
            a = b;
        }
        st >>= 1;
    }
    return a;
}

void gauss_cdf_create_high_precision(prng_ctx_t *prng_ctx, gauss_cdf_high_t *gauss, size_t num_words, size_t precision, FLOAT sigma, sample_blinding_e blinding)
{
    size_t i, j;
    sc_mpf_t s, d, e, t0, t1, sigma128, half128, two_sqrt_2pi, sqrt_1_2;

    sc_mpf_set_precision(precision);  // Note: Additional guard bits in the precision improve the rounding to zero at higher addresses

    sc_mpf_init(&s);
    sc_mpf_init(&d);
    sc_mpf_init(&e);
    sc_mpf_init(&sigma128);
    sc_mpf_init(&half128);
    sc_mpf_init(&t0);
    sc_mpf_init(&t1);
    sc_mpf_init(&two_sqrt_2pi);
    sc_mpf_init(&sqrt_1_2);
    sc_mpf_get_pi(&t0);
    sc_mpf_mul_2exp(&t1, &t0, 1);
    sc_mpf_sqrt(&t0, &t1);
    sc_mpf_set_ui(&t1, 2);
    sc_mpf_div(&two_sqrt_2pi, &t1, &t0);
    sc_mpf_set_d(&t1, 0.5);
    sc_mpf_sqrt(&sqrt_1_2, &t1);
    
    sc_mpf_set_d(&sigma128, sigma);
    sc_mpf_set_d(&half128, 0.5);

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sc_mpf_mul(&sigma128, &sigma128, &sqrt_1_2);
    }

    // 2/sqrt(2*Pi) * (1 << precision) / sigma
    sc_mpf_set_ui(&d, 2);
    sc_mpf_pow_ui(&t0, &d, precision);
    sc_mpf_div(&t1, &t0, &sigma128);
    sc_mpf_mul(&d, &t1, &two_sqrt_2pi);

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    sc_mpf_mul(&t0, &sigma128, &sigma128);
    sc_mpf_div(&e, &half128, &t0);
    sc_mpf_negate(&e, &e);
    sc_mpf_mul(&s, &d, &half128);

    for (i=0; i<num_words; i++) {
        if (128 == precision) {
            gauss->cdf_128[0].w[i] = 0;
        }
        else if (192 == precision) {
            gauss->cdf_192[0].w[i] = 0;
        }
        else if (256 == precision) {
            gauss->cdf_256[0].w[i] = 0;
        }
    }

    for (i=1; i<gauss->cdf_size-1; i++) {
        sc_ulimb_t temp[num_words], same;
        sc_mpf_t *a, *b, *c;
        sc_mpf_set(&t0, &s);
        sc_mpf_div_2exp(&t1, &t0, ((num_words-1) * SC_LIMB_BITS));
        a = &t1;
        b = &t0;
        for (j=num_words-1; j!=0; j--) {
            temp[j] = sc_mpf_get_ui(a);
            sc_mpf_set_ui(b, temp[j]);
            sc_mpf_sub(a, a, b);
            sc_mpf_mul_2exp(b, a, SC_LIMB_BITS);
            c = a;
            a = b;
            b = c;
        }
        temp[0] = sc_mpf_get_ui(a);

        for (j=0; j<num_words; j++) {
            if (128 == precision) {
                gauss->cdf_128[i].w[j] = temp[j];
            }
            else if (192 == precision) {
                gauss->cdf_192[i].w[j] = temp[j];
            }
            else if (256 == precision) {
                gauss->cdf_256[i].w[j] = temp[j];
            }
        }
        if (sc_mpf_is_zero(&s))        // overflow, sc_mpf_get_si() == 0 may be better than the singular
            break;
        // s += d.exp(e.i.i)
        sc_mpf_mul_ui(&t0, &e, i*i);
        sc_mpf_exp(&t1, &t0);
        sc_mpf_mul(&t0, &d, &t1);
        sc_mpf_add(&s, &s, &t0);
    }
    {
        sc_ulimb_t all_ones[num_words];
        for (j=0; j<num_words; j++) {
            all_ones[j] = SC_LIMB_WORD(-1);
        }

        for (; i<gauss->cdf_size; i++) {
            for (j=0; j<num_words; j++) {
                if (128 == precision) {
                    gauss->cdf_128[i].w[j] = all_ones[j];
                }
                else if (192 == precision) {
                    gauss->cdf_192[i].w[j] = all_ones[j];
                }
                else if (256 == precision) {
                    gauss->cdf_256[i].w[j] = all_ones[j];
                }
            }
        }
    }

    /*for (i=0; i<gauss->cdf_size; i++) {
        for (j=0; j<num_words; j++) {
            fprintf(stderr, "%016lX", gauss->cdf_128[i].w[num_words-1-j]);
        }
        fprintf(stderr, "\n");
    }*/
finish:
    sc_mpf_clear(&s);
    sc_mpf_clear(&d);
    sc_mpf_clear(&e);
    sc_mpf_clear(&sigma128);
    sc_mpf_clear(&half128);
    sc_mpf_clear(&t0);
    sc_mpf_clear(&t1);
    sc_mpf_clear(&two_sqrt_2pi);
    sc_mpf_clear(&sqrt_1_2);
    sc_mpf_clear_constants();
}

static void * gaussian_cdf_create_high(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma, sample_blinding_e blinding, size_t precision)
{
    SINT32 bits;
    size_t k = 0;//find_kldiv_k(max_lut_bytes, tail, &sigma);
#if 32 == SC_LIMB_BITS
    size_t num_words = precision >> 5;
#else
    size_t num_words = precision >> 6;
#endif

    bits = sc_ceil_log2(tail * sigma);

    // Allocate memory for the structure to be passed as a void *
    gauss_cdf_high_t *gauss = SC_MALLOC(sizeof(gauss_cdf_high_t));
    if (NULL == gauss) {
        return NULL;
    }

    // Allocate memory for the pre-computed Gaussian distribution
    if (128 == precision) {
        gauss->cdf_128 = SC_MALLOC((1 << bits) * sizeof(u128_t));
        if (NULL == gauss->cdf_128) {
            SC_FREE(gauss, sizeof(gauss_cdf_high_t));
            return NULL;
        }
    }
    else if (192 == precision) {
        gauss->cdf_192 = SC_MALLOC((1 << bits) * sizeof(u192_t));
        if (NULL == gauss->cdf_192) {
            SC_FREE(gauss, sizeof(gauss_cdf_high_t));
            return NULL;
        }
    }
    else {
        gauss->cdf_256 = SC_MALLOC((1 << bits) * sizeof(u256_t));
        if (NULL == gauss->cdf_256) {
            SC_FREE(gauss, sizeof(gauss_cdf_high_t));
            return NULL;
        }
    }

    // Store the Kullback-Leibler divergence constant
    gauss->k = k;

    // Store the size of the distribution
    gauss->cdf_size = (1 << bits);

    // Store a pointer to the PRNG context
    gauss->prng_ctx = prng_ctx;

    gauss_cdf_create_high_precision(prng_ctx, gauss, num_words, precision, sigma, blinding);

    return (void *) gauss;
}

void * gaussian_cdf_create_128(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma, size_t max_lut_bytes, sample_blinding_e blinding)
{
    (void) max_lut_bytes;

    return gaussian_cdf_create_high(prng_ctx, tail, sigma, blinding, 128);
}

void * gaussian_cdf_create_192(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma, size_t max_lut_bytes, sample_blinding_e blinding)
{
    (void) max_lut_bytes;

    return gaussian_cdf_create_high(prng_ctx, tail, sigma, blinding, 192);
}

void * gaussian_cdf_create_256(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma, size_t max_lut_bytes, sample_blinding_e blinding)
{
    (void) max_lut_bytes;

    return gaussian_cdf_create_high(prng_ctx, tail, sigma, blinding, 256);
}

SINT32 gaussian_cdf_destroy_128(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_cdf_high_t *gauss = (gauss_cdf_high_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->cdf_128, gauss->cdf_size * sizeof(u128_t));
    SC_FREE(*sampler, sizeof(gauss_cdf_high_t));

    return SC_FUNC_SUCCESS;
}

SINT32 gaussian_cdf_destroy_192(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_cdf_high_t *gauss = (gauss_cdf_high_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->cdf_192, gauss->cdf_size * sizeof(u192_t));
    SC_FREE(*sampler, sizeof(gauss_cdf_high_t));

    return SC_FUNC_SUCCESS;
}

SINT32 gaussian_cdf_destroy_256(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_cdf_high_t *gauss = (gauss_cdf_high_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->cdf_256, gauss->cdf_size * sizeof(u256_t));
    SC_FREE(*sampler, sizeof(gauss_cdf_high_t));

    return SC_FUNC_SUCCESS;
}

prng_ctx_t * gaussian_cdf_get_prng_128(void *sampler)
{
    gauss_cdf_high_t *gauss = (gauss_cdf_high_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}

SINT32 gaussian_cdf_sample_128(void *sampler)
{
    // Return a random gaussian sample from a pre-computed distribution

    SINT32 a;
    u128_t x;
    gauss_cdf_high_t *gauss = (gauss_cdf_high_t *) sampler;

    x.w[0] = prng_64(gauss->prng_ctx);
    x.w[1] = prng_64(gauss->prng_ctx);
#if 32 == SC_LIMB_BITS
    x.w[2] = prng_32(gauss->prng_ctx);
    x.w[3] = prng_32(gauss->prng_ctx);
#endif
    a = binary_search_128(x, gauss->cdf_128, gauss->cdf_size);

    return (x.w[0] & 1)? a : -a;
}

SINT32 gaussian_cdf_sample_192(void *sampler)
{
    // Return a random gaussian sample from a pre-computed distribution

    SINT32 a;
    u192_t x;
    gauss_cdf_high_t *gauss = (gauss_cdf_high_t *) sampler;

    x.w[0] = prng_64(gauss->prng_ctx);
    x.w[1] = prng_64(gauss->prng_ctx);
    x.w[2] = prng_64(gauss->prng_ctx);
#if 32 == SC_LIMB_BITS
    x.w[3] = prng_32(gauss->prng_ctx);
    x.w[4] = prng_32(gauss->prng_ctx);
    x.w[5] = prng_32(gauss->prng_ctx);
#endif
    a = binary_search_192(x, gauss->cdf_192, gauss->cdf_size);

    return (x.w[0] & 1)? a : -a;
}

SINT32 gaussian_cdf_sample_256(void *sampler)
{
    // Return a random gaussian sample from a pre-computed distribution

    SINT32 a;
    u256_t x;
    gauss_cdf_high_t *gauss = (gauss_cdf_high_t *) sampler;

    x.w[0] = prng_64(gauss->prng_ctx);
    x.w[1] = prng_64(gauss->prng_ctx);
    x.w[2] = prng_64(gauss->prng_ctx);
    x.w[4] = prng_64(gauss->prng_ctx);
#if 32 == SC_LIMB_BITS
    x.w[4] = prng_32(gauss->prng_ctx);
    x.w[5] = prng_32(gauss->prng_ctx);
    x.w[6] = prng_32(gauss->prng_ctx);
    x.w[7] = prng_32(gauss->prng_ctx);
#endif
    a = binary_search_256(x, gauss->cdf_256, gauss->cdf_size);

    return (x.w[0] & 1)? a : -a;
}
#endif


static SINT32 binary_search_64(UINT64 x, const UINT64 *l, SINT32 n)
{
    // Given the table l of length n, return the address in the table
    // that satisfies the condition x >= l[b]

    SINT32 a;
    SINT32 st = n >> 1;

    a = 0;
    while (st > 0) {
        SINT32 b = a + st;
        if (b < n && x >= l[b])
            a = b;
        st >>= 1;
    }
    return a;
}

void * gaussian_cdf_create_64(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma, size_t max_lut_bytes, sample_blinding_e blinding)
{
    (void) max_lut_bytes;

    SINT32 i;
    LONGDOUBLE s, d, e;
    size_t k = 0;//find_kldiv_k(max_lut_bytes, tail, &sigma);
    SINT32 bits = sc_ceil_log2(tail * sigma);

    // Allocate memory for the structure to be passed as a void *
    gauss_cdf_64_t *gauss = SC_MALLOC(sizeof(gauss_cdf_64_t));
    if (NULL == gauss) {
        return NULL;
    }

    // Store the Kullback-Leibler divergence constant
    gauss->k = k;

    // Allocate memory for the pre-computed Gaussian distribution
    gauss->cdf = SC_MALLOC((1 << bits) * sizeof(UINT64));
    if (NULL == gauss->cdf) {
        SC_FREE(gauss, sizeof(gauss_cdf_64_t));
        return NULL;
    }

    // Store the size of the distribution
    gauss->cdf_size = (1 << bits);

    // Store a pointer to the PRNG context
    gauss->prng_ctx = prng_ctx;

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sigma *= SC_M_SQRT1_2l;
    }

    // 2/sqrt(2*Pi) * (1 << 64) / sigma
    d = SC_M_2_SQRTPIl * SC_M_SQRT1_2l * 18446744073709551616.0L / sigma;

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    e = -0.5L / (sigma * sigma);
    s = 0.5L * d;
    gauss->cdf[0] = 0;
    for (i=1; i<gauss->cdf_size-1; i++) {
        gauss->cdf[i] = s;
        if (gauss->cdf[i] == 0)        // overflow
            break;
        s += d * expl(e * ((LONGDOUBLE) (i*i)));
    }
    for (; i<gauss->cdf_size; i++) {
        gauss->cdf[i] = 0xFFFFFFFFFFFFFFFF;
    }

    return (void *) gauss;
}

SINT32 gaussian_cdf_destroy_64(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_cdf_64_t *gauss = (gauss_cdf_64_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->cdf, gauss->cdf_size * sizeof(UINT64));
    SC_FREE(*sampler, sizeof(gauss_cdf_64_t));

    return SC_FUNC_SUCCESS;
}

prng_ctx_t * gaussian_cdf_get_prng_64(void *sampler)
{
    gauss_cdf_64_t *gauss = (gauss_cdf_64_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}

SINT32 gaussian_cdf_sample_64(void *sampler)
{
    // Return a random gaussian sample from a pre-computed distribution

    SINT32 a;
    UINT64 x;
    gauss_cdf_64_t *gauss = (gauss_cdf_64_t *) sampler;
    size_t k = gauss->k;

    x = prng_64(gauss->prng_ctx);
    a = binary_search_64(x, gauss->cdf, gauss->cdf_size);
    if (k > 0) {
        SINT32 b;
        UINT64 y;
        y  = prng_64(gauss->prng_ctx);
        b  = binary_search_64(y, gauss->cdf, gauss->cdf_size);
        a += k * b;
    }

    return (x & 1)? a : -a;
}

static SINT32 binary_search_32(UINT32 x, const UINT32 *l, SINT32 n)
{
    // Given the table l of length n, return the address in the table
    // that satisfies the condition x >= l[b]

    SINT32 a;
    SINT32 st = n >> 1;

    a = 0;
    while (st > 0) {
        SINT32 b = a + st;
        if (b < n && x >= l[b])
            a = b;
        st >>= 1;
    }
    return a;
}

void * gaussian_cdf_create_32(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma, size_t max_lut_bytes, sample_blinding_e blinding)
{
    (void) max_lut_bytes;

    SINT32 i;
    FLOAT s, d, e;
    SINT32 bits = sc_ceil_log2(tail * sigma);

    // Allocate memory for the structure to be passed as a void *
    gauss_cdf_32_t *gauss = SC_MALLOC(sizeof(gauss_cdf_32_t));
    if (NULL == gauss) {
        return NULL;
    }

    // Allocate memory for the pre-computed Gaussian distribution
    gauss->cdf = SC_MALLOC((1 << bits) * sizeof(UINT32));
    if (NULL == gauss->cdf) {
        SC_FREE(gauss, sizeof(gauss_cdf_32_t));
        return NULL;
    }

    // Store the size of the distribution
    gauss->cdf_size = (1 << bits);

    // Store a pointer to the PRNG context
    gauss->prng_ctx = prng_ctx;

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sigma *= M_SQRT1_2;
    }

    // 2/sqrt(2*Pi) * (1 << 32) / sigma
    d = M_2_SQRTPI * M_SQRT1_2 * 4294967296.0 / sigma;

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    e = -0.5L / (sigma * sigma);
    s = 0.5L * d;
    gauss->cdf[0] = 0;
    for (i=1; i<gauss->cdf_size-1; i++) {
        //DOUBLE intpart, fracpart;
        //fracpart = modf(s, &intpart);
        gauss->cdf[i] = s;
        if (gauss->cdf[i] == 0)        // overflow
            break;
        s += d * expl(e * ((FLOAT) (i*i)));
    }
    for (; i<gauss->cdf_size; i++) {
        gauss->cdf[i] = 0xFFFFFFFF;
    }

    return (void *) gauss;
}

SINT32 gaussian_cdf_destroy_32(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_cdf_32_t *gauss = (gauss_cdf_32_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->cdf, gauss->cdf_size * sizeof(UINT32));
    SC_FREE(*sampler, sizeof(gauss_cdf_32_t));

    return SC_FUNC_SUCCESS;
}

prng_ctx_t * gaussian_cdf_get_prng_32(void *sampler)
{
    gauss_cdf_32_t *gauss = (gauss_cdf_32_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}

SINT32 gaussian_cdf_sample_32(void *sampler)
{
    // Return a random gaussian sample from a pre-computed distribution

    SINT32 a;
    UINT32 x;
    gauss_cdf_32_t *gauss = (gauss_cdf_32_t *) sampler;

    x = prng_32(gauss->prng_ctx);
    a = binary_search_32(x, gauss->cdf, gauss->cdf_size);

    return (x & 1)? a : -a;
}
