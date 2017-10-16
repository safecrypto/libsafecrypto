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

#ifdef HAVE_128BIT
SC_STRUCT_PACK_START
typedef struct _gauss_cdf_128 {
    UINT128 *cdf;
    SINT32 cdf_size;
    SINT32 k;
    SINT32 use_kl_divergence;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_cdf_128_t;
SC_STRUCT_PACK_END
#endif

#ifdef HAVE_64BIT
SC_STRUCT_PACK_START
typedef struct _gauss_cdf_64 {
    UINT64 *cdf;
    SINT32 cdf_size;
    SINT32 k;
    SINT32 use_kl_divergence;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_cdf_64_t;
SC_STRUCT_PACK_END
#endif

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

#ifdef HAVE_128BIT
static SINT32 binary_search_128(UINT128 x, const UINT128 *l, SINT32 n)
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

void * gaussian_cdf_create_128(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma, size_t max_lut_bytes, sample_blinding_e blinding)
{
    (void) max_lut_bytes;

#if 0
    SINT32 i, bits;
    FLOAT128 s, d, e, sigma128, half128, two64;
    size_t k = 0;//find_kldiv_k(max_lut_bytes, tail, &sigma);
    
    bits     = sc_ceil_log2(tail * sigma);
    sigma128 = sc_mpf128_convert_f32_to_f128(sigma);
    half128  = sc_mpf128_convert_f32_to_f128(0.5);
    two64    = sc_mpf128_convert_f32_to_f128(18446744073709551616.0L);

    // Allocate memory for the structure to be passed as a void *
    gauss_cdf_128_t *gauss = SC_MALLOC(sizeof(gauss_cdf_128_t));
    if (NULL == gauss) {
        return NULL;
    }

    // Store the Kullback-Leibler divergence constant
    gauss->k = k;

    // Allocate memory for the pre-computed Gaussian distribution
    gauss->cdf = SC_MALLOC((1 << bits) * sizeof(UINT128));
    if (NULL == gauss->cdf) {
        SC_FREE(gauss, sizeof(gauss_cdf_128_t));
        return NULL;
    }

    // Store the size of the distribution
    gauss->cdf_size = (1 << bits);

    // Store a pointer to the PRNG context
    gauss->prng_ctx = prng_ctx;

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sigma128 = sc_mpf128_mul(sigma128, SC_SQRT1_2_QUAD);
    }

    // 2/sqrt(2*Pi) * (1 << 128) / sigma
    d  = sc_mpf128_mul(SC_2_SQRTPI_QUAD, SC_SQRT1_2_QUAD);
    d  = sc_mpf128_mul(d, two64);
    d  = sc_mpf128_mul(d, two64);
    d  = sc_mpf128_div(d, sigma128);

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    e = sc_mpf128_neg(sc_mpf128_div(half128, sc_mpf128_mul(sigma128, sigma128)));
    s = sc_mpf128_mul(half128, d);
    gauss->cdf[0] = 0;
    for (i=1; i<gauss->cdf_size-1; i++) {
        gauss->cdf[i] = sc_mpf128_convert_f128_to_ui128(s);
        if (gauss->cdf[i] == 0)        // overflow
            break;
        s = sc_mpf128_add(s, sc_mpf128_mul(d, sc_mpf128_exp(sc_mpf128_mul(e, sc_mpf128_convert_ui32_to_f128(i*i)))));
    }
    {
        UINT128 all_ones;
        all_ones   = 0xFFFFFFFFFFFFFFFF;
        all_ones <<= 64;
        all_ones  |= 0xFFFFFFFFFFFFFFFF;
        for (; i<gauss->cdf_size; i++) {
            gauss->cdf[i]   = all_ones;
        }
    }
#else
    size_t i;
    SINT32 bits;
    sc_mpf_t s, d, e, t0, t1, sigma128, half128, two_sqrt_2pi, sqrt_1_2;
    size_t k = 0;//find_kldiv_k(max_lut_bytes, tail, &sigma);

    sc_mpf_set_precision(128);  // Additional guard bits in the precision improve the rounding to zero at higher addresses

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
    
    bits = sc_ceil_log2(tail * sigma);
    sc_mpf_set_d(&sigma128, sigma);
    sc_mpf_set_d(&half128, 0.5);

    // Allocate memory for the structure to be passed as a void *
    gauss_cdf_128_t *gauss = SC_MALLOC(sizeof(gauss_cdf_128_t));
    if (NULL == gauss) {
        return NULL;
    }

    // Store the Kullback-Leibler divergence constant
    gauss->k = k;

    // Allocate memory for the pre-computed Gaussian distribution
    gauss->cdf = SC_MALLOC((1 << bits) * sizeof(UINT128));
    if (NULL == gauss->cdf) {
        SC_FREE(gauss, sizeof(gauss_cdf_128_t));
        return NULL;
    }

    // Store the size of the distribution
    gauss->cdf_size = (1 << bits);

    // Store a pointer to the PRNG context
    gauss->prng_ctx = prng_ctx;

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sc_mpf_mul(&sigma128, &sigma128, &sqrt_1_2);
    }

    // 2/sqrt(2*Pi) * (1 << 128) / sigma
    sc_mpf_set_ui(&d, 2);
    sc_mpf_pow_ui(&t0, &d, 128);
    sc_mpf_div(&t1, &t0, &sigma128);
    sc_mpf_mul(&d, &t1, &two_sqrt_2pi);

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    sc_mpf_mul(&t0, &sigma128, &sigma128);
    sc_mpf_div(&e, &half128, &t0);
    sc_mpf_negate(&e, &e);
    sc_mpf_mul(&s, &d, &half128);

    gauss->cdf[0] = 0;
    for (i=1; i<gauss->cdf_size-1; i++) {
        UINT128 temp;
#if 32 == SC_LIMB_BITS
        sc_mpf_set(&t0, &s);
        sc_mpf_div_2exp(&t1, &t0, 96);
        temp   = (UINT128)sc_mpf_get_ui(&t1);

        sc_mpf_set_ui(&t0, temp);
        temp <<= 32;
        sc_mpf_sub(&t1, &t1, &t0);
        sc_mpf_mul_2exp(&t0, &t1, 32);
        temp  |= (UINT128)sc_mpf_get_ui(&t0);

        sc_mpf_set_ui(&t0, temp);
        temp <<= 32;
        sc_mpf_sub(&t1, &t1, &t0);
        sc_mpf_mul_2exp(&t0, &t1, 32);
        temp  |= (UINT128)sc_mpf_get_ui(&t0);

        sc_mpf_set_ui(&t0, temp);
        temp <<= 32;
        sc_mpf_sub(&t1, &t1, &t0);
        sc_mpf_mul_2exp(&t0, &t1, 32);
        temp  |= (UINT128)sc_mpf_get_ui(&t0);
#else
        sc_mpf_set(&t0, &s);
        sc_mpf_div_2exp(&t1, &t0, 64);
        temp   = (UINT128)sc_mpf_get_ui(&t1);

        sc_mpf_set_ui(&t0, temp);
        temp <<= 64;
        sc_mpf_sub(&t1, &t1, &t0);
        sc_mpf_mul_2exp(&t0, &t1, 64);
        temp  |= (UINT128)sc_mpf_get_ui(&t0);
#endif
        gauss->cdf[i] = temp;
        if (sc_mpf_is_zero(&s))        // overflow, sc_mpf_get_si() == 0 may be better than the singular
            break;
        // s += d.exp(e.i.i)
        sc_mpf_mul_ui(&t0, &e, i*i);
        sc_mpf_exp(&t1, &t0);
        sc_mpf_mul(&t0, &d, &t1);
        sc_mpf_add(&s, &s, &t0);
    }
    {
        UINT128 all_ones;
        all_ones   = 0xFFFFFFFFFFFFFFFF;
        all_ones <<= 64;
        all_ones  |= 0xFFFFFFFFFFFFFFFF;
        for (; i<gauss->cdf_size; i++) {
            gauss->cdf[i] = all_ones;
        }
    }

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

#endif

    return (void *) gauss;
}

SINT32 gaussian_cdf_destroy_128(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_cdf_128_t *gauss = (gauss_cdf_128_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->cdf, gauss->cdf_size * sizeof(UINT128));
    SC_FREE(*sampler, sizeof(gauss_cdf_64_t));

    return SC_FUNC_SUCCESS;
}

prng_ctx_t * gaussian_cdf_get_prng_128(void *sampler)
{
    gauss_cdf_128_t *gauss = (gauss_cdf_128_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}

SINT32 gaussian_cdf_sample_128(void *sampler)
{
    // Return a random gaussian sample from a pre-computed distribution

    SINT32 a;
    UINT128 x;
    gauss_cdf_128_t *gauss = (gauss_cdf_128_t *) sampler;

    x = prng_128(gauss->prng_ctx);
    a = binary_search_128(x, gauss->cdf, gauss->cdf_size);

    return (x & 1)? a : -a;
}
#endif

#ifdef HAVE_64BIT
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
#endif

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
