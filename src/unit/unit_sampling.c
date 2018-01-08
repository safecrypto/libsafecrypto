/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <stdlib.h>
#include <check.h>
#include "safecrypto.h"
#include "safecrypto_private.h"
#include "safecrypto_version.h"
#include "utils/crypto/prng.c"
#include "utils/sampling/sampling.h"
#ifdef HAVE_CDF_GAUSSIAN_SAMPLING
#include "utils/sampling/gaussian_cdf.c"
#endif
#ifdef HAVE_KNUTH_YAO_GAUSSIAN_SAMPLING
#include "utils/sampling/gaussian_knuth_yao.c"
#endif
#ifdef HAVE_KNUTH_YAO_FAST_GAUSSIAN_SAMPLING
#include "utils/sampling/gaussian_knuth_yao_fast.c"
#endif
#ifdef HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
#include "utils/sampling/gaussian_ziggurat.c"
#endif
#ifdef HAVE_BERNOULLI_GAUSSIAN_SAMPLING
#include "utils/sampling/gaussian_bernoulli.c"
#endif
#include "utils/sampling/mw_bootstrap.c"


#ifdef HAVE_CDF_GAUSSIAN_SAMPLING
#if !defined(DISABLE_HIGH_PREC_GAUSSIAN)
START_TEST(test_gaussian_create_128)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_128(prng_ctx, 12, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_cdf_destroy_128(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_destroy_bad_128)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_128(prng_ctx, 12, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_cdf_destroy_128(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = gaussian_cdf_destroy_128(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_range_128)
{
    size_t i;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_128(prng_ctx, 12, 100.0f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    gauss_cdf_high_t *gauss_data = (gauss_cdf_high_t *) gauss;
#if 32 == SC_LIMB_BITS
    ck_assert_int_eq(gauss_data->cdf_128[0].w[3], 0);
    ck_assert_int_eq(gauss_data->cdf_128[0].w[2], 0);
    ck_assert_int_eq(gauss_data->cdf_128[0].w[1], 0);
    ck_assert_int_eq(gauss_data->cdf_128[0].w[0], 0);
#else
    ck_assert_int_eq(gauss_data->cdf_128[0].w[1], 0);
    ck_assert_int_eq(gauss_data->cdf_128[0].w[0], 0);
#endif
    for (i=1; i<gauss_data->cdf_size-1; i++) {
#if 32 == SC_LIMB_BITS
        fprintf(stderr, "%zu %08lX%08lX\n", i, gauss_data->cdf_128[i].w[3], gauss_data->cdf_128[i].w[2], gauss_data->cdf_128[i].w[1], gauss_data->cdf_128[i].w[0]);
#else
        fprintf(stderr, "%zu %016lX%016lX\n", i, gauss_data->cdf_128[i].w[1], gauss_data->cdf_128[i].w[0]);
#endif
        //ck_assert_uint_ge(gauss_data->cdf_128[i], gauss_data->cdf_128[i-1]);
    }
#if 32 == SC_LIMB_BITS
    ck_assert_uint_eq(gauss_data->cdf_128[gauss_data->cdf_size-1].w[3], 0xFFFFFFFF);
    ck_assert_uint_eq(gauss_data->cdf_128[gauss_data->cdf_size-1].w[2], 0xFFFFFFFF);
    ck_assert_uint_eq(gauss_data->cdf_128[gauss_data->cdf_size-1].w[1], 0xFFFFFFFF);
    ck_assert_uint_eq(gauss_data->cdf_128[gauss_data->cdf_size-1].w[0], 0xFFFFFFFF);
#else
    ck_assert_uint_eq(gauss_data->cdf_128[gauss_data->cdf_size-1].w[1], 0xFFFFFFFFFFFFFFFF);
    ck_assert_uint_eq(gauss_data->cdf_128[gauss_data->cdf_size-1].w[0], 0xFFFFFFFFFFFFFFFF);
#endif

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = gaussian_cdf_sample_128(gauss);
        ck_assert_int_ge(sample, -(1 << 12));
        ck_assert_int_le(sample, (1 << 12));
    }

    retcode = gaussian_cdf_destroy_128(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_shuffle_128)
{
    size_t i;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    utils_sampling_t *sampler = create_sampler(CDF_GAUSSIAN_SAMPLING, SAMPLING_128BIT, SHUFFLE_SAMPLES, 512,
        SAMPLING_DISABLE_BOOTSTRAP, prng_ctx, 10, 250);
    ck_assert_ptr_ne(sampler, NULL);

    SINT32 samples[512];
    for (i=0; i<512; i++) {
        samples[i] = 0x7FFFFFFF;
    }
    retcode = sampler->vector_32(sampler, samples, 512, 0);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    for (i=0; i<512; i++) {
        ck_assert_int_ne(samples[i], 0x7FFFFFFF);
    }

    retcode = destroy_sampler(&sampler);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(sampler, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif

#ifdef HAVE_64BIT
START_TEST(test_gaussian_create_64)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_64(prng_ctx, 12, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_cdf_destroy_64(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_destroy_bad_64)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    
    void *gauss = gaussian_cdf_create_64(prng_ctx, 12, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_cdf_destroy_64(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = gaussian_cdf_destroy_64(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_range_64)
{
    size_t i;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_64(prng_ctx, 12, 100.0f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    gauss_cdf_64_t *gauss_data = (gauss_cdf_64_t *) gauss;
    ck_assert_int_eq(gauss_data->cdf[0], 0);
    for (i=1; i<gauss_data->cdf_size-1; i++) {
        ck_assert_uint_ge(gauss_data->cdf[i], gauss_data->cdf[i-1]);
    }
    ck_assert_int_eq(gauss_data->cdf[gauss_data->cdf_size-1], 0xFFFFFFFFFFFFFFFF);

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = gaussian_cdf_sample_64(gauss);
        ck_assert_int_ge(sample, -(1 << 12));
        ck_assert_int_le(sample, (1 << 12));
    }

    retcode = gaussian_cdf_destroy_64(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_shuffle_64)
{
    size_t i;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    utils_sampling_t *sampler = create_sampler(CDF_GAUSSIAN_SAMPLING, SAMPLING_64BIT, SHUFFLE_SAMPLES, 512,
        SAMPLING_DISABLE_BOOTSTRAP, prng_ctx, 10, 250);
    ck_assert_ptr_ne(sampler, NULL);

    SINT32 samples[512];
    for (i=0; i<512; i++) {
        samples[i] = 0x7FFFFFFF;
    }
    retcode = sampler->vector_32(sampler, samples, 512, 0);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    for (i=0; i<512; i++) {
        ck_assert_int_ne(samples[i], 0x7FFFFFFF);
    }

    retcode = destroy_sampler(&sampler);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(sampler, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif

START_TEST(test_gaussian_create_32)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_32(prng_ctx, 12, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_cdf_destroy_32(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_destroy_bad_32)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_32(prng_ctx, 12, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_cdf_destroy_32(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = gaussian_cdf_destroy_32(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_range_32)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(6 * 100.0f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_32(prng_ctx, 6, 100.0f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    gauss_cdf_32_t *gauss_data = (gauss_cdf_32_t *) gauss;
    ck_assert_int_eq(gauss_data->cdf[0], 0);
    for (i=1; i<gauss_data->cdf_size-1; i++) {
        ck_assert_uint_ge(gauss_data->cdf[i], gauss_data->cdf[i-1]);
    }
    ck_assert_int_eq(gauss_data->cdf[gauss_data->cdf_size-1], 0xFFFFFFFF);

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = gaussian_cdf_sample_32(gauss);
        ck_assert_int_ge(sample, -max);
        ck_assert_int_le(sample, max);
    }

    retcode = gaussian_cdf_destroy_32(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gaussian_shuffle_32)
{
    size_t i;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    utils_sampling_t *sampler = create_sampler(CDF_GAUSSIAN_SAMPLING, SAMPLING_32BIT, SHUFFLE_SAMPLES, 512,
        SAMPLING_DISABLE_BOOTSTRAP, prng_ctx, 10, 250);
    ck_assert_ptr_ne(sampler, NULL);

    SINT32 samples[512];
    for (i=0; i<512; i++) {
        samples[i] = 0x7FFFFFFF;
    }
    retcode = sampler->vector_32(sampler, samples, 512, 0);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    for (i=0; i<512; i++) {
        ck_assert_int_ne(samples[i], 0x7FFFFFFF);
    }

    retcode = destroy_sampler(&sampler);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(sampler, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif

#ifdef HAVE_KNUTH_YAO_GAUSSIAN_SAMPLING
START_TEST(test_knuth_yao_create_32)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_32(prng_ctx, 6, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_destroy_bad_32)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_32(prng_ctx, 6, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_range_32)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(6 * 100.0f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_32(prng_ctx, 6, 100.0f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = gaussian_knuth_yao_sample(gauss);
        ck_assert_int_ge(sample, -max);
        ck_assert_int_le(sample, max);
    }

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

#ifdef HAVE_64BIT
START_TEST(test_knuth_yao_create_64)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_64(prng_ctx, 6, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_destroy_bad_64)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_64(prng_ctx, 6, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_range_64)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(6 * 100.0f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_64(prng_ctx, 6, 100.0f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = gaussian_knuth_yao_sample(gauss);
        ck_assert_int_ge(sample, -max);
        ck_assert_int_le(sample, max);
    }

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif

#ifdef HAVE_128BIT
START_TEST(test_knuth_yao_create_128)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_128(prng_ctx, 6, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_destroy_bad_128)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_128(prng_ctx, 6, 3.33, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_range_128)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(6 * 100.0f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_create_128(prng_ctx, 6, 100.0f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<(1 << 12); i++) {
        SINT32 sample = gaussian_knuth_yao_sample(gauss);
        ck_assert_int_ge(sample, -max);
        ck_assert_int_le(sample, max);
    }

    retcode = gaussian_knuth_yao_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif
#endif

#ifdef HAVE_KNUTH_YAO_FAST_GAUSSIAN_SAMPLING
START_TEST(test_knuth_yao_fast_create)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_fast_256_create(prng_ctx, 6, 4.5120f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_fast_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_fast_destroy_bad)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_fast_256_create(prng_ctx, 6, 4.5120f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = gaussian_knuth_yao_fast_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = gaussian_knuth_yao_fast_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_knuth_yao_fast_range)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(6 * 4.5120.0f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_knuth_yao_fast_256_create(prng_ctx, 6, 4.5120f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = gaussian_knuth_yao_fast_sample(gauss);
        ck_assert_int_ge(sample, -max);
        ck_assert_int_le(sample, max);
        //fprintf(stderr, "%d\n", sample);
    }

    retcode = gaussian_knuth_yao_fast_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif

#ifdef HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
START_TEST(test_ziggurat_create)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = ziggurat_create(prng_ctx, 6, 4.5120f, 1024, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = ziggurat_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_ziggurat_destroy_bad)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = ziggurat_create(prng_ctx, 6, 4.5120f, 1024, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = ziggurat_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = ziggurat_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_ziggurat_range)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(6 * 4.5120f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = ziggurat_create(prng_ctx, 6, 4.5120f, 1024, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = ziggurat_sample_64(gauss);
        ck_assert_int_ge(sample, -max);
        ck_assert_int_le(sample, max);
    }

    retcode = ziggurat_destroy(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif

#ifdef HAVE_BERNOULLI_GAUSSIAN_SAMPLING
START_TEST(test_bernoulli_create)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = bernoulli_create_64(prng_ctx, 6, 4.5120f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = bernoulli_destroy_64(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_bernoulli_destroy_bad)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = bernoulli_create_64(prng_ctx, 6, 4.5120f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = bernoulli_destroy_64(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = bernoulli_destroy_64(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_bernoulli_table)
{
    size_t i, j;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = bernoulli_create_64(prng_ctx, 8, 19.53f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    gauss_ber_t* gauss_ber = (gauss_ber_t*) gauss;
    ck_assert_uint_eq(gauss_ber->max_ber_entries, ceil(log2f(8.0 * 19.53f * 8.0 * 19.53f)));
    ck_assert_uint_eq(gauss_ber->max_ber_bytes, 8);
    ck_assert_uint_eq(gauss_ber->max_gauss_val, ceil(8.0 * 19.53f));
    ck_assert_uint_eq(gauss_ber->max_gauss_log, ceil(log2f(8.0 * 19.53f)));

    for (i=0; i<gauss_ber->max_ber_entries; i++) {
        fprintf(stderr, "%d ", (int)i);
        for (j=0; j<gauss_ber->max_ber_bytes; j++) {
            fprintf(stderr, "%d ", (int)gauss_ber->ber_table[i][j]);
        }
        fprintf(stderr, "\n");
    }

    retcode = bernoulli_destroy_64(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_bernoulli_range)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(6 * 4.5120.0f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = bernoulli_create_64(prng_ctx, 6, 4.5120f, 64, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<(1 << 16); i++) {
        SINT32 sample = bernoulli_sample_64(gauss);
        ck_assert_int_ge(sample, -max);
        ck_assert_int_le(sample, max);
    }

    retcode = bernoulli_destroy_64(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_bernoulli_shuffle_64)
{
    size_t i;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    utils_sampling_t *sampler = create_sampler(BERNOULLI_GAUSSIAN_SAMPLING, SAMPLING_64BIT, SHUFFLE_SAMPLES, 512,
        SAMPLING_DISABLE_BOOTSTRAP, prng_ctx, 10, 250);
    ck_assert_ptr_ne(sampler, NULL);

    SINT32 samples[512];
    for (i=0; i<512; i++) {
        samples[i] = 0x7FFFFFFF;
    }
    retcode = sampler->vector_32(prng_ctx, sampler, sampler->gauss, samples, 512);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    for (i=0; i<512; i++) {
        ck_assert_int_ne(samples[i], 0x7FFFFFFF);
    }

    retcode = destroy_sampler(&sampler);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(sampler, NULL);
    prng_destroy(prng_ctx);
}
END_TEST
#endif

START_TEST(test_mw_create)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    utils_sampling_t *gauss = create_sampler(CDF_GAUSSIAN_SAMPLING,
        SAMPLING_64BIT, NORMAL_SAMPLES, 64, SAMPLING_MW_BOOTSTRAP,
        prng_ctx, 13, 16.0f);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = destroy_sampler(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_mw_destroy_bad)
{
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    utils_sampling_t *gauss = create_sampler(CDF_GAUSSIAN_SAMPLING,
        SAMPLING_64BIT, NORMAL_SAMPLES, 64, SAMPLING_MW_BOOTSTRAP,
        prng_ctx, 13, 16.0f);
    ck_assert_ptr_ne(gauss, NULL);

    retcode = destroy_sampler(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = destroy_sampler(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_mw_range)
{
    size_t i;
    SINT32 retcode;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    FLOAT tail = 13.0f;
    FLOAT sigma = 1000.0f;

    utils_sampling_t *gauss = create_sampler(CDF_GAUSSIAN_SAMPLING,
        SAMPLING_64BIT, NORMAL_SAMPLES, 64, SAMPLING_MW_BOOTSTRAP,
        prng_ctx, tail, sigma);

    for (i=0; i<64; i++) {
        SINT32 sample = get_bootstrap_sample(gauss, sigma, 0.0f);
        ck_assert_int_ge(sample, -ceil(tail * sigma));
        ck_assert_int_le(sample, ceil(tail * sigma));
    }

    retcode = destroy_sampler(&gauss);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(gauss, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_mw_range_2)
{
    size_t i;
    SINT32 retcode;
    SINT32 max = 1 << sc_ceil_log2(13 * 1000.0f);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    DOUBLE sigma = 1000.0f;

    utils_sampling_t *sampling = create_sampler(CDF_GAUSSIAN_SAMPLING,
        SAMPLING_64BIT, NORMAL_SAMPLES, 64, SAMPLING_MW_BOOTSTRAP,
        prng_ctx, 13.0f, sigma);

    //UINT32 *temp = SC_MALLOC(sizeof(UINT32) * 65537);
    for (i=0; i<65536; i++) {
        SINT32 sample = get_bootstrap_sample(sampling, sigma, 0.0f);
        ck_assert_int_ge(sample, -ceil(13.0f * 1000.0f));
        ck_assert_int_le(sample, ceil(13.0f * 1000.0f));
        /*if (sample >= -32768 && sample <= 32768) {
            temp[sample+32768]++;
        }*/
    }
    /*for (i=0; i<65537; i++) {
        fprintf(stderr, "%d: %d\n", (SINT32)i - 32768, temp[i]);
    }*/
    //SC_FREE(temp, sizeof(UINT32) * 65537);

    retcode = destroy_sampler(&sampling);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(sampling, NULL);
    prng_destroy(prng_ctx);
}
END_TEST

Suite *gaussian_suite(void)
{
    Suite *s;
    TCase *tc_cdf, *tc_knuth_yao, *tc_knuth_yao_fast,
        *tc_ziggurat, *tc_bernoulli, *tc_mw;

    s = suite_create("gaussian");

    /* Test cases */
#ifdef HAVE_CDF_GAUSSIAN_SAMPLING
    tc_cdf = tcase_create("CDF");
#if !defined(DISABLE_HIGH_PREC_GAUSSIAN)
    tcase_add_test(tc_cdf, test_gaussian_create_128);
    tcase_add_test(tc_cdf, test_gaussian_destroy_bad_128);
    tcase_add_test(tc_cdf, test_gaussian_range_128);
    tcase_add_test(tc_cdf, test_gaussian_shuffle_128);
#endif
#ifdef HAVE_64BIT
    tcase_add_test(tc_cdf, test_gaussian_create_64);
    tcase_add_test(tc_cdf, test_gaussian_destroy_bad_64);
    tcase_add_test(tc_cdf, test_gaussian_range_64);
    tcase_add_test(tc_cdf, test_gaussian_shuffle_64);
#endif
    tcase_add_test(tc_cdf, test_gaussian_create_32);
    tcase_add_test(tc_cdf, test_gaussian_destroy_bad_32);
    tcase_add_test(tc_cdf, test_gaussian_range_32);
    tcase_add_test(tc_cdf, test_gaussian_shuffle_32);
    suite_add_tcase(s, tc_cdf);
#endif

#ifdef HAVE_KNUTH_YAO_GAUSSIAN_SAMPLING
    tc_knuth_yao = tcase_create("Knuth-Yao");
#ifdef HAVE_128BIT
    tcase_add_test(tc_knuth_yao, test_knuth_yao_create_128);
    tcase_add_test(tc_knuth_yao, test_knuth_yao_destroy_bad_128);
    tcase_add_test(tc_knuth_yao, test_knuth_yao_range_128);
#endif
#ifdef HAVE_64BIT
    tcase_add_test(tc_knuth_yao, test_knuth_yao_create_64);
    tcase_add_test(tc_knuth_yao, test_knuth_yao_destroy_bad_64);
    tcase_add_test(tc_knuth_yao, test_knuth_yao_range_64);
#endif
    tcase_add_test(tc_knuth_yao, test_knuth_yao_create_32);
    tcase_add_test(tc_knuth_yao, test_knuth_yao_destroy_bad_32);
    tcase_add_test(tc_knuth_yao, test_knuth_yao_range_32);
    suite_add_tcase(s, tc_knuth_yao);
#endif

#ifdef HAVE_KNUTH_YAO_FAST_GAUSSIAN_SAMPLING
    tc_knuth_yao_fast = tcase_create("Knuth-Yao Fast");
    tcase_add_test(tc_knuth_yao_fast, test_knuth_yao_fast_create);
    tcase_add_test(tc_knuth_yao_fast, test_knuth_yao_fast_destroy_bad);
    tcase_add_test(tc_knuth_yao_fast, test_knuth_yao_fast_range);
    suite_add_tcase(s, tc_knuth_yao_fast);
#endif

#ifdef HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
    tc_ziggurat = tcase_create("Ziggurat");
    tcase_add_test(tc_ziggurat, test_ziggurat_create);
    tcase_add_test(tc_ziggurat, test_ziggurat_destroy_bad);
    tcase_add_test(tc_ziggurat, test_ziggurat_range);
    suite_add_tcase(s, tc_ziggurat);
#endif

#ifdef HAVE_BERNOULLI_GAUSSIAN_SAMPLING
    tc_bernoulli = tcase_create("Bernoulli");
    tcase_add_test(tc_bernoulli, test_bernoulli_create);
    tcase_add_test(tc_bernoulli, test_bernoulli_destroy_bad);
    tcase_add_test(tc_bernoulli, test_bernoulli_table);
    tcase_add_test(tc_bernoulli, test_bernoulli_shuffle_64);
    tcase_add_test(tc_bernoulli, test_bernoulli_range);
    suite_add_tcase(s, tc_bernoulli);
#endif

    tc_mw = tcase_create("MW Bootstrap");
    tcase_add_test(tc_mw, test_mw_create);
    tcase_add_test(tc_mw, test_mw_destroy_bad);
    tcase_add_test(tc_mw, test_mw_range);
    tcase_add_test(tc_mw, test_mw_range_2);
    suite_add_tcase(s, tc_mw);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = gaussian_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


