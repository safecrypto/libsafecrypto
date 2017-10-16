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
#include "utils/arith/arith.h"
#include "utils/arith/ntt.c"
#ifdef HAVE_AVX2
#include "utils/arith/ntt_avx.h"
//#include "utils/arith/ntt_avx_rev.h"
#endif
#include "utils/arith/ntt_tables.c"
#include "utils/arith/ntt_barrett.h"
//#include "utils/arith/ntt_barrett_rev.c"
#include "utils/arith/ntt_reference.h"
//#include "utils/arith/ntt_reference_rev.h"
#include "utils/arith/roots_of_unity.c"
#include "utils/crypto/prng.c"
#ifndef DISABLE_IBE_DLP
#include "utils/arith/sc_poly_mpz.c"
#endif

START_TEST(test_ntt32_muln)
{
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.ntt32.q = 12289;
    ntt.u.ntt32.m = 2730;
    ntt.u.ntt32.k = 25;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    SINT32 x=1234, y=5678;
    SINT32 r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    r = ntt32_muln_barrett(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    r = ntt32_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 1922);
}
END_TEST

START_TEST(test_ntt32_muln_barrett)
{
    ntt_params_t barrett;
    barrett.n = 512;
    barrett.u.ntt32.q = 12289;
    barrett.u.ntt32.m = 87374;
    barrett.u.ntt32.k = 30;

    SINT32 x=1234, y=5678;
    SINT32 r = ntt32_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 1922);

    x=1, y=12289;
    r = ntt32_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 0);

    x=1, y=12290;
    r = ntt32_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 1);

    x=1, y=12289*12289-1;
    r = ntt32_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 12288);

    x=1, y=12289*12289;
    r = ntt32_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 0);
}
END_TEST

START_TEST(test_ntt32_muln_fp)
{
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.ntt32.q = 12289;
    ntt.u.ntt32.m = 87374;
    ntt.u.ntt32.k = 30;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    SINT32 x=1234, y=5678;
    SINT32 r = ntt32_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    x=1, y=12289;
    r = ntt32_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 0);

    x=1, y=12290;
    r = ntt32_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 1);

    x=1, y=12289*12289-1;
    r = ntt32_muln_fp(x, y, &ntt);
    fprintf(stderr, "r (fp) = %d\n", r);
    ck_assert_int_eq(r, 12288);

    x=1, y=12289*12289;
    r = ntt32_muln_fp(x, y, &ntt);
    fprintf(stderr, "r (fp) = %d\n", r);
    ck_assert_int_eq(r, 0);
}
END_TEST

START_TEST(test_ntt32_muln_negative)
{
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.ntt32.q = 12289;
    ntt.u.ntt32.m = 12;

    SINT32 x=-1234, y=5678;
    SINT32 r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -1922);

    x=-1234, y=-5678;
    r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    x=1, y=12289;
    r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 0);

    x=1, y=-12289;
    r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 0);

    x=1, y=-12290;
    r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -1);
}
END_TEST

START_TEST(test_ntt32_muln_mismatch)
{
    size_t i;
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.ntt32.q = 12289;
    ntt.u.ntt32.m = 87374;
    ntt.u.ntt32.k = 30;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    SINT32 x=-10635, y=1479;
    SINT32 r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -11534);
    r = ntt32_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, -11534);

    x=-126331, y=12229;
    r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -2453);
    r = ntt32_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, -2453);    

    x=-120825, y=7866;
    r = ntt32_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -2768);
    r = ntt32_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, -2768);

    for (i=0; i<16384; i++) {
        x = -64*i; y = 0x7FFFFFFF;
        SINT32 r1 = ntt32_muln_reference(x, y, &ntt);
        SINT32 r2 = ntt32_muln_fp(x, y, &ntt);
        ck_assert_int_eq(r1, r2);
    }
}
END_TEST

START_TEST(test_ntt_muln)
{
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.nttlimb.q = 12289;
    ntt.u.nttlimb.m = 2730;
    ntt.u.nttlimb.k = 25;
    ntt.q_dbl = ntt.u.nttlimb.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    sc_slimb_t x=1234, y=5678;
    sc_slimb_t r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    r = ntt_muln_barrett(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 1922);
}
END_TEST

START_TEST(test_ntt_muln_barrett)
{
    ntt_params_t barrett;
    barrett.n = 512;
    barrett.u.nttlimb.q = 12289;
    barrett.u.nttlimb.m = 87374;
    barrett.u.nttlimb.k = 30;

    sc_slimb_t x=1234, y=5678;
    sc_slimb_t r = ntt_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 1922);

    x=1, y=12289;
    r = ntt_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 0);

    x=1, y=12290;
    r = ntt_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 1);

    x=1, y=12289*12289-1;
    r = ntt_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 12288);

    x=1, y=12289*12289;
    r = ntt_muln_barrett(x, y, &barrett);
    ck_assert_int_eq(r, 0);
}
END_TEST

START_TEST(test_ntt_muln_fp)
{
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.nttlimb.q = 12289;
    ntt.u.nttlimb.m = 87374;
    ntt.u.nttlimb.k = 30;
    ntt.q_dbl = ntt.u.nttlimb.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    sc_slimb_t x=1234, y=5678;
    sc_slimb_t r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    x=1, y=12289;
    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 0);

    x=1, y=12290;
    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 1);

    x=1, y=12289*12289-1;
    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 12288);

    x=1, y=12289*12289;
    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, 0);
}
END_TEST

START_TEST(test_ntt_muln_negative)
{
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.nttlimb.q = 12289;
    ntt.u.nttlimb.m = 12;

    sc_slimb_t x=-1234, y=5678;
    sc_slimb_t r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -1922);

    x=-1234, y=-5678;
    r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 1922);

    x=1, y=12289;
    r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 0);

    x=1, y=-12289;
    r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, 0);

    x=1, y=-12290;
    r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -1);
}
END_TEST

START_TEST(test_ntt_muln_mismatch)
{
    size_t i;
    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.nttlimb.q = 12289;
    ntt.u.nttlimb.m = 87374;
    ntt.u.nttlimb.k = 30;
    ntt.q_dbl = ntt.u.nttlimb.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    sc_slimb_t x=-10635, y=1479;
    sc_slimb_t r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -11534);
    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, -11534);

    x=-126331, y=12229;
    r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -2453);
    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, -2453);    

    x=-120825, y=7866;
    r = ntt_muln_reference(x, y, &ntt);
    ck_assert_int_eq(r, -2768);
    r = ntt_muln_fp(x, y, &ntt);
    ck_assert_int_eq(r, -2768);

    for (i=0; i<16384; i++) {
        x = -64*i; y = 0x7FFFFFFF;
        sc_slimb_t r1 = ntt_muln_reference(x, y, &ntt);
        sc_slimb_t r2 = ntt_muln_fp(x, y, &ntt);
        ck_assert_int_eq(r1, r2);
    }
}
END_TEST

SINT32 small_rand_dist(prng_ctx_t *prng_ctx, sc_slimb_t *v, const UINT16 *c, size_t c_len, size_t n, UINT16 n_bits)
{
    size_t j;
    UINT32 sign_bit = 1 << n_bits;
    UINT32 mask     = sign_bit - 1;

    for (j=0; j<n; j++) {
        v[j] = 0;
    }

    for (j=0; j<c_len; j++) {
        size_t i = 0;
        while (i < c[j]) {
            UINT32 rand = prng_32(prng_ctx);
            size_t index = rand & mask;
            if (0 == v[index]) {
                v[index] = (rand & sign_bit)? j-c_len : c_len-j;
                i++;
            }
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 small_rand_dist_32(prng_ctx_t *prng_ctx, SINT32 *v, const UINT16 *c, size_t c_len, size_t n, UINT16 n_bits)
{
    size_t j;
    UINT32 sign_bit = 1 << n_bits;
    UINT32 mask     = sign_bit - 1;

    for (j=0; j<n; j++) {
        v[j] = 0;
    }

    for (j=0; j<c_len; j++) {
        size_t i = 0;
        while (i < c[j]) {
            UINT32 rand = prng_32(prng_ctx);
            size_t index = rand & mask;
            if (0 == v[index]) {
                v[index] = (rand & sign_bit)? j-c_len : c_len-j;
                i++;
            }
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 small_rand_dist_16(prng_ctx_t *prng_ctx, SINT16 *v, const UINT16 *c, size_t c_len, size_t n, UINT16 n_bits)
{
    size_t j;
    UINT32 sign_bit = 1 << n_bits;
    UINT32 mask     = sign_bit - 1;

    for (j=0; j<n; j++) {
        v[j] = 0;
    }
    
    for (j=0; j<c_len; j++) {
        size_t i = 0;
        while (i < c[j]) {
            UINT32 rand = prng_32(prng_ctx);
            size_t index = rand & mask;
            if (0 == v[index]) {
                v[index] = (rand & sign_bit)? j-c_len : c_len-j;
                i++;
            }
        }
    }

    return SC_FUNC_SUCCESS;
}

static const UINT16 coeff_len[] = {1, 1, 3, 5, 8, 12, 17, 24, 31, 38, 44, 48};

#ifdef NTT_NEEDS_8399873
START_TEST(test_ntt32_8399873_inv_512)
{
    size_t i, iter, n=512;
    UINT32 q = 8399873;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    SINT32 *s = g + 3 * n;
    const SINT32 *w = w8399873_n512;
    const SINT32 *r = r8399873_n512;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 10);
    
        // Attempt to invert g
        sc_ntt->mul_32_pointwise(s, &ntt, g, w);
        sc_ntt->fft_32_32(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            SINT32 x = sc_ntt->modn_32(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_32(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            SINT32 temp_a = s[i];
            SINT32 temp_b = u[i];
            SINT32 one    = (SINT32)(((SINT64)temp_a * (SINT64)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_32_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        sc_ntt->fft_32_32(s, &ntt, w);
        sc_ntt->mul_32_pointwise(s, &ntt, s, r);
        sc_ntt->flip_32(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_12289
START_TEST(test_ntt32_12289_inv_1024_fp)
{
    size_t i, iter, n=1024;
    UINT16 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    SINT32 *s = g + 3 * n;
    const SINT16 *w = w12289_n1024;
    const SINT16 *r = r12289_n1024;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 10);
    
        // Attempt to invert g
        sc_ntt->mul_32_pointwise_16(s, &ntt, g, w);
        sc_ntt->fft_32_16(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            SINT32 x = sc_ntt->modn_32(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_32(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            SINT32 temp_a = s[i];
            SINT32 temp_b = u[i];
            SINT32 one    = (SINT32)(((SINT64)temp_a * (SINT64)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_32_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        sc_ntt->fft_32_16(s, &ntt, w);
        sc_ntt->mul_32_pointwise_16(s, &ntt, s, r);
        sc_ntt->flip_32(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_12289
START_TEST(test_ntt32_12289_inv_1024_barrett)
{
    size_t i, iter, n=1024;
    UINT16 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    SINT32 *s = g + 3 * n;
    const SINT16 *w = w12289_n1024;
    const SINT16 *r = r12289_n1024;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 10);
    
        // Attempt to invert g
        sc_ntt->mul_32_pointwise_16(s, &ntt, g, w);
        sc_ntt->fft_32_16(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            SINT32 x = sc_ntt->modn_32(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_32(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            SINT32 temp_a = s[i];
            SINT32 temp_b = u[i];
            SINT32 one    = (SINT32)(((SINT64)temp_a * (SINT64)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_32_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        sc_ntt->fft_32_16(s, &ntt, w);
        sc_ntt->mul_32_pointwise_16(s, &ntt, s, r);
        sc_ntt->flip_32(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_12289
START_TEST(test_ntt32_12289_inv_512_barrett)
{
    size_t i, iter, n=512;
    UINT16 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    SINT32 *s = g + 3 * n;
    const SINT16 *w = w12289_n512;
    const SINT16 *r = r12289_n512;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 9);
    
        // Attempt to invert g
        sc_ntt->mul_32_pointwise_16(s, &ntt, g, w);
        sc_ntt->fft_32_16(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            SINT32 x = sc_ntt->modn_32(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_32(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            SINT32 temp_a = s[i];
            SINT32 temp_b = u[i];
            SINT32 one    = (SINT32)(((SINT64)temp_a * (SINT64)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_32_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        sc_ntt->fft_32_16(s, &ntt, w);
        sc_ntt->mul_32_pointwise_16(s, &ntt, s, r);
        sc_ntt->flip_32(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_7681
START_TEST(test_ntt32_7681_inv_256_barrett)
{
    size_t i, iter, n=256;
    UINT16 q = 7681;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    SINT32 *s = g + 3 * n;
    const SINT16 *w = w7681_n256;
    const SINT16 *r = r7681_n256;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 8);
    
        // Attempt to invert g
        sc_ntt->mul_32_pointwise_16(s, &ntt, g, w);
        sc_ntt->fft_32_16(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            SINT32 x = sc_ntt->modn_32(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_32(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            SINT32 temp_a = s[i];
            SINT32 temp_b = u[i];
            SINT32 one    = (SINT32)(((SINT64)temp_a * (SINT64)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_32_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        sc_ntt->fft_32_16(s, &ntt, w);
        sc_ntt->mul_32_pointwise_16(s, &ntt, s, r);
        sc_ntt->flip_32(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_12289
START_TEST(test_mixed_ntt32_12289)
{
    size_t i, n=512;
    UINT16 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    const SINT16 *w = w12289_n512;
    const SINT16 *r = r12289_n512;

    // Create a random polynomial g
    small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 9);

    // Forward NTT
    sc_ntt->mul_32_pointwise_16(u, &ntt, g, w);
    inverse_shuffle_32(u, n);
    sc_ntt->fft_32_16(u, &ntt, w);
    sc_ntt->normalize_32(u, n, &ntt);
    
    // Inverse NTT
    inverse_shuffle_32(u, n);
    sc_ntt->fft_32_16(u, &ntt, w);
    sc_ntt->mul_32_pointwise_16(u, &ntt, u, r);
    sc_ntt->flip_32(u, &ntt);
    
    for (i=0; i<n; i++) {
        u[i] = (u[i] > (q>>1))? u[i] - q : u[i];
        ck_assert_int_eq(g[i], u[i]);
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_7681
START_TEST(test_mixed_ntt32_7681)
{
    size_t i, n=256;
    UINT16 q = 7681;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    const SINT16 *w = w7681_n256;
    const SINT16 *r = r7681_n256;

    // Create a random polynomial g
    small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 8);

    // Forward NTT
    sc_ntt->mul_32_pointwise_16(u, &ntt, g, w);
    inverse_shuffle_32(u, n);
    sc_ntt->fft_32_16(u, &ntt, w);
    sc_ntt->normalize_32(u, n, &ntt);
    
    // Inverse NTT
    inverse_shuffle_32(u, n);
    sc_ntt->fft_32_16(u, &ntt, w);
    sc_ntt->mul_32_pointwise_16(u, &ntt, u, r);
    sc_ntt->flip_32(u, &ntt);
    
    for (i=0; i<n; i++) {
        u[i] = (u[i] > (q>>1))? u[i] - q : u[i];
        ck_assert_int_eq(g[i], u[i]);
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_7681
START_TEST(test_rev_ntt32_7681)
{
    size_t i, n=256;
    UINT16 q = 7681;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT_REV);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    const SINT16 *w_rev = rev_w7681_n256;
    const SINT16 *w_inv = inv_w7681_n256;
    const SINT16 *r_inv = inv_r7681_n256;

    // Create a random polynomial g
    small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 8);

    fprintf(stderr, "g = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", g[i]);
    }
    fprintf(stderr, "\n");

    // Forward NTT
    sc_ntt->fwd_ntt_32_16(u, &ntt, g, w_rev);
    fprintf(stderr, "NTT(g) = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", u[i]);
    }
    fprintf(stderr, "\n");
    
    // Inverse NTT
    sc_ntt->inv_ntt_32_16(u, &ntt, u, w_inv, r_inv);
    
    fprintf(stderr, "u = INTT(NTT(g)) = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", u[i]);
    }
    fprintf(stderr, "\n");
    for (i=0; i<n; i++) {
        u[i] = (u[i] > (q>>1))? u[i] - q : u[i];
        ck_assert_int_eq(g[i], u[i]);
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_12289
START_TEST(test_rev_ntt32_12289)
{
    size_t i, n=512;
    UINT16 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT_REV);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(4 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    const SINT16 *w_rev = rev_w12289_n512;
    const SINT16 *w_inv = inv_w12289_n512;
    const SINT16 *r_inv = inv_r12289_n512;

    // Create a random polynomial g
    small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 8);

    fprintf(stderr, "g = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", g[i]);
    }
    fprintf(stderr, "\n");

    // Forward NTT
    sc_ntt->fwd_ntt_32_16(u, &ntt, g, w_rev);
    fprintf(stderr, "NTT(g) = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", u[i]);
    }
    fprintf(stderr, "\n");
    
    // Inverse NTT
    sc_ntt->inv_ntt_32_16(u, &ntt, u, w_inv, r_inv);
    
    fprintf(stderr, "u = INTT(NTT(g)) = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", u[i]);
    }
    fprintf(stderr, "\n");
    for (i=0; i<n; i++) {
        u[i] = (u[i] > (q>>1))? u[i] - q : u[i];
        ck_assert_int_eq(g[i], u[i]);
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_12289
START_TEST(test_ntt32_fwd_inv_512)
{
    size_t i, iter, n=512;
    UINT16 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(2 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    const SINT16 *w = w12289_n512;
    const SINT16 *r = r12289_n512;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 9);
        sc_ntt->normalize_32(g, n, &ntt);

        /*fprintf(stderr, "g:\n");
        for (i=0; i<n; i++) {
            fprintf(stderr, "%6d ", g[i]);
            if ((i&0x7) == 0x7) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");*/

        // Forward NTT
        sc_ntt->mul_32_pointwise_16(u, &ntt, g, w);
        inverse_shuffle_32(u, n);
        sc_ntt->fft_32_16(u, &ntt, w);
        sc_ntt->normalize_32(u, n, &ntt);

        /*fprintf(stderr, "ntt(g):\n");
        for (i=0; i<n; i++) {
            fprintf(stderr, "%6d ", u[i]);
            if ((i&0x7) == 0x7) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");*/

        // Inverse NTT
        inverse_shuffle_32(u, n);
        sc_ntt->fft_32_16(u, &ntt, w);
        sc_ntt->mul_32_pointwise_16(u, &ntt, u, r);
        sc_ntt->flip_32(u, &ntt);
        sc_ntt->normalize_32(u, n, &ntt);
    
        // Ensure that the NTT methods match
        /*fprintf(stderr, "inv_ntt(ntt(g)):\n");
        for (i=0; i<n; i++) {
            fprintf(stderr, "%6d ", u[i]);
            if ((i&0x7) == 0x7) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");*/

        for (i=0; i<n; i++) {
            ck_assert_int_eq(u[i], g[i]);
        }
        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 2 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_12289
START_TEST(test_ntt32_fwd_inv_1024)
{
    size_t i, iter, n=1024;
    UINT16 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_BARRETT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / q;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SINT32 *g = SC_MALLOC(2 * n * sizeof(SINT32));
    SINT32 *u = g + n;
    const SINT16 *w = w12289_n1024;
    const SINT16 *r = r12289_n1024;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist_32(prng_ctx, g, coeff_len, 12, n, 10);
        sc_ntt->normalize_32(g, n, &ntt);

        /*fprintf(stderr, "g:\n");
        for (i=0; i<n; i++) {
            fprintf(stderr, "%6d ", g[i]);
            if ((i&0x7) == 0x7) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");*/

        // Forward NTT
        sc_ntt->mul_32_pointwise_16(u, &ntt, g, w);
        inverse_shuffle_32(u, n);
        sc_ntt->fft_32_16(u, &ntt, w);
        sc_ntt->normalize_32(u, n, &ntt);

        /*fprintf(stderr, "ntt(g):\n");
        for (i=0; i<n; i++) {
            fprintf(stderr, "%6d ", u[i]);
            if ((i&0x7) == 0x7) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");*/

        // Inverse NTT
        inverse_shuffle_32(u, n);
        sc_ntt->fft_32_16(u, &ntt, w);
        sc_ntt->mul_32_pointwise_16(u, &ntt, u, r);
        sc_ntt->flip_32(u, &ntt);
        sc_ntt->normalize_32(u, n, &ntt);
    
        // Ensure that the NTT methods match
        /*fprintf(stderr, "inv_ntt(ntt(g)):\n");
        for (i=0; i<n; i++) {
            fprintf(stderr, "%6d ", u[i]);
            if ((i&0x7) == 0x7) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");*/

        for (i=0; i<n; i++) {
            ck_assert_int_eq(u[i], g[i]);
        }
        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 2 * n * sizeof(SINT32));
}
END_TEST
#endif

#ifdef NTT_NEEDS_8399873
START_TEST(test_ntt_8399873_inv_512)
{
    size_t i, iter, n=512;
    UINT32 q = 8399873;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.nttlimb.q = q;
    ntt.u.nttlimb.k = 30;
    ntt.u.nttlimb.m = (1 << ntt.u.nttlimb.k) / q;
    ntt.q_dbl = ntt.u.nttlimb.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    sc_slimb_t *g = SC_MALLOC(4 * n * sizeof(sc_slimb_t));
    sc_slimb_t *u = g + n;
    sc_slimb_t *s = g + 3 * n;
    const SINT32 *w = w8399873_n512;
    const SINT32 *r = r8399873_n512;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist(prng_ctx, g, coeff_len, 12, n, 10);
    
        // Attempt to invert g
        sc_ntt->mul_limb_pointwise_32(s, &ntt, g, w);
        sc_ntt->fft_limb_32(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            sc_slimb_t x = sc_ntt->modn_limb(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_limb(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            sc_slimb_t temp_a = s[i];
            sc_slimb_t temp_b = u[i];
            sc_slimb_t one    = (sc_slimb_t)(((sc_slimb_big_t)temp_a * (sc_slimb_big_t)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_limb_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        inverse_shuffle(s, n);
        sc_ntt->fft_limb_32(s, &ntt, w);
        sc_ntt->mul_limb_pointwise_32(s, &ntt, s, r);
        sc_ntt->flip_limb(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(sc_slimb_t));
}
END_TEST
#endif

START_TEST(test_primitive_root)
{
    sc_ulimb_t prim;
    sc_mod_t mod;
    limb_mod_init(&mod, 1025);
    prim = find_primitive_root(&mod);
    ck_assert_uint_eq(0, prim);
    limb_mod_init(&mod, 7681);
    prim = find_primitive_root(&mod);
    ck_assert_uint_eq(17, prim);
    limb_mod_init(&mod, 12289);
    prim = find_primitive_root(&mod);
    ck_assert_uint_eq(11, prim);
    limb_mod_init(&mod, 15873);
    prim = find_primitive_root(&mod);
    ck_assert_uint_eq(0, prim);
    limb_mod_init(&mod, 32257);
    prim = find_primitive_root(&mod);
    ck_assert_uint_eq(15, prim);
}
END_TEST

START_TEST(test_roots_of_unity)
{
    sc_slimb_t *w, *r;
    size_t i, iter, n=512;
    UINT32 q = 8399873;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.nttlimb.q = q;
    ntt.u.nttlimb.k = 30;
    ntt.u.nttlimb.m = (1 << ntt.u.nttlimb.k) / q;
    ntt.q_dbl = ntt.u.nttlimb.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    w = SC_MALLOC(sizeof(sc_slimb_t) * n);
    r = SC_MALLOC(sizeof(sc_slimb_t) * n);
    roots_of_unity_slimb(w, r, n, q, 0);
    /*fprintf(stderr, "w = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%lu ", w[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "r = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%lu ", r[i]);
    }
    fprintf(stderr, "\n");*/

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    sc_slimb_t *g = SC_MALLOC(4 * n * sizeof(sc_slimb_t));
    sc_slimb_t *u = g + n;
    sc_slimb_t *s = g + 3 * n;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist(prng_ctx, g, coeff_len, 12, n, 10);
    
        // Attempt to invert g
        sc_ntt->mul_limb_pointwise(s, &ntt, g, w);
        sc_ntt->fft_limb(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            sc_slimb_t x = sc_ntt->modn_limb(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_limb(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            sc_slimb_t temp_a = s[i];
            sc_slimb_t temp_b = u[i];
            sc_slimb_t one    = (sc_slimb_t)(((sc_slimb_big_t)temp_a * (sc_slimb_big_t)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_limb_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        inverse_shuffle(s, n);
        sc_ntt->fft_limb(s, &ntt, w);
        sc_ntt->mul_limb_pointwise(s, &ntt, s, r);
        sc_ntt->flip_limb(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(sc_slimb_t));
    SC_FREE(w, sizeof(sc_ulimb_t) * n);
    SC_FREE(r, sizeof(sc_ulimb_t) * n);
}
END_TEST

START_TEST(test_roots_of_unity_2)
{
#if 1
    SINT32 *w, *r;
#else
    const SINT32 *w = w8399873_n512;
    const SINT32 *r = r8399873_n512;
#endif
    size_t i, iter, n=512;
    UINT32 q = 8399873;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.nttlimb.q = q;
    ntt.u.nttlimb.k = 30;
    ntt.u.nttlimb.m = (1 << ntt.u.nttlimb.k) / q;
    ntt.q_dbl = ntt.u.nttlimb.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    w = SC_MALLOC(sizeof(SINT32) * n);
    r = SC_MALLOC(sizeof(SINT32) * n);
    roots_of_unity_s32(w, r, n, q, 0);

    /*fprintf(stderr, "w = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", w[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "r = ");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%d ", r[i]);
    }
    fprintf(stderr, "\n");*/

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    sc_slimb_t *g = SC_MALLOC(4 * n * sizeof(sc_slimb_t));
    sc_slimb_t *u = g + n;
    sc_slimb_t *s = g + 3 * n;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist(prng_ctx, g, coeff_len, 12, n, 10);
    
        // Attempt to invert g
        sc_ntt->mul_limb_pointwise_32(s, &ntt, g, w);
        sc_ntt->fft_limb_32(s, &ntt, w);
    
        for (i=0; i<n; i++) {
            sc_slimb_t x = sc_ntt->modn_limb(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_limb(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            sc_slimb_t temp_a = s[i];
            sc_slimb_t temp_b = u[i];
            sc_slimb_t one    = (sc_slimb_t)(((sc_slimb_big_t)temp_a * (sc_slimb_big_t)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_limb_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        sc_ntt->fft_limb_32(s, &ntt, w);
        sc_ntt->mul_limb_pointwise_32(s, &ntt, s, r);
        sc_ntt->flip_limb(s, &ntt);

        // Check that the result is 1
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }
        ck_assert_int_eq(s[0], 1);

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(sc_slimb_t));
    SC_FREE(w, sizeof(SINT32) * n);
    SC_FREE(r, sizeof(SINT32) * n);
}
END_TEST

START_TEST(test_roots_of_unity_3)
{
    SINT16 *w, *r;
    size_t i, iter, n=4096;
    UINT32 q = 12289;
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.nttlimb.q = q;
    ntt.u.nttlimb.k = 30;
    ntt.u.nttlimb.m = (1 << ntt.u.nttlimb.k) / q;
    ntt.q_dbl = ntt.u.nttlimb.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    w = SC_MALLOC(sizeof(SINT16) * n);
    r = SC_MALLOC(sizeof(SINT16) * n);
    roots_of_unity_s16(w, r, n, q, 0);

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    sc_slimb_t *g = SC_MALLOC(4 * n * sizeof(sc_slimb_t));
    sc_slimb_t *u = g + n;
    sc_slimb_t *s = g + 3 * n;

    for (iter=0; iter<999; iter++) {

        // Create a random polynomial g
        small_rand_dist(prng_ctx, g, coeff_len, 12, n, 10);

        // Attempt to invert g
        sc_ntt->mul_limb_pointwise_16(s, &ntt, g, w);
        sc_ntt->fft_limb_16(s, &ntt, w);

        for (i=0; i<n; i++) {
            sc_slimb_t x = sc_ntt->modn_limb(s[i], &ntt);
            if (x == 0) {
                break;
            }
            x = sc_ntt->pwr_limb(x, q - 2, &ntt);
            u[i] = x;
        }
        if (i < n) {
            continue;
        }

        // Ensure that each element contains the multiplicative inverse by
        // multiplying with the original value and checking that the result is 1
        for (i=0; i<n; i++) {
            sc_slimb_t temp_a = s[i];
            sc_slimb_t temp_b = u[i];
            sc_slimb_t one    = (sc_slimb_t)(((sc_slimb_big_t)temp_a * (sc_slimb_big_t)temp_b) % q);
            if (one < 0) one += q;
            ck_assert_int_eq(one, 1);
        }

        // Calculate the product of g and 1/g
        sc_ntt->mul_limb_pointwise(s, &ntt, s, u);

        // Perform an inverse NTT
        sc_ntt->fft_limb_16(s, &ntt, w);
        sc_ntt->mul_limb_pointwise_16(s, &ntt, s, r);
        sc_ntt->flip_limb(s, &ntt);

        // Check that the result is 1
        ck_assert_int_eq(s[0], 1);
        for (i=1; i<n; i++) {
            ck_assert_int_eq(s[i], 0);
        }

        break;
    }

    prng_destroy(prng_ctx);
    SC_FREE(g, 4 * n * sizeof(sc_slimb_t));
    SC_FREE(w, sizeof(SINT16) * n);
    SC_FREE(r, sizeof(SINT16) * n);
}
END_TEST

#ifndef DISABLE_IBE_DLP
START_TEST(test_ibe)
{
    SINT32 g[512] = {-94, 115, -19, 176, 12, -129, -16, 97, 82, 107, 87, 53, -123, 49, 146, -12, -109, -147, -170, 4, -134, -113, -121, -64, -148, -129, 123, 1, 107, 78, -128, -107, -60, -170, -79, -82, -81, 123, 58, 44, -3, -26, -197, 104, -121, -1, -62, -71, -22, 178, -133, -7, 41, -42, -103, -46, 33, -133, -46, -19, 273, -41, 48, 65, -42, -61, 41, -66, 58, 98, 199, 30, 177, 32, 31, 98, -133, 124, 143, 36, 98, -226, -98, -254, -116, -37, 64, 133, 111, -36, -22, 63, 71, 66, -29, 154, -194, 114, -106, -61, -69, -140, -74, 20, -35, 144, -24, 22, -23, 20, -134, -104, -62, -22, 87, 120, -119, 164, -140, 298, -60, 182, 121, -12, 18, -203, -27, 31, -64, -197, -263, -112, 38, 131, 50, -287, -17, 10, 9, -20, -183, 5, 153, 150, 11, -133, -111, 239, 23, 86, 245, -151, 317, 53, -100, -156, 14, 31, 72, 71, 121, -98, 134, -196, -70, 105, -72, -65, 250, 22, 7, -192, -95, 146, -64, -79, 13, -23, 41, -78, -226, 222, 115, -3, 7, 8, -57, -52, -50, 29, -105, 7, -259, 177, -87, -9, 107, 58, 77, -35, -170, -125, 276, -7, -40, -52, -71, -186, -38, 0, -56, 65, 147, -236, -207, 149, 51, 20, -137, -48, -128, -78, 145, 112, -118, 9, 150, -92, -182, -30, -26, 59, 132, 10, 125, 125, 171, 55, 34, 120, 32, -81, -118, -10, -27, 255, 187, -43, -24, 161, -73, -105, 13, 44, 153, 5, 22, 151, 94, -42, 21, 177, 52, 171, 35, 104, -141, -20, 173, 17, -6, 105, -39, -3, 80, -147, -6, 77, -101, 60, -78, -77, -149, 29, 343, 44, 82, -91, 58, -12, 189, -49, -112, 115, -73, 105, -45, -30, -106, -62, 163, -99, -184, -116, 183, 37, -59, 111, 130, 105, 14, -21, -18, 24, -31, 44, -61, 156, -22, 136, 4, -21, 141, 25, -91, 42, 64, -132, -136, -35, -67, 84, -248, 108, -27, -35, -63, 261, -11, 16, 71, -14, 130, -111, -3, -73, 50, -7, 76, 10, -3, 23, 162, -154, 99, 76, -84, -12, 130, -71, -62, 117, -71, 261, -59, 49, 25, -137, 29, -74, -66, 21, 67, -107, 25, 28, -5, 59, -54, 14, -129, 2, 83, 74, 30, 23, -75, 10, 124, -135, 47, 147, 147, 123, -90, -48, 161, 303, 18, 64, -120, -48, -110, 13, -79, -41, -76, 30, 28, -159, -45, 52, 158, -294, -32, -118, 29, -14, -46, -60, -24, -128, -59, -105, -69, -32, -63, 33, -162, 73, 58, -137, -24, 247, -32, -33, -28, 92, 69, 49, 55, -26, -64, 1, -12, -97, -83, -76, 120, -48, -224, 48, -50, -2, -98, -23, -76, 24, 70, 31, 422, -179, 77, -34, 74, -123, 14, 8, 196, -92, -67, -18, -132, -53, 164, -44, -77, 52, 59, 12, 135, 61, -63, 96, -102, 11, -15, 54, 23, -72, 45, -28, 55, 5, 70, 6, -95, -203, 79, -53, -12, -58, 56, 133, -50, -78, 76, 97, -220, -118, 63, 268};
    SINT32 f[512] = {-197, 131, -48, -68, 60, 138, -155, -61, 144, 75, -81, 61, 107, 103, 59, -45, 6, -53, -3, 111, -143, -191, -19, 28, -172, -189, -64, 28, 200, 50, 92, -148, 8, -185, 78, -32, -105, 59, 66, -16, -55, 10, 0, 206, 44, 67, -168, -113, 54, -18, 166, 86, -43, -105, -15, -99, -66, 17, -132, -33, 68, 13, -95, 45, 303, -168, -187, -130, 22, 74, -27, 81, -48, -97, -91, -130, -122, 91, -76, 91, -40, -186, -34, 130, 120, -2, 39, 16, -192, -118, -46, 35, -70, -125, -64, 41, -32, -8, -5, 266, 137, 62, -200, -79, -93, 81, 4, 32, 99, 122, -19, -76, -138, -21, 19, 43, 45, -102, 154, -106, 166, -141, -37, -249, -173, -199, -21, 58, 49, -64, -112, 2, -125, -93, -31, 170, 44, 85, -32, 81, -91, -76, -8, -2, 25, -166, 0, -45, 1, -111, 116, 111, 29, -29, 115, 23, -20, 174, 29, 27, 4, 15, 243, 64, 59, 139, -62, 128, 9, -83, 28, 180, 59, -182, 110, 180, 122, 70, -120, -19, -136, 92, 9, -28, 140, -67, 26, -28, -41, -56, -28, -17, -35, 54, 156, -52, -46, 33, -35, 193, 80, -196, 130, 56, 279, 115, 1, 87, -37, -76, -126, -57, 7, -69, -8, 33, -75, 6, 50, 143, -102, 80, -13, 64, 42, -163, 53, 54, 55, 129, -62, -95, -65, 86, -52, 28, -108, 70, -254, 125, -63, -106, 19, 147, 84, 20, -29, -7, 72, 43, -44, -156, -65, -47, 152, 167, -74, -116, 166, -49, -66, 25, 25, 6, 4, -21, -108, 35, -68, -62, -140, -175, -23, -93, 59, -213, 59, 129, -74, -22, -101, 82, -193, 29, -5, -38, -39, -17, 254, 23, -16, -139, 54, 23, -59, -136, 59, -51, 85, -190, 25, -2, 1, 18, 20, -23, -28, 32, 96, 165, 19, 73, -58, 107, -225, 131, 12, 34, 1, 103, 97, -120, 221, -25, -65, 135, -206, -27, -92, 18, 77, -84, 12, 183, 7, 66, -12, -78, -144, -14, 59, 120, 27, -171, -95, 101, -26, -32, -125, 112, -52, -98, 138, -50, -22, -16, -251, 129, 97, 212, -112, 3, -77, 18, 69, 58, 8, 58, 13, 68, -122, 19, -159, -179, -36, -144, 124, -23, 91, -54, -120, -88, 75, -155, -3, 1, -11, 92, 188, 93, -138, -109, 41, -66, -2, 0, -107, -176, -102, 136, -111, 106, 162, -3, 35, 63, 37, 21, 146, -70, 138, -196, -172, -154, -113, -29, -133, 41, 91, -29, 30, -30, -37, -40, 8, 120, -56, -98, 109, -147, -49, 178, -4, 68, 225, -116, 121, -120, 2, 26, 24, -171, -20, 26, -1, 42, -102, -45, 120, 59, 85, 59, -10, 57, 77, -27, 45, 214, 239, 56, 179, 60, 23, 15, -31, 22, -179, 108, -8, 131, 92, 42, -57, 119, -105, 206, 87, -99, 18, -42, -75, 99, 47, -5, 53, 51, -83, -155, 14, -26, 32, 8, -54, 42, 53, 91, -139, -117, -109, -163, -64, 25, 66, -139, 47, 68, 40, 180, -169, -43, -101, 18};
    SINT32 c[512] = {5671740, 1531577, 6138309, 8054866, 3476695, 7751463, 7125644, 1018501, 3598617, 3660197, 8257295, 5442692, 7671413, 4639820, 5098153, 7583479, 2985877, 7476517, 736063, 8036797, 4762528, 7711800, 3058935, 3788986, 4279142, 3184562, 133833, 7552223, 7700852, 2384889, 5441262, 8148365, 4464108, 51492, 6986243, 8189930, 4802428, 6695027, 2928485, 5190212, 7762326, 3333442, 6300291, 5771762, 5253215, 1907495, 4708752, 5232454, 6428433, 187899, 4393441, 4549771, 8359334, 3867245, 364795, 629560, 158145, 3080811, 2140093, 5104597, 242767, 5532503, 6846443, 1383972, 1566821, 1418858, 4724772, 5369065, 6104916, 5247399, 3125201, 7006946, 2445417, 3330751, 1554360, 4905543, 5733829, 3615825, 7897477, 204023, 4071597, 6643627, 3479707, 7564407, 4425372, 6721634, 4525804, 520630, 4185346, 8358945, 5951944, 4471278, 4473069, 7698351, 2495580, 4741340, 7696706, 1599949, 1898892, 217814, 3624811, 2388208, 2411720, 1676341, 3394059, 1308397, 8159097, 7006061, 2054493, 5493079, 6045871, 6538347, 7844965, 7177277, 1827818, 1563559, 1486357, 7448228, 3543575, 2666213, 5414080, 946795, 4859310, 6923901, 3914167, 4466664, 3924855, 6720239, 142322, 8390485, 4722694, 4168677, 7980619, 2469393, 1324133, 7462874, 6335089, 5627034, 5087264, 3639694, 7924121, 4912640, 4061983, 7207859, 801298, 2467731, 6302532, 8107067, 7246477, 6853495, 7544239, 5046700, 2446876, 206115, 5027020, 1799878, 5443591, 3313899, 4701291, 5674364, 167749, 8001890, 3812581, 3913705, 823610, 431464, 198733, 7355131, 7547647, 6758399, 6118644, 3176827, 1583870, 964716, 8021180, 5265980, 4114584, 2504691, 5669104, 934394, 6994712, 4768155, 5387982, 5307067, 5013872, 6999276, 779487, 7078716, 5663161, 4174897, 2855185, 2526287, 7842278, 2800617, 5888186, 850157, 4189731, 4025214, 4385343, 3209383, 3686940, 1985821, 58642, 2822325, 3464099, 3058284, 8241143, 6059436, 6714429, 2721295, 6532112, 652990, 7177087, 5206569, 8080433, 175109, 3599300, 3399669, 7705288, 5732858, 8338764, 7819589, 3647396, 4754649, 89437, 6724852, 4586618, 1523148, 5057909, 7146582, 5686986, 2712423, 5577599, 4398149, 6477088, 7248413, 861738, 3748888, 3147207, 7965751, 952642, 770215, 6310839, 5931589, 1482513, 142750, 6183848, 6594261, 7926886, 4665272, 3572383, 1488752, 2138495, 7870642, 2011307, 3845881, 2617180, 4270752, 7460678, 6851027, 2749882, 4136422, 7668612, 2082830, 8269906, 6507776, 1635509, 7450444, 5915286, 5358636, 526221, 7317431, 3860082, 7227104, 3508604, 2397485, 2252429, 4488700, 8269414, 7160252, 4660207, 5269851, 6452758, 7165744, 7160331, 4152354, 89507, 7016804, 2630754, 5098960, 6525097, 7041895, 6288703, 1364707, 6123274, 1333081, 1966181, 3700424, 946467, 1807562, 3242909, 2477640, 3066288, 7088664, 3986476, 1533440, 6698564, 3467342, 4103510, 7899970, 7550823, 4951015, 5407252, 3159235, 7936932, 1142368, 6645978, 580847, 4155104, 6696907, 3037587, 2392459, 2198271, 721239, 4286285, 2162817, 3215679, 7611737, 5815053, 1299215, 6481005, 3244826, 6126876, 2844106, 6453500, 7900519, 416830, 4258329, 7227683, 8109285, 2861825, 6757960, 4150904, 6979817, 2040702, 3728118, 6342682, 6828961, 6524241, 4255281, 5554424, 8349707, 5571835, 2228271, 3179468, 7585065, 5104621, 1316182, 2072599, 3372785, 3911021, 3372112, 2846791, 3579889, 7272571, 3871010, 6710639, 5100638, 7071839, 2158068, 7894257, 3589395, 6343860, 7831130, 4062841, 6413393, 4804477, 826671, 7885828, 4966900, 6481330, 1164188, 2772914, 670883, 4783077, 2842506, 6069456, 6830658, 60078, 4139100, 3953495, 451364, 4862717, 7908722, 1977703, 1728447, 1326349, 7001372, 5171451, 7715568, 5068852, 8225927, 6894618, 6402376, 4705, 3106213, 6542046, 3253509, 7016319, 5322866, 5624946, 399070, 5444059, 2698866, 4499766, 360306, 5564870, 1311051, 1066107, 6911175, 3283233, 3449157, 130745, 348899, 8064864, 5954199, 1901473, 7350095, 3569578, 232980, 757245, 5267219, 3064212, 6440716, 835944, 3849976, 8043955, 4070611, 7113354, 1923204, 5588453, 753742, 8314705, 3449164, 7890716, 2942571, 7550036, 1055744, 907828, 1984910, 6303566, 5249341, 477036, 5124120, 4604454, 2782587, 4161958, 6754536, 4345042, 5351081, 1763860, 822251, 6663601, 6365566, 4192915, 6279380, 3705120, 3168526, 7075468, 8043503, 2249143, 851388, 6390557, 1811822, 7943992, 2717496, 3941012, 4868376, 15946, 4625360, 1441347, 5924645, 474212, 2168720, 1378102, 1324726, 6177872, 7731717, 7029443, 2708846, 1209434, 6546257, 464591, 1676384, 3559248, 1906837, 1536746, 860528, 8106137, 6245775, 7391684, 5222301, 527303, 5497579, 3125587, 2952999, 840854, 666280, 2501033, 4972033, 4009100, 1732949};
    SINT32 s1[512] = {2580, 5551, -5460, 1736, -3655, 15166, 9924, 14035, 7350, 12014, -8221, 894, 2389, 5667, -2549, 4261, -1182, 4122, -7697, 5417, 11213, -7308, 6432, -3923, 3772, -1528, -1505, 7492, 5407, 1602, 9099, 2331, -8305, 14967, 2338, 2377, -3757, 2355, 2810, 2596, 240, 2678, 4553, -3584, 13071, 7690, 8271, 8360, 1639, -2602, 10094, -129, 5003, -2337, 9218, 502, -5738, 4729, -14204, 6391, 4044, 140, 8330, -4551, 15331, 7264, -819, 6600, 8759, 8452, 2462, -17611, -5315, 10999, -9420, -7465, 7996, 8762, 7512, 9039, -34, -5023, -1212, 6008, 13721, 9447, 723, 1241, -3337, 7123, -6091, -3895, -3447, 11349, 6790, 2332, 1057, -5441, 4594, 10408, -1911, -2017, 6652, -577, 407, -2685, 1426, -3633, -1023, 4287, 13, 2963, -3055, -3478, 3462, 866, -1989, 3844, 11693, 6941, -10230, -2175, -146, 8596, 2237, 248, 4191, -8566, 940, 554, -8638, 11063, -10873, -4567, 959, -3336, 6010, -7197, 6138, 4824, 3752, 4505, 10472, -9839, -6417, -12047, 6495, -3986, -261, 1215, -7312, -3339, 4924, -439, -11657, 5238, -13636, -2793, 4730, 10351, -7795, -7524, 6217, -3171, 1278, -2460, 444, 10900, -2689, -2037, -317, -8332, 283, -7708, -6680, -5392, -10290, -8249, 8773, -7477, 6209, -9653, -4929, 1490, 2742, -3388, -5964, -1963, -3872, -2887, -813, 2897, -6670, -2672, 14031, -1982, -6912, 8836, 3362, -8544, -1885, -1513, -1689, -6337, 11076, -12738, -4798, 7478, -2911, -2699, 10829, 1869, 6996, 307, -12906, 2344, 3746, 637, -4846, -837, 512, -9291, 6523, -5706, -3878, 9012, 1539, -4987, 9315, 7610, 2003, -9010, 1201, 3977, -5815, 1252, 238, 3122, 8338, 1159, 11434, -2968, 5274, -3384, 2011, 7415, -10424, 9681, 7084, 4185, -8342, -12602, 5161, 3240, -1627, 2139, -684, -5477, -354, 3203, 8976, -5695, 10065, 5104, 4430, 2381, -5895, -4496, 817, 6912, 6902, 7404, 4152, 2259, -5718, 4444, 599, -9685, -4669, -1225, -12540, -773, -8683, 12469, 54, 3077, -404, -3018, 3442, 1753, 4253, -4967, 4745, -9705, 3482, 617, -13894, -3360, -843, 23, -902, -2433, 2734, 13441, -6819, 3332, 5811, 1145, -5531, -9922, 7928, -2601, -5139, 5640, 10608, 10725, -4053, 1597, -2423, 10894, -15750, 16109, -9148, 7172, -12061, -6322, -6726, 16318, -16214, -4773, -7174, 4820, -3535, -7734, 4976, 11389, 6959, -2789, 6421, -1037, 7317, 5325, -4864, 5142, -6444, 771, -7207, -9185, -1084, -5314, -54, 138, 11904, -8323, -6069, -8761, 6105, 10396, 3750, -7807, -1361, 5220, -3578, 1645, -10112, -4475, 5843, -12346, -11587, -6548, -9103, -8782, 1218, -3072, 3443, -1409, 8287, -20470, 4492, -13034, -70, -4537, -4590, -4606, -9721, -9318, 8888, 6356, -9150, -2581, -1558, -1376, 6840, 3895, -8426, -4404, -6543, -11967, 3490, 858, -6816, 5609, -10986, 3477, -3513, -5860, 5655, -13846, 302, -2119, -4975, 2987, -599, 590, 2202, 3987, 4795, -6097, -4855, -4890, -14251, 401, -6612, 1848, -7536, -13538, -8039, -1660, 18990, -3126, 5904, 3321, -10172, -8024, -3277, -25, 1204, -3453, 1686, -8663, -9368, -11283, -14912, 2645, -5162, 11646, 10045, -1452, -4428, -2154, -13421, -1187, -1039, -7684, -5432, -6257, -5497, 7853, 1572, 2591, -4095, -1811, -12209, -5105, 2437, 10950, 5046, 1261, -338, -307, -4193, -5375, -9971, -2256, 9966, -10568, 4193, -8333, 3394, 2292, 230, -9959, 4729, -1647, 6446, -2140, 1042, 1149, 2025, -3673, 8861, -6791, -4098, -11634, 8519, 2217, -14344, -1106, 11801, 3783, 2116, 6265, 363, 7923, -3825, -929, 146, -7002, -10732, 4181, 1300, -379};
    SINT32 s2[512] = {4780, -9712, -8, 7999, -1416, -3934, 7024, -2409, -5614, 5914, -7284, -11821, 2572, 978, 6098, -5759, -10696, -15804, -428, 5115, 2170, -1692, 5777, 2656, 9153, -10732, -13367, -7987, 2142, 2870, -11545, -13661, 475, 4646, -2677, -5499, -1885, 6993, -561, 14997, 5170, -86, 2215, 8826, 14386, 700, 2830, -17016, -14099, -8207, -4096, 861, 1047, -855, 3263, -4496, 10891, -4586, 3238, 3307, -5423, -37, -1879, -3630, -10708, -2754, -1874, -8994, -5367, -5386, 6365, 3831, -4951, 1188, -1353, -5681, -6968, -15114, 1276, 2605, -17073, 3586, -1544, -10543, -716, -3937, 840, 5876, -5147, -663, 2856, -1678, -4082, -864, 6984, 6677, -12882, 1517, 56, -7419, -6893, 5452, 8470, 425, -7704, -14178, 886, -8038, -6680, 7947, -4485, -2224, 8656, -10493, 3823, 8860, 7783, 1294, -8461, 5074, -3745, 5523, -4289, -166, -3340, -12692, 6922, 8604, -15907, -5019, 361, -14812, -397, -4405, -6570, -9220, -7620, -3638, 5609, 420, -1118, -2174, 4822, -11462, -3466, 5131, -8882, -9986, 9085, -5696, -8179, 2889, -3172, 320, -4324, -7606, -10524, 7522, 2938, 1139, 2356, 4016, -5044, 5648, 8168, -6612, -1430, 3689, -2293, -4954, -11895, -6624, -2788, 8453, 1793, -14264, -350, -3763, -3133, -74, -16773, -11166, -8932, -7153, -2175, 4329, -5888, -2308, 2961, -4330, -7138, 581, -5264, -10569, -1405, -3136, -4488, -13532, -10564, -8573, -11136, -10467, -746, 3642, -7235, 838, -2441, 6552, -1879, -2564, -6301, 3671, 608, -2298, -3497, -5924, -2864, 2579, 8997, -14853, 1248, -1355, 2565, -7664, 3787, 1792, -489, -2741, -11833, -18128, -11354, -1175, 11363, -1406, -17271, -885, -7471, -833, 8103, 9789, -7460, -2932, -3096, 4009, 3842, 1572, 5571, 6426, -10689, -6382, -3647, -11498, 780, 1485, 1253, 7857, 8317, -9330, -4297, 6437, -8942, 8210, -11978, 9046, 12151, 1022, 6849, -556, 6361, -931, -2935, -910, -3027, 9599, -185, 1830, 2025, -3700, -3474, -12308, 7284, 2738, 3036, 6904, -11531, -2797, 7176, 4149, -8544, -6432, 1707, 8907, -12037, -9012, -6343, 2381, 9088, -80, 9048, 4705, 929, 4536, -2447, -337, -4093, -8805, -2868, -11063, -6362, 12000, -14059, -6684, -9017, 2942, 6575, 2071, 2710, 7144, 4914, -13481, -2069, -2557, 1980, 1698, 3755, 3742, 11672, 1335, 6192, 2031, -543, -90, -2215, 206, -3935, -6609, -1747, -2531, 4191, 389, 16471, 257, -13012, 6806, -6756, -463, 1961, 9916, -2566, -4432, -1028, 4432, 1034, 2572, 9382, -7943, 2859, -9183, -46, 4020, -5329, 13550, 497, -12751, -3684, 8264, -3897, 3845, 7900, 7981, 1257, 4143, 15276, 14479, -10132, 7286, 6734, 5253, -2258, -1124, -4354, -9407, -4965, -2277, 2423, -517, 13839, 1977, -10419, 1252, -10270, -1452, -5676, -13977, -5144, -928, 3492, -1824, -165, 10448, -4406, 597, -10859, 8419, 8751, 2674, -768, -2737, 17012, 5966, -313, -3560, 12905, -2375, 1397, 1919, -1019, -8666, -3241, 4913, 6143, -4595, 904, -2177, 9439, 2848, -8343, 10572, -1756, -12131, 5288, -9915, 8934, -2244, 11398, 3631, 17382, -7244, 7151, -1467, 6875, -4598, -15504, 5434, -6021, 8201, -8482, -8497, -2255, 1333, 20347, 4778, 4451, -1961, 4299, -4556, -8768, -4581, 2872, -5803, 14109, 6220, 4369, 6335, -2632, 7378, 10624, -689, 898, -1995, 5942, 11529, 6812, -1233, -2718, 6608, 3606, -3389, 7035, 8005, 2897, 4941, 9385, 7014, -11013, 9886, -9, -204, 4208, -5037, -13470, -8468, -9001, 11398, -9117, 6749, -13786, -1353, 3252, -7624, 12379, 3570, -1550, -5400, -5197, 8885, 3941, 8918, 4961, 6682, 5868, 6771};

    SINT32 n = 512;
    SINT32 q = 8399873;
    SINT32 *w = SC_MALLOC(sizeof(SINT32) * n);//        = w8399873_n512;
    SINT32 *r = SC_MALLOC(sizeof(SINT32) * n);//        = r8399873_n512;
    roots_of_unity_s32(w, r, n, q, 0);
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    const utils_arith_poly_t *sc_poly  = utils_arith_poly();
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    //barrett_init(&ntt);
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0 / ntt.q_dbl;
    ntt.inv_q_flt = 1.0f / (FLOAT)ntt.u.ntt32.q;

    sc_poly->sub_single_32(s1, n, c);

    sc_poly_mpz_t pf, pg;
    sc_poly_mpz_t mp_f, mp_g;
    sc_poly_mpz_t temp, temp2;
    sc_poly_mpz_init(&temp, 2*n);
    sc_poly_mpz_init(&temp2, 2*n);
    sc_poly_mpz_init(&pf, n);
    sc_poly_mpz_init(&pg, n);
    sc_poly_mpz_init(&mp_f, n);
    sc_poly_mpz_init(&mp_g, n);

    poly_si32_to_mpi(&mp_f, n, f);
    poly_si32_to_mpi(&mp_g, n, g);
    poly_si32_to_mpi(&pf, n, s1);
    poly_si32_to_mpi(&pg, n, s2);

    sc_mod_t mod;
    limb_mod_init(&mod, q);

    sc_poly_mpz_mul(&temp, &pf, &mp_f);
    sc_poly_mpz_mod_ring(&temp, n, &temp);
    fprintf(stderr, "s1 * f FULL = ");
    size_t i;
    for (i=0; i<n; i++) {
        sc_mpz_out_str(stderr, 16, &temp.p[i]);
        fprintf(stderr, " ");
        if ((i&0x7) == 0x7) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    sc_poly_mpz_mod(&temp, &temp, &mod);

    fprintf(stderr, "s1 * f = ");
    for (i=0; i<n; i++) {
        sc_mpz_out_str(stderr, 16, &temp.p[i]);
        fprintf(stderr, " ");
        if ((i&0x7) == 0x7) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    //poly_mpi_addmul(&temp, &pg, &mp_g);      // (s1 - c)*f + s2*g
    //poly_mpi_mod_ring(&temp, n, &temp);
    sc_poly_mpz_mul(&temp2, &pg, &mp_g);
    sc_poly_mpz_mod_ring(&temp2, n, &temp2);
    sc_poly_mpz_mod(&temp2, &temp2, &mod);

    fprintf(stderr, "s2 * g = ");
    for (i=0; i<n; i++) {
        sc_mpz_out_str(stderr, 16, &temp2.p[i]);
        fprintf(stderr, " ");
        if ((i&0x7) == 0x7) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");


    sc_poly_mpz_add(&temp, &temp2, &temp);
    sc_poly_mpz_mod(&temp, &temp, &mod);
    SINT32 deg = sc_poly_mpz_degree(&temp);
    fprintf(stderr, "a. (s1-t)*f + g*s2 = ");
    sc_mpz_out_str(stderr, 16, &temp.p[0]);
    fprintf(stderr, ", deg = %d\n", deg);

    sc_poly_mpz_clear(&temp);
    sc_poly_mpz_clear(&temp2);
    sc_poly_mpz_clear(&pf);
    sc_poly_mpz_clear(&pg);
    sc_poly_mpz_clear(&mp_f);
    sc_poly_mpz_clear(&mp_g);

    sc_ntt->fwd_ntt_32_32_large(s1, &ntt, s1, w);
    sc_ntt->fwd_ntt_32_32_large(s2, &ntt, s2, w);
    sc_ntt->fwd_ntt_32_32(f, &ntt, f, w);
    sc_ntt->fwd_ntt_32_32(g, &ntt, g, w);
    sc_ntt->mul_32_pointwise(s1, &ntt, s1, f);
    sc_ntt->mul_32_pointwise(s2, &ntt, s2, g);
    sc_ntt->inv_ntt_32_32_large(s1, &ntt, s1, w, r);
    sc_ntt->inv_ntt_32_32_large(s2, &ntt, s2, w, r);

    fprintf(stderr, "s1 * f:\n");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%6d ", s1[i]);
        if ((i&0x7) == 0x7) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "s2 * g:\n");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%6d ", s2[i]);
        if ((i&0x7) == 0x7) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    sc_poly->add_single_32(s1, n, s2);
    sc_ntt->normalize_32(s1, n, &ntt);

    fprintf(stderr, "s1:\n");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%6d ", s1[i]);
        if ((i&0x7) == 0x7) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    deg = poly_32_degree(s1, n);
    fprintf(stderr, "c. (s1-t)*f + g*s2 = %d, deg = %d\n", s1[deg], deg);

    SC_FREE(w, sizeof(SINT32) * n);
    SC_FREE(r, sizeof(SINT32) * n);

    ck_assert_int_eq(deg, 0);
    ck_assert_int_eq(s1[deg], 0);
}
END_TEST
#endif

#ifdef HAVE_AVX2
START_TEST(test_ntt_mul_pointwise_avx)
{
    SINT32 v[4], t[4] = {12289, -12289, 12288, -12288}, u[4] = {-12289, -12289, 12288, -12288};
    ntt_params_t ntt;
    ntt.n = 4;
    ntt.u.ntt32.q = 12289;
    ntt.u.ntt32.k = 30;
    ntt.u.ntt32.m = (1 << ntt.u.ntt32.k) / ntt.u.ntt32.q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0 / ntt.q_dbl;

    ntt32_mult_pointwise_avx(v, &ntt, t, u);

    ck_assert_int_eq(v[0], 0);
    ck_assert_int_eq(v[1], 0);
    ck_assert_int_eq(v[2], 1);
    ck_assert_int_eq(v[3], 1);
}
END_TEST
#endif

Suite *ntt32_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_ntt, *tc_tables;
#ifndef USE_RUNTIME_NTT_TABLES
    TCase *tc_ntt32;
#endif
#ifndef DISABLE_IBE_DLP
    TCase *tc_ibe;
#endif
#ifdef HAVE_AVX2
    TCase *tc_avx;
#endif

    s = suite_create("ntt");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_ntt32_muln);
    tcase_add_test(tc_core, test_ntt32_muln_barrett);
    tcase_add_test(tc_core, test_ntt32_muln_fp);
    tcase_add_test(tc_core, test_ntt32_muln_negative);
    tcase_add_test(tc_core, test_ntt32_muln_mismatch);
    tcase_add_test(tc_core, test_ntt_muln);
    tcase_add_test(tc_core, test_ntt_muln_barrett);
    tcase_add_test(tc_core, test_ntt_muln_fp);
    tcase_add_test(tc_core, test_ntt_muln_negative);
    tcase_add_test(tc_core, test_ntt_muln_mismatch);
    suite_add_tcase(s, tc_core);

#ifndef USE_RUNTIME_NTT_TABLES
    tc_ntt32 = tcase_create("NTT32");
#ifdef NTT_NEEDS_8399873
    tcase_add_test(tc_ntt32, test_ntt32_8399873_inv_512);
#endif
#ifdef NTT_NEEDS_12289
    tcase_add_test(tc_ntt32, test_ntt32_12289_inv_1024_fp);
    tcase_add_test(tc_ntt32, test_ntt32_12289_inv_1024_barrett);
    tcase_add_test(tc_ntt32, test_ntt32_12289_inv_512_barrett);
#endif
#ifdef NTT_NEEDS_7681
    tcase_add_test(tc_ntt32, test_ntt32_7681_inv_256_barrett);
#endif
#ifdef NTT_NEEDS_12289
    tcase_add_test(tc_ntt32, test_ntt32_fwd_inv_512);
    tcase_add_test(tc_ntt32, test_ntt32_fwd_inv_1024);
    tcase_add_test(tc_ntt32, test_mixed_ntt32_12289);
#endif
#ifdef NTT_NEEDS_7681
    tcase_add_test(tc_ntt32, test_mixed_ntt32_7681);
    //tcase_add_test(tc_ntt32, test_rev_ntt32_7681);
#endif
#ifdef NTT_NEEDS_12289
    //tcase_add_test(tc_ntt32, test_rev_ntt32_12289);
#endif
    suite_add_tcase(s, tc_ntt32);
#endif

    tc_ntt = tcase_create("NTT");
#ifdef NTT_NEEDS_8399873
    tcase_add_test(tc_ntt, test_ntt_8399873_inv_512);
#endif
    suite_add_tcase(s, tc_ntt);

    tc_tables = tcase_create("TABLES");
    tcase_add_test(tc_tables, test_primitive_root);
    tcase_add_test(tc_tables, test_roots_of_unity);
    tcase_add_test(tc_tables, test_roots_of_unity_2);
    tcase_add_test(tc_tables, test_roots_of_unity_3);
    suite_add_tcase(s, tc_tables);
    tcase_set_timeout(tc_tables, 40);

#ifndef DISABLE_IBE_DLP
    tc_ibe = tcase_create("IBE");
    tcase_add_test(tc_ibe, test_ibe);
    suite_add_tcase(s, tc_ibe);
#endif

#ifdef HAVE_AVX2
    tc_avx = tcase_create("AVX");
    tcase_add_test(tc_avx, test_ntt_mul_pointwise_avx);
    suite_add_tcase(s, tc_avx);
#endif

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = ntt32_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


