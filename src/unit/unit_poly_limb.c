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
#include "utils/arith/poly_limb.c"
#include "utils/crypto/prng.c"
#include "utils/arith/next_prime.h"
#include "utils/sampling/sampling.h"


START_TEST(test_poly_limb_copy)
{
    size_t i;
    SINT32 retval;
    const size_t n = 2048;
    sc_ulimb_t out[n], in[n];
    for (i=0; i<n; i++) {
        in[i] = i;
    }
    retval = poly_limb_copy(out, n, NULL);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = poly_limb_copy(NULL, n, in);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = poly_limb_copy(out, n, in);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    for (i=0; i<n; i++) {
        ck_assert_uint_eq(in[i], out[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_swap)
{
    size_t i;
    SINT32 retval;
    const size_t n = 2048;
    sc_ulimb_t a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = i;
        b[i] = (SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)) | i;
    }
    size_t len_a = n, len_b = n >> 1;
    retval = poly_limb_swap(a, &len_a, b, &len_b);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    for (i=0; i<n >> 1; i++) {
        ck_assert_uint_eq(a[i], (SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)) | i);
    }
    for (i=0; i<n >> 1; i++) {
        ck_assert_uint_eq(b[i], i);
    }
}
END_TEST

START_TEST(test_poly_limb_degree)
{
    size_t i;
    SINT32 deg;
    const size_t n = 2048;
    sc_ulimb_t a[2048] = {0};
    for (i=0; i<n; i++) {
        a[i] = 1;
        deg = poly_limb_degree(a, n);
        ck_assert_int_eq(deg, i);
    }
}
END_TEST

START_TEST(test_poly_limb_reset)
{
    size_t i;
    const size_t n = 2048;
    sc_ulimb_t a[2048];
    for (i=0; i<n; i++) {
        a[i] = i;
    }
    poly_limb_reset(a, n);
    for (i=0; i<n; i++) {
        ck_assert_uint_eq(a[i], SC_LIMB_WORD(0));
    }
}
END_TEST

START_TEST(test_poly_limb_negate_mod)
{
    size_t i;
    sc_mod_t mod;
    mod.m     = next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    mod.m_inv = limb_inverse(mod.m);
    mod.norm  = limb_clz(mod.m);
    const size_t n = 2048;
    sc_ulimb_t a[n], out[n];
    for (i=0; i<n; i++) {
        a[i] = (i < (n/2))? mod.m - (n/2) + i : i - (n/2);
    }
    poly_limb_negate_mod(out, a, n, &mod);
    for (i=0; i<n; i++) {
        ck_assert_int_eq(out[i], (i < (n/2))? (n/2) - i : (i == (n/2))? 0 : mod.m - i + (n/2));
    }
}
END_TEST

START_TEST(test_poly_limb_mod)
{
    size_t i, j;
    const size_t n = 2048;
    for (j=8; j<SC_LIMB_BITS; j++) {
        sc_mod_t mod;
        mod.m     = (SC_LIMB_WORD(1) << j) + 1;
        mod.m_inv = limb_inverse(mod.m);
        mod.norm  = limb_clz(mod.m);

        sc_ulimb_t a[n], out[n];
        for (i=0; i<n; i++) {
            a[i] = mod.m + i;
        }
        poly_limb_mod(out, a, n, &mod);
        for (i=0; i<n; i++) {
            ck_assert_uint_eq(out[i], i % mod.m);
        }
    }
}
END_TEST

START_TEST(test_poly_limb_max_bits)
{
    size_t i, j;
    const size_t n = 2048;
    for (j=0; j<SC_LIMB_BITS; j++) {
        sc_ulimb_t a[n];
        size_t max_bits;
        for (i=0; i<n; i++) {
            a[i] = SC_LIMB_WORD(1) << j;
        }
        max_bits = poly_limb_max_bits(a, n);
        ck_assert_uint_eq(j + 1, max_bits);
    }
}
END_TEST

START_TEST(test_poly_limb_add_mod)
{
    size_t i;
    sc_mod_t mod;
    mod.m     = next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    mod.m_inv = limb_inverse(mod.m);
    mod.norm  = limb_clz(mod.m);
    sc_ulimb_t out[2048], a[2048], b[2048];
    for (i=0; i<2048; i++) {
        a[i] = mod.m;
        b[i] = i;
    }
    poly_limb_add_mod(out, a, 2048, b, 2048, &mod);
    for (i=0; i<2048; i++) {
        ck_assert_uint_eq(out[i], i);
    }
}
END_TEST

START_TEST(test_poly_limb_sub_mod)
{
    size_t i;
    sc_mod_t mod;
    mod.m     = next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    mod.m_inv = limb_inverse(mod.m);
    mod.norm  = limb_clz(mod.m);
    sc_ulimb_t out[2048], a[2048], b[2048];
    for (i=0; i<2048; i++) {
        a[i] = mod.m;
        b[i] = i;
    }
    poly_limb_sub_mod(out, a, 2048, b, 2048, &mod);
    for (i=0; i<2048; i++) {
        ck_assert_uint_eq(out[i], mod.m - i);
    }
}
END_TEST

START_TEST(test_poly_limb_addmul_mod_scalar)
{
    size_t i;
    sc_mod_t mod;
    mod.m     = next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    mod.m_inv = limb_inverse(mod.m);
    mod.norm  = limb_clz(mod.m);
    sc_ulimb_t out[4096], a[2048], b;
    for (i=0; i<2048; i++) {
        a[i] = mod.m + SC_LIMB_WORD(i);
        out[i] = SC_LIMB_WORD(i);
    }
    b = SC_LIMB_WORD(2);
    poly_limb_addmul_mod_scalar(out, a, 2048, b, &mod);
    for (i=0; i<2048; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(i+2*i));
    }
}
END_TEST

START_TEST(test_poly_limb_submul_mod_scalar)
{
    size_t i;
    sc_mod_t mod;
    mod.m     = next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    mod.m_inv = limb_inverse(mod.m);
    mod.norm  = limb_clz(mod.m);
    sc_ulimb_t out[4096], a[2048], b;
    for (i=0; i<2048; i++) {
        a[i] = SC_LIMB_WORD(i);
        out[i] = SC_LIMB_WORD(i);
    }
    b = SC_LIMB_WORD(3);
    poly_limb_submul_mod_scalar(out, a, 2048, b, &mod);
    for (i=0; i<2048; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(2*i)); // i.e. i-3*i (mod m)
    }
}
END_TEST

START_TEST(test_poly_limb_mul_mod_simple)
{
    size_t i;
    sc_mod_t mod;
    limb_mod_init(&mod, SC_LIMB_WORD(257));

    const size_t n = 16;
    sc_ulimb_t out[2*n], a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = mod.m + SC_LIMB_WORD(i);
        b[i] = SC_LIMB_WORD(0);
    }
    b[0] = SC_LIMB_WORD(2);
    b[n-1] = SC_LIMB_WORD(2);

    const SINT32     log_len = SC_LIMB_BITS - limb_clz(n);
    const sc_ulimb_t bits    = mod.b_norm;
    ck_assert_uint_lt(2*bits+log_len, SC_LIMB_BITS);

    poly_limb_mul_mod_simple(out, a, n, b, n, &mod);
    for (i=0; i<n; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(2*i));
    }
    for (i=n; i<2*n-1; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(2*(i-n+1)));
    }
}
END_TEST

START_TEST(test_poly_limb_mul_mod_gradeschool)
{
    size_t i;
    sc_mod_t mod;
    mod.m     = next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    mod.m_inv = limb_inverse(mod.m);
    mod.norm  = limb_clz(mod.m);
    const size_t n = 2048;
    sc_ulimb_t out[2*n], a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = mod.m + SC_LIMB_WORD(i);
        b[i] = SC_LIMB_WORD(0);
    }
    b[0] = SC_LIMB_WORD(2);
    b[n-1] = SC_LIMB_WORD(2);
    poly_limb_mul_mod_gradeschool(out, a, n, b, n, &mod);
    for (i=0; i<n; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(2*i));
    }
    for (i=n; i<2*n-1; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(2*(i-n+1)));
    }
}
END_TEST

START_TEST(test_poly_limb_mul_mod_gradeschool_trunc)
{
    size_t i;
    sc_mod_t mod;
    mod.m     = next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    mod.m_inv = limb_inverse(mod.m);
    mod.norm  = limb_clz(mod.m);
    const size_t n = 2048;
    sc_ulimb_t out[n], a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = mod.m + SC_LIMB_WORD(i);
        b[i] = SC_LIMB_WORD(0);
    }
    b[0] = SC_LIMB_WORD(2);
    poly_limb_mul_mod_gradeschool_trunc(out, a, n, b, n, n, &mod);
    for (i=0; i<n; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(2*i));
    }
}
END_TEST

START_TEST(test_poly_limb_mul_mod_karatsuba)
{
    size_t i;
    sc_mod_t mod;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    const size_t n = 2048;
    sc_ulimb_t out[2][2*n], a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = prng_32(prng_ctx) % mod.m;
        b[i] = prng_32(prng_ctx) % mod.m;
    }
    poly_limb_mul_mod_karatsuba(out[0], a, n, b, n, &mod);
    poly_limb_mul_mod_gradeschool(out[1], a, n, b, n, &mod);
    for (i=0; i<2*n-1; i++) {
        ck_assert_uint_eq(out[0][i], out[1][i]);
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_poly_limb_mul_mod_kronecker)
{
    size_t i;
    sc_mod_t mod;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    const size_t n = 2048;
    sc_ulimb_t out[2][2*n], a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = prng_32(prng_ctx) % mod.m;
        b[i] = prng_32(prng_ctx) % mod.m;
    }
    poly_limb_mul_mod_kronecker(out[0], a, n, b, n, &mod);
    poly_limb_mul_mod_gradeschool(out[1], a, n, b, n, &mod);
    for (i=0; i<2*n-1; i++) {
        ck_assert_uint_eq(out[0][i], out[1][i]);
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_poly_limb_mul_mod_kronecker_trunc)
{
    size_t i;
    sc_mod_t mod;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    const size_t n = 2048;
    sc_ulimb_t out[2][2*n], a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = prng_32(prng_ctx) % mod.m;
        b[i] = prng_32(prng_ctx) % mod.m;
    }
    poly_limb_mul_mod_kronecker_trunc(out[0], a, n, b, n, n, &mod);
    poly_limb_mul_mod_gradeschool(out[1], a, n, b, n, &mod);
    for (i=0; i<n; i++) {
        ck_assert_uint_eq(out[0][i], out[1][i]);
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_poly_limb_mul_mod_kronecker_ks4)
{
    size_t i;
    sc_mod_t mod;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    const size_t n = 2048;
    sc_ulimb_t out[2][2*n], a[n], b[n];
    for (i=0; i<n; i++) {
        a[i] = prng_32(prng_ctx) % mod.m;
        b[i] = prng_32(prng_ctx) % mod.m;
    }
    poly_limb_mul_mod_gradeschool(out[1], a, n, b, n, &mod);
    poly_limb_mul_mod_kronecker_ks4(out[0], a, n, b, n, &mod);
    for (i=0; i<2*n-1; i++) {
        ck_assert_uint_eq(out[0][i], out[1][i]);
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_poly_limb_mul_mod_scalar)
{
    size_t i;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t out[2048], a[2048];
    for (i=0; i<2048; i++) {
        a[i] = mod.m + SC_LIMB_WORD(i);
    }
    poly_limb_mul_mod_scalar(out, a, 2048, SC_LIMB_WORD(2), &mod);
    for (i=0; i<2048; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(2*i));
    }
}
END_TEST

START_TEST(test_poly_limb_divrem_mod)
{
    size_t i, len_q, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], r[4] = {0}, a[4], b[4], res[4] = {0};
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    b[0] = SC_LIMB_WORD(2);
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 1, &mod);
    poly_limb_mul_mod_scalar(res, q, len_q, b[0], &mod);
    poly_limb_add_mod(res, res, len_q, r, len_r, &mod);
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(res[i], a[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_divrem_mod_2)
{
    size_t i, len_q, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], r[4] = {0}, a[4], b[4], res[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    b[0] = SC_LIMB_WORD(3);
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 1, &mod);
    poly_limb_mul_mod_scalar(res, q, 4, b[0], &mod);
    poly_limb_add_mod(res, res, 4, r, 4, &mod);
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(res[i], a[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_divrem_mod_3)
{
    size_t i, len_q, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4] = {0}, r[4] = {0}, a[4], b[4], mul_res[8] = {0}, res[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    for (i=0; i<3; i++) {
        b[i] = SC_LIMB_WORD(2);
    }
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 3, &mod);
    poly_limb_mul_mod(mul_res, q, len_q, b, 3, &mod);
    poly_limb_add_mod(res, mul_res, 3+len_q, r, len_r, &mod);
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(res[i], a[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_divrem_mod_4)
{
    size_t i, len_q, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4] = {0}, r[4] = {0}, a[4], b[4], mul_res[8] = {0}, res[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
        b[i] = SC_LIMB_WORD(2);
    }
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 4, &mod);
    poly_limb_mul_mod(mul_res, q, len_q, b, 4, &mod);
    poly_limb_add_mod(res, mul_res, 4+len_q, r, len_r, &mod);
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(res[i], a[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_div_mod)
{
    size_t i, len_q, len_q2, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], q2[4], r[4] = {0}, a[4], b[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    b[0] = SC_LIMB_WORD(2);
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 1, &mod);
    poly_limb_div_mod(q2, &len_q2, a, 4, b, 1, &mod);
    ck_assert_uint_eq(len_q, len_q2);
    for (i=0; i<len_q; i++) {
        ck_assert_uint_eq(q[i], q2[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_div_mod_2)
{
    size_t i, len_q, len_q2, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], q2[4], r[4] = {0}, a[4], b[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    b[0] = SC_LIMB_WORD(3);
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 1, &mod);
    poly_limb_div_mod(q2, &len_q2, a, 4, b, 1, &mod);
    ck_assert_uint_eq(len_q, len_q2);
    for (i=0; i<len_q; i++) {
        ck_assert_uint_eq(q[i], q2[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_div_mod_3)
{
    size_t i, len_q, len_q2, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], q2[4], r[4] = {0}, a[4], b[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    for (i=0; i<3; i++) {
        b[i] = SC_LIMB_WORD(2);
    }
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 3, &mod);
    poly_limb_div_mod(q2, &len_q2, a, 4, b, 3, &mod);
    ck_assert_uint_eq(len_q, len_q2);
    for (i=0; i<len_q; i++) {
        ck_assert_uint_eq(q[i], q2[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_div_mod_4)
{
    size_t i, len_q, len_q2, len_r;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], q2[4], r[4] = {0}, a[4], b[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
        b[i] = SC_LIMB_WORD(2);
    }
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 4, &mod);
    poly_limb_div_mod(q2, &len_q2, a, 4, b, 4, &mod);
    ck_assert_uint_eq(len_q, len_q2);
    for (i=0; i<len_q; i++) {
        ck_assert_uint_eq(q[i], q2[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_rem_mod)
{
    size_t i, len_q, len_r, len_r2;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], r[4] = {0}, r2[4] = {0}, a[4], b[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    b[0] = SC_LIMB_WORD(2);
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 1, &mod);
    poly_limb_rem_mod(r2, &len_r2, a, 4, b, 1, &mod);
    ck_assert_uint_eq(len_r2, len_r);
}
END_TEST

START_TEST(test_poly_limb_rem_mod_2)
{
    size_t i, len_q, len_r, len_r2;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], r[4] = {0}, r2[4] = {0}, a[4], b[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    b[1] = SC_LIMB_WORD(2);
    b[0] = SC_LIMB_WORD(1);
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 2, &mod);
    poly_limb_rem_mod(r2, &len_r2, a, 4, b, 2, &mod);
    ck_assert_uint_eq(len_r2, len_r);
    for (i=0; i<len_r; i++) {
        ck_assert_uint_eq(r[i], r2[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_rem_mod_3)
{
    size_t i, len_q, len_r, len_r2;
    sc_mod_t mod;
    limb_mod_init(&mod, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    sc_ulimb_t q[4], r[4] = {0}, r2[4] = {0}, a[4], b[4];
    for (i=0; i<4; i++) {
        a[i] = SC_LIMB_WORD(i);
    }
    b[2] = SC_LIMB_WORD(1);
    b[1] = SC_LIMB_WORD(2);
    b[0] = SC_LIMB_WORD(3);
    poly_limb_divrem_mod(q, &len_q, r, &len_r, a, 4, b, 3, &mod);
    poly_limb_rem_mod(r2, &len_r2, a, 4, b, 3, &mod);
    ck_assert_uint_eq(len_r2, len_r);
    for (i=0; i<len_r; i++) {
        ck_assert_uint_eq(r[i], r2[i]);
    }
}
END_TEST

START_TEST(test_poly_limb_gcd_mod)
{
    size_t i, lenQ[2], lenR;
    const size_t n = 256;

    sc_mod_t modulus;
    limb_mod_init(&modulus, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    ck_assert_ptr_ne(prng_ctx, NULL);

    sc_ulimb_t gcd[n], a[n], b[n];
    for (i=0; i<n; i++) {
        SINT32 c1;
        sc_ulimb_t r;
        c1 = prng_32(prng_ctx);
        if (c1 < 0) {
            r = modulus.m - (-c1 % modulus.m);
            if (r == modulus.m)
                r = 0;
        }
        else {
            r = c1 % modulus.m;
        }
        a[i] = r;
        c1 = prng_32(prng_ctx);
        if (c1 < 0) {
            r = modulus.m - (-c1 % modulus.m);
            if (r == modulus.m)
                r = 0;
        }
        else {
            r = c1 % modulus.m;
        }
        b[i] = r;
    }

    // Calculate the GCD of the two polynomials sampled from
    // a Gaussian distribution
    SINT32 deg_a   = poly_limb_degree(a, n);
    SINT32 deg_b   = poly_limb_degree(b, n);
    SINT32 len_gcd = poly_limb_gcd_mod(gcd, a, deg_a+1, b, deg_b+1, &modulus);

    // Verify that the remainder is 0 when a or b is divided by the GCD
    sc_ulimb_t Q0[n], Q1[n], R[n];
    poly_limb_divrem_mod(Q0, &lenQ[0], R, &lenR, a, deg_a+1, gcd, len_gcd, &modulus);
    ck_assert_uint_eq(lenR, 0);
    poly_limb_divrem_mod(Q1, &lenQ[1], R, &lenR, b, deg_b+1, gcd, len_gcd, &modulus);
    ck_assert_uint_eq(lenR, 0);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_poly_limb_xgcd_mod)
{
    size_t i, lenQ[2], lenR;
    const size_t n = 256;

    sc_mod_t modulus;
    limb_mod_init(&modulus, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    ck_assert_ptr_ne(prng_ctx, NULL);

    sc_ulimb_t gcd[n], a[n], b[n];
    for (i=0; i<n; i++) {
        SINT32 c1;
        sc_ulimb_t r;
        c1 = prng_32(prng_ctx);
        if (c1 < 0) {
            r = modulus.m - (-c1 % modulus.m);
            if (r == modulus.m)
                r = 0;
        }
        else {
            r = c1 % modulus.m;
        }
        a[i] = r;
        c1 = prng_32(prng_ctx);
        if (c1 < 0) {
            r = modulus.m - (-c1 % modulus.m);
            if (r == modulus.m)
                r = 0;
        }
        else {
            r = c1 % modulus.m;
        }
        b[i] = r;
    }

    // Calculate the XGCD of the two polynomials sampled from
    // a Gaussian distribution
    SINT32 deg_a   = poly_limb_degree(a, n);
    SINT32 deg_b   = poly_limb_degree(b, n);
    sc_ulimb_t x[deg_b-1], y[deg_a-1];
    SINT32 len_gcd = poly_limb_xgcd_mod(gcd, x, y, a, deg_a+1, b, deg_b+1, &modulus);

    // Verify that the remainder is 0 when a or b is divided by the GCD
    sc_ulimb_t Q0[n], Q1[n], R[n];
    poly_limb_divrem_mod(Q0, &lenQ[0], R, &lenR, a, deg_a+1, gcd, len_gcd, &modulus);
    ck_assert_uint_eq(lenR, 0);
    poly_limb_divrem_mod(Q1, &lenQ[1], R, &lenR, b, deg_b+1, gcd, len_gcd, &modulus);
    ck_assert_uint_eq(lenR, 0);

    // Prove that a*x + b*y = GCD(a,b)
    sc_ulimb_t P0[deg_a+deg_b], P1[deg_a+deg_b];
    poly_limb_mul_mod(P0, a, deg_a+1, x, deg_b, &modulus);
    poly_limb_mul_mod(P1, b, deg_b+1, y, deg_a, &modulus);
    poly_limb_add_mod(P0, P0, (deg_a+1)+deg_b-1, P1, (deg_b+1)+deg_a-1, &modulus);
    for (i=0; i<len_gcd; i++) {
        ck_assert_uint_eq(P0[i], gcd[i]);
    }
    for (i=len_gcd; i<deg_a+deg_b; i++) {
        ck_assert_uint_eq(P0[i], SC_LIMB_WORD(0));
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_poly_limb_resultant_euclidean)
{
    sc_mod_t modulus;
    limb_mod_init(&modulus, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    size_t i, len_a = 1024, len_b = 1024;
    sc_ulimb_t a[len_a], b[len_b];
    for (i=0; i<len_a; i++) {
        a[i] = i+1;
    }
    for (i=0; i<len_b; i++) {
        b[i] = i+2;
    }

    sc_ulimb_t res;
    res = poly_limb_resultant_euclidean(a, len_a, a, len_a, NULL, &modulus);
    ck_assert_uint_eq(res, 0);

    res = poly_limb_resultant_euclidean(a, 1, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, 1);

    res = poly_limb_resultant_euclidean(a, 2, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, b[0]);

    res = poly_limb_resultant_euclidean(a, 3, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, (b[0] * b[0]) % modulus.m);

    res = poly_limb_resultant_euclidean(a, 8, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, (b[0] * b[0] * b[0] * b[0] * b[0] * b[0] * b[0]) % modulus.m);
}
END_TEST

START_TEST(test_poly_limb_resultant_euclidean_2)
{
    sc_mod_t modulus;
    limb_mod_init(&modulus, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    
    size_t i, len_a = 1024, len_b = 1024;
    sc_ulimb_t a[len_a], b[len_b];
    for (i=0; i<len_a; i++) {
        a[i] = 0;
    }
    for (i=0; i<len_b; i++) {
        b[i] = 0;
    }

    sc_ulimb_t *scratch = SC_MALLOC(sizeof(sc_ulimb_t) * 4 * len_a);
    sc_ulimb_t res = poly_limb_resultant_euclidean(a, len_a, b, len_b, scratch, &modulus);
    SC_FREE(scratch, sizeof(sc_ulimb_t) * 4 * len_a);
    ck_assert_uint_eq(res, 0);
}
END_TEST

START_TEST(test_poly_limb_resultant_halfgcd)
{
    sc_mod_t modulus;
    limb_mod_init(&modulus, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));

    size_t i, len_a = 1024, len_b = 1024;
    sc_ulimb_t a[len_a], b[len_b];
    for (i=0; i<len_a; i++) {
        a[i] = i+1;
    }
    for (i=0; i<len_b; i++) {
        b[i] = i+2;
    }

    sc_ulimb_t res;
    res = poly_limb_resultant_halfgcd(a, len_a, a, len_a, NULL, &modulus);
    ck_assert_uint_eq(res, 0);

    res = poly_limb_resultant_halfgcd(a, 1, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, 1);

    res = poly_limb_resultant_halfgcd(a, 2, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, b[0]);

    res = poly_limb_resultant_halfgcd(a, 3, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, (b[0] * b[0]) % modulus.m);

    res = poly_limb_resultant_halfgcd(a, 8, b, 1, NULL, &modulus);
    ck_assert_uint_eq(res, (b[0] * b[0] * b[0] * b[0] * b[0] * b[0] * b[0]) % modulus.m);
}
END_TEST

START_TEST(test_poly_limb_resultant_halfgcd_2)
{
    sc_mod_t modulus;
    limb_mod_init(&modulus, next_prime(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)));
    
    size_t i, len_a = 1024, len_b = 1024;
    sc_ulimb_t a[len_a], b[len_b];
    for (i=0; i<len_a; i++) {
        a[i] = 0;
    }
    for (i=0; i<len_b; i++) {
        b[i] = 0;
    }

    sc_ulimb_t *scratch = SC_MALLOC(sizeof(sc_ulimb_t) * 4 * len_a);
    sc_ulimb_t res = poly_limb_resultant_halfgcd(a, len_a, b, len_b, scratch, &modulus);
    SC_FREE(scratch, sizeof(sc_ulimb_t) * 4 * len_a);
    ck_assert_uint_eq(res, 0);
}
END_TEST

Suite *poly_limb_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly_limb");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_poly_limb_copy);
    tcase_add_test(tc_core, test_poly_limb_swap);
    tcase_add_test(tc_core, test_poly_limb_degree);
    tcase_add_test(tc_core, test_poly_limb_reset);
    tcase_add_test(tc_core, test_poly_limb_negate_mod);
    tcase_add_test(tc_core, test_poly_limb_mod);
    tcase_add_test(tc_core, test_poly_limb_max_bits);
    tcase_add_test(tc_core, test_poly_limb_add_mod);
    tcase_add_test(tc_core, test_poly_limb_sub_mod);
    tcase_add_test(tc_core, test_poly_limb_addmul_mod_scalar);
    tcase_add_test(tc_core, test_poly_limb_submul_mod_scalar);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_simple);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_gradeschool);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_gradeschool_trunc);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_karatsuba);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_kronecker);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_kronecker_trunc);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_kronecker_ks4);
    tcase_add_test(tc_core, test_poly_limb_mul_mod_scalar);
    tcase_add_test(tc_core, test_poly_limb_divrem_mod);
    tcase_add_test(tc_core, test_poly_limb_divrem_mod_2);
    tcase_add_test(tc_core, test_poly_limb_divrem_mod_3);
    tcase_add_test(tc_core, test_poly_limb_divrem_mod_4);
    tcase_add_test(tc_core, test_poly_limb_div_mod);
    tcase_add_test(tc_core, test_poly_limb_div_mod_2);
    tcase_add_test(tc_core, test_poly_limb_div_mod_3);
    tcase_add_test(tc_core, test_poly_limb_div_mod_4);
    tcase_add_test(tc_core, test_poly_limb_rem_mod);
    tcase_add_test(tc_core, test_poly_limb_rem_mod_2);
    tcase_add_test(tc_core, test_poly_limb_rem_mod_3);
    tcase_add_test(tc_core, test_poly_limb_gcd_mod);
    tcase_add_test(tc_core, test_poly_limb_xgcd_mod);
    tcase_add_test(tc_core, test_poly_limb_resultant_euclidean);
    tcase_add_test(tc_core, test_poly_limb_resultant_euclidean_2);
    tcase_add_test(tc_core, test_poly_limb_resultant_halfgcd);
    tcase_add_test(tc_core, test_poly_limb_resultant_halfgcd_2);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = poly_limb_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


