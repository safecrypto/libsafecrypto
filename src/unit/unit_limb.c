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
#include "utils/arith/limb.c"
#include "utils/arith/next_prime.h"
#include "utils/crypto/prng.c"


START_TEST(test_primes)
{
    size_t i;
    sc_ulimb_t p;
    for (i=1; i<NUM_SMALL_PRIMES; i++) {
        p = next_prime(small_primes[i-1]);
        ck_assert_uint_eq(p, small_primes[i]);
    }
}
END_TEST

START_TEST(test_primes_2)
{
    sc_ulimb_t p;
    p = next_prime(1021);
    ck_assert_uint_eq(p, 1031);
    p = next_prime(1031);
    ck_assert_uint_eq(p, 1033);
}
END_TEST

START_TEST(test_primes_3)
{
    size_t i, j;
    sc_ulimb_t *d = SC_MALLOC(1024 * sizeof(sc_ulimb_t));
    for (i=0; i<16; i++) {
        // Generate 1024 sequential prime numbers starting at
        // a defined interval
        d[0] = 1 << (i+(SC_LIMB_BITS/2));
        d[0] = next_prime(d[0]);
        for (j=1; j<1024; j++) {
            d[j] = next_prime(d[j-1]);

            // Test the generated prime numbers for ascending size
            ck_assert_int_gt(d[j], d[j-1]);
        }
    }
    SC_FREE(d, 1024 * sizeof(sc_ulimb_t));
}
END_TEST

START_TEST(test_multiplicative_inverse)
{
    size_t i;
    sc_ulimb_t p = SC_LIMB_WORD(1) << (SC_LIMB_BITS-1);
    sc_ulimb_t data, data_inv;
    sc_ulimb_big_t result;
    for (i=1; i<64; i++) {
        p        = next_prime(p);
        data     = SC_LIMB_B4(i)*SC_LIMB_B4(i);
        data_inv = limb_inv_mod(data, p);
        result   = ((sc_ulimb_big_t) data * (sc_ulimb_big_t) data_inv) % p;
        fprintf(stderr, "%016lX %016lX %016lX %016lX\n", p, data, data_inv, (sc_ulimb_t)result);
        ck_assert_uint_eq((sc_ulimb_t)result, 1);
    }
}
END_TEST

START_TEST(test_limb_clz)
{
    SINT32 count;
    count = limb_clz(SC_LIMB_WORD(0));
    ck_assert_int_eq(count, SC_LIMB_BITS);
    count = limb_clz(SC_LIMB_WORD(1));
    ck_assert_int_eq(count, SC_LIMB_BITS-1);
    count = limb_clz(SC_LIMB_WORD(2));
    ck_assert_int_eq(count, SC_LIMB_BITS-2);
    count = limb_clz(SC_LIMB_WORD(3));
    ck_assert_int_eq(count, SC_LIMB_BITS-2);
    count = limb_clz(SC_LIMB_WORD(32));
    ck_assert_int_eq(count, SC_LIMB_BITS-6);
    count = limb_clz(SC_LIMB_WORD(-1));
    ck_assert_int_eq(count, 0);
    count = limb_clz(SC_LIMB_WORD(-1) >> 1);
    ck_assert_int_eq(count, 1);
    count = limb_clz(SC_LIMB_WORD(-1) >> 2);
    ck_assert_int_eq(count, 2);
    count = limb_clz(SC_LIMB_WORD(-1) >> 3);
    ck_assert_int_eq(count, 3);
}
END_TEST

START_TEST(test_limb_mul_hi_lo)
{
    sc_ulimb_t p1, p0;
    limb_mul_hi_lo(&p1, &p0, SC_LIMB_WORD(1), SC_LIMB_WORD(0));
    ck_assert_uint_eq(p0, 0);
    ck_assert_uint_eq(p1, 0);
    limb_mul_hi_lo(&p1, &p0, SC_LIMB_WORD(1), SC_LIMB_WORD(1));
    ck_assert_uint_eq(p0, 1);
    ck_assert_uint_eq(p1, 0);
    limb_mul_hi_lo(&p1, &p0, SC_LIMB_WORD(-1), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(1));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(-2));
    limb_mul_hi_lo(&p1, &p0, SC_LIMB_WORD(1) << (SC_LIMB_BITS-1), SC_LIMB_WORD(2));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(0));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(1));
}
END_TEST

START_TEST(test_limb_sqr_hi_lo)
{
    sc_ulimb_t p1, p0;
    limb_sqr_hi_lo(&p1, &p0, SC_LIMB_WORD(0));
    ck_assert_uint_eq(p0, 0);
    ck_assert_uint_eq(p1, 0);
    limb_sqr_hi_lo(&p1, &p0, SC_LIMB_WORD(1));
    ck_assert_uint_eq(p0, 1);
    ck_assert_uint_eq(p1, 0);
    limb_sqr_hi_lo(&p1, &p0, SC_LIMB_WORD(2));
    ck_assert_uint_eq(p0, 4);
    ck_assert_uint_eq(p1, 0);
    limb_sqr_hi_lo(&p1, &p0, SC_LIMB_WORD(-1));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(1));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(-2));
    limb_sqr_hi_lo(&p1, &p0, SC_LIMB_WORD(-2));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(4));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(-4));
}
END_TEST

START_TEST(test_limb_add_hi_lo)
{
    sc_ulimb_t p1, p0;
    limb_add_hi_lo(&p1, &p0, SC_LIMB_WORD(0), SC_LIMB_WORD(-1), SC_LIMB_WORD(1), SC_LIMB_WORD(1));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(0));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(2));
    limb_add_hi_lo(&p1, &p0, SC_LIMB_WORD(0), SC_LIMB_WORD(-1), SC_LIMB_WORD(0), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(-2));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(1));
    limb_add_hi_lo(&p1, &p0, SC_LIMB_WORD(0), SC_LIMB_WORD(-2), SC_LIMB_WORD(0), SC_LIMB_WORD(2));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(0));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(1));
}
END_TEST

START_TEST(test_limb_sub_hi_lo)
{
    sc_ulimb_t p1, p0;
    limb_sub_hi_lo(&p1, &p0, SC_LIMB_WORD(1), SC_LIMB_WORD(-1), SC_LIMB_WORD(1), SC_LIMB_WORD(0));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(-1));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(0));
    limb_sub_hi_lo(&p1, &p0, SC_LIMB_WORD(-1), SC_LIMB_WORD(0), SC_LIMB_WORD(1), SC_LIMB_WORD(1));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(-1));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(-3));
    limb_sub_hi_lo(&p1, &p0, SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(p0, SC_LIMB_WORD(0));
    ck_assert_uint_eq(p1, SC_LIMB_WORD(0));
}
END_TEST

START_TEST(test_limb_mod_l)
{
    sc_ulimb_t lo, m, minv, norm, res;
    m    = SC_LIMB_WORD(1) << (SC_LIMB_BITS-1);
    m    = next_prime(m);
    minv = limb_inverse(m);
    norm = limb_clz(m);
    lo   = SC_LIMB_WORD(0);
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    lo   = SC_LIMB_WORD(1);
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    lo   = m;
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    lo   = m + SC_LIMB_WORD(1);
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));

    m    = SC_LIMB_WORD(256);
    m    = next_prime(m);
    minv = limb_inverse(m);
    norm = limb_clz(m);
    lo   = SC_LIMB_WORD(0);
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    lo   = SC_LIMB_WORD(1);
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    lo   = m;
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    lo   = m + SC_LIMB_WORD(1);
    res  = limb_mod_l(lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
}
END_TEST

START_TEST(test_limb_mod_ll)
{
    sc_ulimb_t hi, lo, m, minv, norm, res, mul_hi, mul_lo;
    m    = SC_LIMB_WORD(1) << (SC_LIMB_BITS-1);
    m    = next_prime(m);
    minv = limb_inverse(m);
    norm = limb_clz(m);
    hi   = SC_LIMB_WORD(0);
    lo   = SC_LIMB_WORD(0);
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    hi   = SC_LIMB_WORD(0);
    lo   = SC_LIMB_WORD(1);
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    hi   = SC_LIMB_WORD(0);
    lo   = m;
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    hi   = SC_LIMB_WORD(0);
    lo   = m + SC_LIMB_WORD(1);
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    limb_mul_hi_lo(&mul_hi, &mul_lo, m, SC_LIMB_WORD(31));
    limb_add_hi_lo(&hi, &lo, mul_hi, mul_lo, 0, SC_LIMB_WORD(5));
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(5));
    limb_mul_hi_lo(&mul_hi, &mul_lo, m, SC_LIMB_WORD(-1));
    limb_add_hi_lo(&hi, &lo, mul_hi, mul_lo, 0, SC_LIMB_WORD(1));
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    limb_mul_hi_lo(&mul_hi, &mul_lo, m, SC_LIMB_WORD(-2));
    limb_add_hi_lo(&hi, &lo, mul_hi, mul_lo, 0, m - 1);
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, m - 1);
}
END_TEST

START_TEST(test_limb_mod_lll)
{
    sc_ulimb_t hi, mi, lo, m, minv, norm, res, mul_hi, mul_lo;
    m    = SC_LIMB_WORD(1) << (SC_LIMB_BITS-1);
    m    = next_prime(m);
    minv = limb_inverse(m);
    norm = limb_clz(m);
    hi   = SC_LIMB_WORD(0);
    mi   = SC_LIMB_WORD(0);
    lo   = SC_LIMB_WORD(0);
    res  = limb_mod_lll(hi, mi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    hi   = SC_LIMB_WORD(0);
    mi   = SC_LIMB_WORD(0);
    lo   = SC_LIMB_WORD(1);
    res  = limb_mod_lll(hi, mi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    hi   = SC_LIMB_WORD(0);
    mi   = SC_LIMB_WORD(0);
    lo   = m;
    res  = limb_mod_lll(hi, mi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    hi   = SC_LIMB_WORD(0);
    mi   = SC_LIMB_WORD(0);
    lo   = m + SC_LIMB_WORD(1);
    res  = limb_mod_lll(hi, mi, lo, m, minv, norm);
    hi   = SC_LIMB_WORD(0);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    limb_mul_hi_lo(&mul_hi, &mul_lo, m, SC_LIMB_WORD(31));
    limb_add_hi_lo(&mi, &lo, mul_hi, mul_lo, 0, SC_LIMB_WORD(5));
    res  = limb_mod_lll(hi, mi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(5));
    limb_mul_hi_lo(&mul_hi, &mul_lo, m, SC_LIMB_WORD(-1));
    limb_add_hi_lo(&mi, &lo, mul_hi, mul_lo, 0, SC_LIMB_WORD(1));
    res  = limb_mod_lll(hi, mi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    limb_mul_hi_lo(&mul_hi, &mul_lo, m, SC_LIMB_WORD(-2));
    limb_add_hi_lo(&mi, &lo, mul_hi, mul_lo, 0, m - 1);
    res  = limb_mod_lll(hi, mi, lo, m, minv, norm);
    ck_assert_uint_eq(res, m - 1);
}
END_TEST

START_TEST(test_add_mod)
{
    // NOTE: INPUTS MUST BE MODULO M

    sc_ulimb_t result;
    result = limb_add_mod(0, 0, 1);
    ck_assert_uint_eq(result, 0);
    result = limb_add_mod(1, 0, 2);
    ck_assert_uint_eq(result, 1);
    result = limb_add_mod(SC_LIMB_WORD(-2), 0, SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, SC_LIMB_WORD(-2));
    result = limb_add_mod(0, 1, 2);
    ck_assert_uint_eq(result, 1);
    result = limb_add_mod(0, SC_LIMB_WORD(-2), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, SC_LIMB_WORD(-2));
    result = limb_add_mod(SC_LIMB_WORD(-2), SC_LIMB_WORD(-2), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, SC_LIMB_WORD(-3));
    result = limb_add_mod(SC_LIMB_WORD(-2), 1, SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, 0);
    result = limb_add_mod(SC_LIMB_WORD(-2), SC_LIMB_WORD(-3), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, SC_LIMB_WORD(-4));
}
END_TEST

START_TEST(test_sub_mod)
{
    // NOTE: INPUTS MUST BE MODULO M

    sc_ulimb_t result;
    result = limb_sub_mod(0, 0, 1);
    ck_assert_uint_eq(result, 0);
    result = limb_sub_mod(1, 0, 2);
    ck_assert_uint_eq(result, 1);
    result = limb_sub_mod(SC_LIMB_WORD(-2), 0, SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, SC_LIMB_WORD(-2));
    result = limb_sub_mod(0, 1, 2);
    ck_assert_uint_eq(result, 1);
    result = limb_sub_mod(0, SC_LIMB_WORD(-2), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, 1);
    result = limb_sub_mod(SC_LIMB_WORD(-2), SC_LIMB_WORD(-2), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, 0);
    result = limb_sub_mod(SC_LIMB_WORD(-2), 1, SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, SC_LIMB_WORD(-3));
    result = limb_sub_mod(SC_LIMB_WORD(-2), SC_LIMB_WORD(-3), SC_LIMB_WORD(-1));
    ck_assert_uint_eq(result, 1);
}
END_TEST

START_TEST(test_mul_mod)
{
    size_t i;
    sc_ulimb_t p = SC_LIMB_WORD(1) << (SC_LIMB_BITS - 1);
    sc_ulimb_t p_inv, p_norm, result;
    sc_ulimb_big_t test;
    for (i=0; i<16; i++) {
        p      = next_prime(p);
        p_inv  = limb_inverse(p);
        p_norm = limb_clz(p);
        result = limb_mul_mod_norm(SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), p, p_inv, p_norm);
        test  = ((sc_ulimb_big_t)SC_LIMB_WORD(-1) *
            (sc_ulimb_big_t)SC_LIMB_WORD(-1)) % (sc_ulimb_big_t)p;
        ck_assert_uint_eq(result, (sc_ulimb_t)test);
    }
}
END_TEST

START_TEST(test_sqr_mod)
{
    size_t i;
    sc_ulimb_t p = SC_LIMB_WORD(1) << (SC_LIMB_BITS - 1);
    sc_ulimb_t p_inv, p_norm, result;
    sc_ulimb_big_t test;
    for (i=0; i<16; i++) {
        p      = next_prime(p);
        p_inv  = limb_inverse(p);
        p_norm = limb_clz(p);
        result = limb_sqr_mod_norm(SC_LIMB_WORD(-1), p, p_inv, p_norm);
        test  = ((sc_ulimb_big_t)SC_LIMB_WORD(-1) *
            (sc_ulimb_big_t)SC_LIMB_WORD(-1)) % (sc_ulimb_big_t)p;
        ck_assert_uint_eq(result, (sc_ulimb_t)test);
    }
}
END_TEST

START_TEST(test_gcd)
{
    sc_ulimb_t gcd;
    gcd = limb_gcd(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1), 1);
    ck_assert_uint_eq(gcd, 1);
    gcd = limb_gcd(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1), 2);
    ck_assert_uint_eq(gcd, 2);
    gcd = limb_gcd(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1), 1024);
    ck_assert_uint_eq(gcd, 1024);
    gcd = limb_gcd(16, 16);
    ck_assert_uint_eq(gcd, 16);
    gcd = limb_gcd(54, 24);
    ck_assert_uint_eq(gcd, 6);
    gcd = limb_gcd(3, 5);
    ck_assert_uint_eq(gcd, 1);
    gcd = limb_gcd(31, 17);
    ck_assert_uint_eq(gcd, 1);
    gcd = limb_gcd(12289, 7681);
    ck_assert_uint_eq(gcd, 1);
}
END_TEST

START_TEST(test_xgcd)
{
    sc_ulimb_t gcd, x, y;
    sc_ulimb_t p;
    gcd = limb_xgcd(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1), 1, &x, &y);
    p = (sc_ulimb_big_t)(SC_LIMB_WORD(1) << (SC_LIMB_BITS-1)) * (sc_ulimb_t)x + (sc_ulimb_t)y;
    ck_assert_uint_eq(gcd, 1);
    ck_assert_uint_eq(p, gcd);

    gcd = limb_xgcd(512, 12289, &x, &y);
    p = SC_LIMB_WORD(512) * (sc_ulimb_t)x + SC_LIMB_WORD(12289) * (sc_ulimb_t)y;
    ck_assert_uint_eq(gcd, 1);
    ck_assert_uint_eq(p, gcd);
}
END_TEST

START_TEST(test_inverse_3by2)
{
    sc_ulimb_t hi, lo, m, minv, norm, res;
    m    = SC_LIMB_WORD(1) << (SC_LIMB_BITS-1);
    m    = next_prime(m);
    norm = limb_clz(m);
    minv = limb_inverse_3by2(m, 0);
    hi   = SC_LIMB_WORD(0);
    lo   = SC_LIMB_WORD(0);
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(0));
    hi   = SC_LIMB_WORD(0);
    lo   = SC_LIMB_WORD(1);
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
    hi   = SC_LIMB_WORD(0);
    lo   = m + SC_LIMB_WORD(1);
    res  = limb_mod_ll(hi, lo, m, minv, norm);
    ck_assert_uint_eq(res, SC_LIMB_WORD(1));
}
END_TEST

START_TEST(test_qrnnd_3by2)
{
    sc_ulimb_t q, r1, r0, n2, n1, n0, d1, d0, d_inv;
    n2 = 0;
    n1 = 2;
    n0 = 0;
    d1 = 1;
    d0 = 0;
    d_inv = limb_inverse_3by2(d1, d0);
    udiv_qrnnndd_preinv(&q, &r1, &r0, n2, n1, n0, d1, d0, d_inv);
    ck_assert_uint_eq(q, SC_LIMB_WORD(2));
    ck_assert_uint_eq(r1, SC_LIMB_WORD(0));
    ck_assert_uint_eq(r0, SC_LIMB_WORD(0));
    n2 = 0;
    n1 = 3;
    n0 = 0;
    d1 = 1;
    d0 = SC_LIMB_HIGHBIT;
    d_inv = limb_inverse_3by2(d1, d0);
    udiv_qrnnndd_preinv(&q, &r1, &r0, n2, n1, n0, d1, d0, d_inv);
    ck_assert_uint_eq(q, SC_LIMB_WORD(2));
    ck_assert_uint_eq(r1, SC_LIMB_WORD(0));
    ck_assert_uint_eq(r0, SC_LIMB_WORD(0));
}
END_TEST

START_TEST(test_umul32)
{
    UINT32 hi, lo, u, v;
    u = 0x00000000L;
    v = 0x00000000L;
    umul32(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x00000000L);
    ck_assert_uint_eq(hi, 0x00000000L);

    u = 0x00000000L;
    v = 0x00000001L;
    umul32(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x00000000L);
    ck_assert_uint_eq(hi, 0x00000000L);

    u = 0x00000001L;
    v = 0x80000000L;
    umul32(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x80000000L);
    ck_assert_uint_eq(hi, 0x00000000L);

    u = 0x00000002L;
    v = 0x80000000L;
    umul32(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x00000000L);
    ck_assert_uint_eq(hi, 0x00000001L);

    u = 0xFFFFFFFFL;
    v = 0xFFFFFFFFL;
    umul32(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x00000001L);
    ck_assert_uint_eq(hi, 0xFFFFFFFEL);
}
END_TEST

START_TEST(test_umul64)
{
    UINT64 hi, lo, u, v;
    u = 0x0000000000000000L;
    v = 0x0000000000000000L;
    umul64(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x0000000000000000L);
    ck_assert_uint_eq(hi, 0x0000000000000000L);

    u = 0x0000000000000000L;
    v = 0x0000000000000001L;
    umul64(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x0000000000000000L);
    ck_assert_uint_eq(hi, 0x0000000000000000L);

    u = 0x0000000000000001L;
    v = 0x8000000000000000L;
    umul64(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x8000000000000000L);
    ck_assert_uint_eq(hi, 0x0000000000000000L);

    u = 0x0000000000000002L;
    v = 0x8000000000000000L;
    umul64(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x0000000000000000L);
    ck_assert_uint_eq(hi, 0x0000000000000001L);

    u = 0xFFFFFFFFFFFFFFFFL;
    v = 0xFFFFFFFFFFFFFFFFL;
    umul64(&hi, &lo, u, v);
    ck_assert_uint_eq(lo, 0x0000000000000001L);
    ck_assert_uint_eq(hi, 0xFFFFFFFFFFFFFFFEL);
}
END_TEST

START_TEST(test_limb_mont_mul)
{
    sc_ulimb_t a, b, m, hi, lo, abar, bbar, mprime, rinv, result;

    m = 7681;
    a = 0;
    b = 0;
    limb_binxgcd(SC_LIMB_HIGHBIT, m, &rinv, &mprime);
    abar = limb_umod(a, 0, m);
    bbar = limb_umod(b, 0, m);
    result = limb_mont_mul(abar, bbar, m, mprime);
    limb_umul(&hi, &lo, result, rinv);
    result = limb_umod(hi, lo, m);
    ck_assert_uint_eq(result, 0);

    m = 7681;
    a = 1;
    b = 1;
    limb_binxgcd(SC_LIMB_HIGHBIT, m, &rinv, &mprime);
    abar = limb_umod(a, 0, m);
    bbar = limb_umod(b, 0, m);
    result = limb_mont_mul(abar, bbar, m, mprime);
    limb_umul(&hi, &lo, result, rinv);
    result = limb_umod(hi, lo, m);
    ck_assert_uint_eq(result, 1);

    m = 7681;
    a = 7680;
    b = 1;
    limb_binxgcd(SC_LIMB_HIGHBIT, m, &rinv, &mprime);
    abar = limb_umod(a, 0, m);
    bbar = limb_umod(b, 0, m);
    result = limb_mont_mul(abar, bbar, m, mprime);
    limb_umul(&hi, &lo, result, rinv);
    result = limb_umod(hi, lo, m);
    ck_assert_uint_eq(result, 7680);

    m = 7681;
    a = m - 1;
    b = m - 1;
    limb_binxgcd(SC_LIMB_HIGHBIT, m, &rinv, &mprime);
    abar = limb_umod(a, 0, m);
    bbar = limb_umod(b, 0, m);
    result = limb_mont_mul(abar, bbar, m, mprime);
    limb_umul(&hi, &lo, result, rinv);
    result = limb_umod(hi, lo, m);
    ck_assert_uint_eq(result, 1);

    m = 7681;
    a = 127;
    b = 4567;
    limb_binxgcd(SC_LIMB_HIGHBIT, m, &rinv, &mprime);
    abar = limb_umod(a, 0, m);
    bbar = limb_umod(b, 0, m);
    result = limb_mont_mul(abar, bbar, m, mprime);
    limb_umul(&hi, &lo, result, rinv);
    result = limb_umod(hi, lo, m);
    ck_assert_uint_eq(result, 3934);
}
END_TEST

Suite *limb_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("limb");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_primes);
    //tcase_add_test(tc_core, test_primes_2);
    //tcase_add_test(tc_core, test_primes_3);
    tcase_add_test(tc_core, test_multiplicative_inverse);
    tcase_add_test(tc_core, test_limb_clz);
    tcase_add_test(tc_core, test_limb_mul_hi_lo);
    tcase_add_test(tc_core, test_limb_sqr_hi_lo);
    tcase_add_test(tc_core, test_limb_add_hi_lo);
    tcase_add_test(tc_core, test_limb_sub_hi_lo);
    tcase_add_test(tc_core, test_limb_mod_l);
    tcase_add_test(tc_core, test_limb_mod_ll);
    tcase_add_test(tc_core, test_limb_mod_lll);
    tcase_add_test(tc_core, test_add_mod);
    tcase_add_test(tc_core, test_sub_mod);
    tcase_add_test(tc_core, test_mul_mod);
    tcase_add_test(tc_core, test_sqr_mod);
    tcase_add_test(tc_core, test_gcd);
    tcase_add_test(tc_core, test_xgcd);
    tcase_add_test(tc_core, test_inverse_3by2);
    tcase_add_test(tc_core, test_qrnnd_3by2);
    tcase_add_test(tc_core, test_umul32);
    tcase_add_test(tc_core, test_umul64);
    tcase_add_test(tc_core, test_limb_mont_mul);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = limb_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


