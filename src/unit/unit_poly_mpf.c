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
#include "utils/arith/poly_mpf.c"
#include "utils/crypto/prng.c"
#include "utils/sampling/gaussian_cdf.c"


START_TEST(test_dot_product)
{
    sc_mpf_t poly[4];
    for (size_t i=0; i<4; i++) {
        mpf_init(poly[i].data);
    }
    mpf_set_si(poly[0].data, 1);
    mpf_set_si(poly[1].data, 2);
    mpf_set_si(poly[2].data, 3);
    mpf_set_si(poly[3].data, 4);
    sc_mpf_t value;
    value = poly_mpf_dot_product(NULL, 4);
    ck_assert_int_eq(1, mpf_dbl_equal(value, -1));
    value = poly_mpf_dot_product(poly, 0);
    ck_assert_int_eq(1, mpf_dbl_equal(value, 0));
    value = poly_mpf_dot_product(poly, 4);
    ck_assert_int_eq(1, mpf_dbl_equal(value, 30));
}
END_TEST

START_TEST(test_modulus)
{
    sc_mpf_t poly[4];
    for (size_t i=0; i<4; i++) {
        mpf_init(poly[i].data);
    }
    mpf_set_si(poly[0].data, 1);
    mpf_set_si(poly[1].data, 2);
    mpf_set_si(poly[2].data, 3);
    mpf_set_si(poly[3].data, 4);
    sc_mpf_t value;
    value = poly_mpf_modulus(NULL, 4);
    ck_assert_int_eq(1, mpf_dbl_equal(value, -1));
    value = poly_mpf_modulus(poly, 0);
    ck_assert_int_eq(1, mpf_dbl_equal(value, 0));
    value = poly_mpf_modulus(poly, 4);
    ck_assert_int_eq(1, mpf_dbl_equal(value, sqrt(30)));
}
END_TEST

START_TEST(test_degree)
{
    sc_mpf_t poly[4];
    for (size_t i=0; i<4; i++) {
        mpf_init(poly[i].data);
    }
    mpf_set_si(poly[0].data, 1);
    mpf_set_si(poly[1].data, 2);
    mpf_set_si(poly[2].data, 3);
    mpf_set_si(poly[3].data, 4);
    SINT32 value;
    value = poly_mpf_degree(NULL, 4);
    ck_assert_int_eq(value, -1);
    value = poly_mpf_degree(poly, 0);
    ck_assert_int_eq(value, -1);
    value = poly_mpf_degree(poly, 4);
    ck_assert_int_eq(value, 3);
}
END_TEST

START_TEST(test_div_0)
{
    size_t i;
    sc_mpf_t num[4], den[4], quo[4], rem[4];
    for (size_t i=0; i<4; i++) {
        mpf_init(num[i].data);
        mpf_init(den[i].data);
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }
    mpf_set_si(num[0].data, 1);
    mpf_set_si(num[1].data, 2);
    mpf_set_si(num[2].data, 3);
    mpf_set_si(num[3].data, 4);
    mpf_set_si(den[0].data, 2);
    mpf_set_si(den[1].data, 0);
    mpf_set_si(den[2].data, 0);
    mpf_set_si(den[3].data, 0);
    for (i=0; i<4; i++) {
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }
    poly_mpf_div(num, den, 4, quo, rem);
    sc_mpf_t prod[8];
    for (i=0; i<8; i++) {
        mpf_init(prod[i].data);
    }
    poly_mpf_mul(prod, 4, den, quo);
    poly_mpf_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, equal(prod[i], num[i]));
    }
}
END_TEST

START_TEST(test_div_1)
{
    size_t i;
    sc_mpf_t num[4], den[4], quo[4], rem[4];
    for (size_t i=0; i<4; i++) {
        mpf_init(num[i].data);
        mpf_init(den[i].data);
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }
    mpf_set_si(num[0].data, 1);
    mpf_set_si(num[1].data, 2);
    mpf_set_si(num[2].data, 3);
    mpf_set_si(num[3].data, 4);
    mpf_set_si(den[0].data, 0);
    mpf_set_si(den[1].data, 0);
    mpf_set_si(den[2].data, 2);
    mpf_set_si(den[3].data, 0);
    for (i=0; i<4; i++) {
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }
    poly_mpf_div(num, den, 4, quo, rem);
    sc_mpf_t prod[8];
    for (i=0; i<8; i++) {
        mpf_init(prod[i].data);
    }
    poly_mpf_mul(prod, 4, den, quo);
    poly_mpf_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, equal(prod[i], num[i]));
    }
}
END_TEST

START_TEST(test_div_2)
{
    size_t i;
    sc_mpf_t num[4], den[4], quo[4], rem[4];
    for (size_t i=0; i<4; i++) {
        mpf_init(num[i].data);
        mpf_init(den[i].data);
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }
    mpf_set_si(num[0].data, 1);
    mpf_set_si(num[1].data, 0);
    mpf_set_si(num[2].data, 0);
    mpf_set_si(num[3].data, 2);
    mpf_set_si(den[0].data, 7);
    mpf_set_si(den[1].data, 0);
    mpf_set_si(den[2].data, 0);
    mpf_set_si(den[3].data, 0);
    for (i=0; i<4; i++) {
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }
    poly_mpf_div(num, den, 4, quo, rem);
    sc_mpf_t prod[8];
    for (i=0; i<8; i++) {
        mpf_init(prod[i].data);
    }
    poly_mpf_mul(prod, 4, den, quo);
    poly_mpf_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, equal(prod[i], num[i]));
    }
}
END_TEST

START_TEST(test_div_3)
{
    size_t i;
    sc_mpf_t num[128], den[128], quo[128], rem[256], prod[256];
    for (size_t i=0; i<128; i++) {
        mpf_init(num[i].data);
        mpf_init(den[i].data);
        mpf_init(quo[i].data);
    }
    for (size_t i=0; i<256; i++) {
        mpf_init(rem[i].data);
        mpf_init(prod[i].data);
    }
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    poly_mpf_reset(rem, 0, 256);

    for (int j=0; j<128; j++) {
        for (i=0; i<128; i++) {
            mpf_set_ui(num[i].data, prng_32(prng_ctx));
            mpf_set_ui(den[i].data, (i>=j)? prng_32(prng_ctx) : 0);
        }
        poly_mpf_div(num, den, 128, quo, rem);
        poly_mpf_mul(prod, 128, den, quo);
        poly_mpf_add(prod, 256, prod, rem);
        for (i=0; i<128; i++) {
            ck_assert_int_eq(1, equal(prod[i], num[i]));
        }
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gcd_single)
{
    sc_mpf_t a, b, tv_gcd, gcd;
    mpf_init(a.data);
    mpf_init(b.data);
    mpf_init(tv_gcd.data);
    mpf_init(gcd.data);
    mpf_set_si(a.data, 54);
    mpf_set_si(b.data, 24);
    mpf_set_si(tv_gcd.data, 6);
    SINT32 result = poly_mpf_gcd_single(a, b, &gcd);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    fprintf(stderr, "gcd = %f\n", mpf_get_d(gcd.data));
    ck_assert_int_eq(1, equal(tv_gcd, gcd));
}
END_TEST

START_TEST(test_gcd_0)
{
    size_t i;
    sc_mpf_t a[4], b[4], tv_gcd[4], gcd, temp[8*4], quo[4], rem[4];
    for (size_t i=0; i<4; i++) {
        mpf_init(a[i].data);
        mpf_init(b[i].data);
        mpf_init(tv_gcd[i].data);
    }
    mpf_set_si(a[0].data, 4);
    mpf_set_si(a[1].data, 8);
    mpf_set_si(a[2].data, 0);
    mpf_set_si(a[3].data, 8);
    mpf_set_si(b[0].data, 4);
    mpf_set_si(b[1].data, 0);
    mpf_set_si(b[2].data, 0);
    mpf_set_si(b[3].data, 0);
    mpf_set_si(tv_gcd[0].data, 4);
    mpf_set_si(tv_gcd[1].data, 0);
    mpf_set_si(tv_gcd[2].data, 0);
    mpf_set_si(tv_gcd[3].data, 0);
    mpf_init(gcd.data);
    for (i=0; i<8*4; i++) {
        mpf_init(temp[i].data);
    }
    for (i=0; i<4; i++) {
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }

    SINT32 result = poly_mpf_gcd(a, b, &gcd, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_mpf_div(a, b, 4, quo, rem);
    ck_assert_int_eq(1, equal(tv_gcd[0], gcd));
    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, mpf_dbl_equal(rem[i], 0.0));
    }
}
END_TEST

START_TEST(test_gcd_1)
{
    size_t i;
    const size_t n = 128;
    sc_mpf_t gcd[n], a[n], b[n], temp[8*n], quo[n], rem[n], prod[n];
    for (size_t i=0; i<n; i++) {
        mpf_init(gcd[i].data);
        mpf_init(a[i].data);
        mpf_init(b[i].data);
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }
    for (size_t i=0; i<8*n; i++) {
        mpf_init(temp[i].data);
    }
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_DEV_URANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    for (int j=0; j<32; j++) {
        for (i=0; i<n; i++) {
            mpf_set_ui(a[i].data, prng_32(prng_ctx));
            mpf_set_ui(b[i].data, (i>=j)? prng_32(prng_ctx) : 0);
        }
        poly_mpf_gcd(a, b, &gcd[0], temp, n);
        /*poly_mpf_div(a, gcd, n, quo, rem);
        for (i=0; i<n; i++) {
            ck_assert_int_eq(1, mpf_dbl_equal(rem[i], 0.0));
        }
        poly_mpf_div(b, gcd, n, quo, rem);
        for (i=0; i<n; i++) {
            ck_assert_int_eq(1, mpf_dbl_equal(rem[i], 0.0));
        }*/
    }

    prng_destroy(prng_ctx);
    for (size_t i=0; i<n; i++) {
        mpf_clear(gcd[i].data);
        mpf_clear(a[i].data);
        mpf_clear(b[i].data);
        mpf_clear(quo[i].data);
        mpf_clear(rem[i].data);
    }
    for (size_t i=0; i<8*n; i++) {
        mpf_clear(temp[i].data);
    }
}
END_TEST

START_TEST(test_gcd_2)
{
    size_t i;
    const size_t n = 513;
    DOUBLE f[n];
    sc_mpf_t a[n], b[n], tv_gcd[n], gcd[n], temp[8*n], quo[n], rem[n];
    for (size_t i=0; i<n; i++) {
        mpf_init(gcd[i].data);
        mpf_init(a[i].data);
        mpf_init(b[i].data);
        mpf_init(tv_gcd[i].data);
    }
    SC_MEMCOPY(f, test_f, sizeof(DOUBLE) * 512);
    poly_dbl_to_mpf(a, n-1, f);
    mpf_set_d(b[0].data, 1.0);
    mpf_set_d(b[n-1].data, 1.0);
    for (i=0; i<8*n; i++) {
        mpf_init(temp[i].data);
    }
    for (i=0; i<n; i++) {
        mpf_init(quo[i].data);
        mpf_init(rem[i].data);
    }

    SINT32 result = poly_mpf_gcd(a, b, &gcd[0], temp, n);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);

    poly_mpf_div(a, gcd, n-1, quo, rem);
    for (i=0; i<n; i++) {
        ck_assert_int_eq(1, mpf_dbl_equal(rem[i], 0.0));
    }

    poly_mpf_div(b, gcd, n, quo, rem);
    for (i=0; i<n; i++) {
        ck_assert_int_eq(1, mpf_dbl_equal(rem[i], 0.0));
    }
}
END_TEST

START_TEST(test_ext_euclidean_single)
{
    sc_mpf_t a, b, tv_x, tv_y, gcd, x, y, temp;
    mpf_init(a.data);
    mpf_init(b.data);
    mpf_init(tv_x.data);
    mpf_init(tv_y.data);
    mpf_init(gcd.data);
    mpf_init(x.data);
    mpf_init(y.data);
    mpf_init(temp.data);
    mpf_set_si(a.data, 54);
    mpf_set_si(b.data, 24);
    mpf_set_si(tv_x.data, 1);
    mpf_set_si(tv_y.data, -2);
    SINT32 result = poly_mpf_ext_euclidean_single(a, b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    DOUBLE prod = mpf_get_d(a.data)*mpf_get_d(x.data) +
                  mpf_get_d(b.data)*mpf_get_d(y.data);
    ck_assert_int_eq(1, mpf_dbl_equal(gcd, prod));
    ck_assert_int_eq(1, equal(tv_x, x));
    ck_assert_int_eq(1, equal(tv_y, y));
}
END_TEST

START_TEST(test_ext_euclidean_0)
{
    size_t i;
    sc_mpf_t a[4], b[4], gcd, temp[8*4], x[4], y[4], prod[8];
    for (i=0; i<4; i++) {
        mpf_init(a[i].data);
        mpf_init(b[i].data);
    }
    mpf_set_si(a[0].data, 4);
    mpf_set_si(a[1].data, 8);
    mpf_set_si(a[2].data, 0);
    mpf_set_si(a[3].data, 8);
    mpf_set_si(b[0].data, 4);
    mpf_set_si(b[1].data, 0);
    mpf_set_si(b[2].data, 0);
    mpf_set_si(b[3].data, 0);
    for (i=0; i<8*4; i++) {
        mpf_init(temp[i].data);
    }
    for (i=0; i<4; i++) {
        mpf_init(x[i].data);
        mpf_init(y[i].data);
    }
    for (i=0; i<8; i++) {
        mpf_init(prod[i].data);
    }
    mpf_init(gcd.data);

    SINT32 result = poly_mpf_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_mpf_mul(prod, 4, a, x);
    poly_mpf_mul(temp, 4, b, y);
    poly_mpf_add(prod, 8, prod, temp);
    ck_assert_int_eq(1, equal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_1)
{
    size_t i;
    sc_mpf_t a[4], b[4], gcd, temp[8*4], x[4], y[4], prod[8];
    for (i=0; i<4; i++) {
        mpf_init(a[i].data);
        mpf_init(b[i].data);
    }
    mpf_set_si(a[0].data, 54);
    mpf_set_si(a[1].data, 0);
    mpf_set_si(a[2].data, 1);
    mpf_set_si(a[3].data, 0);
    mpf_set_si(b[0].data, 24);
    mpf_set_si(b[1].data, 0);
    mpf_set_si(b[2].data, 0);
    mpf_set_si(b[3].data, 0);
    for (i=0; i<8*4; i++) {
        mpf_init(temp[i].data);
    }
    for (i=0; i<4; i++) {
        mpf_init(x[i].data);
        mpf_init(y[i].data);
    }
    for (i=0; i<8; i++) {
        mpf_init(prod[i].data);
    }
    mpf_init(gcd.data);

    SINT32 result = poly_mpf_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_mpf_mul(prod, 4, a, x);
    poly_mpf_mul(temp, 4, b, y);
    poly_mpf_add(prod, 8, prod, temp);
    ck_assert_int_eq(1, equal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_2)
{
    size_t i;
    sc_mpf_t a[4], b[4], gcd, temp[8*4], x[4], y[4], prod[8];
    for (i=0; i<4; i++) {
        mpf_init(a[i].data);
        mpf_init(b[i].data);
    }
    mpf_set_si(a[0].data, 8);
    mpf_set_si(a[1].data, 0);
    mpf_set_si(a[2].data, 0);
    mpf_set_si(a[3].data, 0x61437152);
    mpf_set_si(b[0].data, 7);
    mpf_set_si(b[1].data, 0);
    mpf_set_si(b[2].data, 0);
    mpf_set_si(b[3].data, 0);
    for (i=0; i<8*4; i++) {
        mpf_init(temp[i].data);
    }
    for (i=0; i<4; i++) {
        mpf_init(x[i].data);
        mpf_init(y[i].data);
    }
    for (i=0; i<8; i++) {
        mpf_init(prod[i].data);
    }
    mpf_init(gcd.data);

    SINT32 result = poly_mpf_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_mpf_mul(prod, 4, a, x);
    poly_mpf_mul(temp, 4, b, y);
    poly_mpf_add(prod, 8, prod, temp);
    ck_assert_int_eq(1, equal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_3)
{
    size_t i;
    sc_mpf_t a[8];
    sc_mpf_t b[8];
    sc_mpf_t factor[4], gcd, x[8], y[8];
    sc_mpf_t temp[8*8];
    sc_mpf_t prod[16];
    for (i=0; i<8; i++) {
        mpf_init(a[i].data);
        mpf_init(b[i].data);
        mpf_init(x[i].data);
        mpf_init(y[i].data);
    }
    for (i=0; i<4; i++) {
        mpf_init(factor[i].data);
    }
    for (i=0; i<8*8; i++) {
        mpf_init(temp[i].data);
    }
    for (i=0; i<16; i++) {
        mpf_init(prod[i].data);
    }
    mpf_init(gcd.data);

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_64(prng_ctx, 12, 3.33, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<4; i++) {
        mpf_set_d(temp[i].data, (DOUBLE)gaussian_cdf_sample_64(gauss));
        mpf_set_d(temp[4+i].data, (DOUBLE)gaussian_cdf_sample_64(gauss));
    }
    mpf_set_si(factor[0].data, 2);
    poly_mpf_mul(a, 4, temp, factor);
    poly_mpf_mul(b, 4, temp+4, factor);
    SINT32 result = poly_mpf_ext_euclidean(a, b, &gcd, x, y, temp, 8);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_mpf_mul(prod, 8, a, x);
    poly_mpf_mul(temp, 8, b, y);
    poly_mpf_add(prod, 16, prod, temp);

    ck_assert_int_eq(1, equal(prod[0], gcd));

    gaussian_cdf_destroy_64(&gauss);
    prng_destroy(prng_ctx);
}
END_TEST

Suite *poly_mpf_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly_mpf");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_dot_product);
    tcase_add_test(tc_core, test_modulus);
    tcase_add_test(tc_core, test_degree);
    tcase_add_test(tc_core, test_div_0);
    tcase_add_test(tc_core, test_div_1);
    tcase_add_test(tc_core, test_div_2);
    tcase_add_test(tc_core, test_div_3);
    tcase_add_test(tc_core, test_gcd_single);
    tcase_add_test(tc_core, test_gcd_0);
    tcase_add_test(tc_core, test_gcd_1);
    tcase_add_test(tc_core, test_gcd_2);
    tcase_add_test(tc_core, test_ext_euclidean_single);
    tcase_add_test(tc_core, test_ext_euclidean_0);
    tcase_add_test(tc_core, test_ext_euclidean_1);
    tcase_add_test(tc_core, test_ext_euclidean_2);
    tcase_add_test(tc_core, test_ext_euclidean_3);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = poly_mpf_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


