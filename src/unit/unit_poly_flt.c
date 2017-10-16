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
#include "utils/arith/poly_flt.c"
#include "utils/crypto/prng.c"
#include "utils/sampling/gaussian_cdf.c"

static const FLOAT epsilon = 0.001;

static SINT32 fequal(FLOAT a, FLOAT b)
{
    FLOAT thresh = (a == 0 || b == 0)? epsilon :
                                       fmaxf(fabsf(a),fabsf(b)) * epsilon;
    return fabsf(a-b) < thresh;
}


START_TEST(test_dot_product)
{
    FLOAT poly[4] = {1, 2, 3, 4};
    FLOAT value;
    value = poly_flt_dot_product(NULL, 4);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_flt_dot_product(poly, 0);
    ck_assert_int_eq(1, fequal(value, 0));
    value = poly_flt_dot_product(poly, 4);
    ck_assert_int_eq(1, fequal(value, 30));
}
END_TEST

START_TEST(test_modulus)
{
    FLOAT poly[4] = {1, 2, 3, 4};
    FLOAT value;
    value = poly_flt_modulus(NULL, 4);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_flt_modulus(poly, 0);
    ck_assert_int_eq(1, fequal(value, 0));
    value = poly_flt_modulus(poly, 4);
    ck_assert_int_eq(1, fequal(value, sqrt(30)));
}
END_TEST

START_TEST(test_degree)
{
    FLOAT poly[4] = {1, 2, 3, 4};
    FLOAT value;
    value = poly_flt_degree(NULL, 4);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_flt_degree(poly, 0);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_flt_degree(poly, 4);
    ck_assert_int_eq(1, fequal(value, 3));
}
END_TEST

START_TEST(test_div_0)
{
    const size_t N = 4;
    size_t i;
    FLOAT num[4] = {1, 2, 3, 4};
    FLOAT den[4] = {2, 0, 0, 0};
    FLOAT quo[4], rem[4];
    poly_flt_div(num, den, 4, quo, rem);
    FLOAT prod[7];
    poly_flt_mul(prod, 4, den, quo);
    poly_flt_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, prod[i] == num[i]);
    }
}
END_TEST

START_TEST(test_div_1)
{
    size_t i;
    FLOAT num[4] = {1, 2, 3, 4};
    FLOAT den[4] = {0, 0, 2, 0};
    FLOAT quo[4], rem[4];
    poly_flt_div(num, den, 4, quo, rem);
    FLOAT prod[7];
    poly_flt_mul(prod, 4, den, quo);
    poly_flt_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(prod[i], num[i]);
    }
}
END_TEST

START_TEST(test_div_2)
{
    size_t i;
    FLOAT num[4] = {1, 0, 0, 2};
    FLOAT den[4] = {7, 0, 0, 0};
    FLOAT tv_quo[4] = {1, 2, 0, 0};
    FLOAT tv_rem[4] = {1, 2, 1, 0};
    FLOAT quo[4], rem[4];
    poly_flt_div(num, den, 4, quo, rem);
    FLOAT prod[7];
    poly_flt_mul(prod, 4, den, quo);
    poly_flt_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(prod[i], num[i]);
    }
}
END_TEST

START_TEST(test_div_3)
{
    size_t i;
    FLOAT num[128];
    FLOAT den[128];
    FLOAT quo[128], rem[128];
    FLOAT prod[255];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    for (int j=0; j<128; j++) {
        for (i=0; i<128; i++) {
            num[i] = (FLOAT)prng_32(prng_ctx);
            den[i] = (i<=j)? (FLOAT)prng_32(prng_ctx) : 0;
        }
        poly_flt_div(num, den, 128, quo, rem);
        poly_flt_mul(prod, 128, den, quo);
        poly_flt_add(prod, 128, prod, rem);
        for (i=0; i<128; i++) {
            ck_assert_int_eq(prod[i], num[i]);
        }
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gcd_single)
{
    size_t i;
    FLOAT a = 54;
    FLOAT b = 24;
    FLOAT tv_gcd = 6;
    FLOAT gcd;
    FLOAT result = poly_flt_gcd_single(a, b, &gcd);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    ck_assert_int_eq(1, fequal(6.0, gcd));
}
END_TEST

START_TEST(test_gcd)
{
    size_t i;
    FLOAT a[4] = {4, 8, 0, 8};
    FLOAT b[4] = {4, 0, 0, 0};
    FLOAT tv_gcd[4] = {4, 0, 0, 0};
    FLOAT tv_x[4] = {1, 0, 1, 0};
    FLOAT tv_y[4] = {1, 0, 1, 0};
    FLOAT gcd;
    FLOAT temp[8*4];
    FLOAT prod[8];
    FLOAT quo[4], rem[4];
    FLOAT result = poly_flt_gcd(a, b, &gcd, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_flt_div(a, b, 4, quo, rem);
    ck_assert_int_eq(1, fequal(tv_gcd[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_single)
{
    size_t i;
    FLOAT a = 54;
    FLOAT b = 24;
    FLOAT tv_gcd = 6;
    FLOAT tv_x = 1;
    FLOAT tv_y = -2;
    FLOAT gcd, x, y;
    FLOAT prod;
    FLOAT result = poly_flt_ext_euclidean_single(a, b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    prod = a*x + b*y;
    ck_assert_int_eq(1, fequal(prod, gcd));
    ck_assert_int_eq(1, fequal(tv_x, x));
    ck_assert_int_eq(1, fequal(tv_y, y));
}
END_TEST

START_TEST(test_ext_euclidean_0)
{
    size_t i;
    FLOAT a[4] = {4, 8, 0, 8};
    FLOAT b[4] = {4, 0, 0, 0};
    FLOAT tv_gcd[4] = {4, 0, 0, 0};
    FLOAT tv_x[4] = {1, 0, 1, 0};
    FLOAT tv_y[4] = {1, 0, 1, 0};
    FLOAT gcd, x[4], y[4];
    FLOAT temp[8*4];
    FLOAT prod[7];
    FLOAT result = poly_flt_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_flt_mul(prod, 4, a, x);
    poly_flt_mul(temp, 4, b, y);
    poly_flt_add(prod, 7, prod, temp);
    ck_assert_int_eq(1, fequal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_1)
{
    size_t i;
    FLOAT a[4] = {54, 0, 0, 0};
    FLOAT b[4] = {24, 0, 0, 0};
    FLOAT gcd, x[4], y[4];
    FLOAT temp[8*4];
    FLOAT prod[7];
    FLOAT result = poly_flt_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_flt_mul(prod, 4, a, x);
    poly_flt_mul(temp, 4, b, y);
    poly_flt_add(prod, 7, prod, temp);
    ck_assert_int_eq(1, fequal(6, gcd));
    ck_assert_int_eq(1, fequal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_2)
{
    size_t i;
    FLOAT a[4] = {8, 0, 0, 0x61437152};
    FLOAT b[4] = {7, 0, 0, 0};
    FLOAT gcd, x[4], y[4];
    FLOAT temp[8*4];
    FLOAT prod[7];
    FLOAT result = poly_flt_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_flt_mul(prod, 4, a, x);
    poly_flt_mul(temp, 4, b, y);
    poly_flt_add(prod, 7, prod, temp);
    ck_assert_int_eq(1, fequal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_3)
{
    size_t i;
    FLOAT a[8];
    FLOAT b[8];
    FLOAT factor[4], gcd, x[8], y[8];
    FLOAT temp[8*8];
    FLOAT prod[15];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_64(prng_ctx, 12, 3.33, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<4; i++) {
        factor[i] = 0;
        temp[i]   = (float)gaussian_cdf_sample_64(gauss);
        temp[4+i] = (float)gaussian_cdf_sample_64(gauss);
    }
    factor[0] = 2;
    poly_flt_mul(a, 4, temp, factor);
    poly_flt_mul(b, 4, temp+4, factor);
    FLOAT result = poly_flt_ext_euclidean(a, b, &gcd, x, y, temp, 8);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_flt_mul(prod, 8, a, x);
    poly_flt_mul(temp, 8, b, y);
    poly_flt_add(prod, 15, prod, temp);

    ck_assert_int_eq(1, fequal(prod[0], gcd));

    gaussian_cdf_destroy_64(&gauss);
    prng_destroy(prng_ctx);
}
END_TEST

Suite *poly32_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly_flt");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_dot_product);
    tcase_add_test(tc_core, test_modulus);
    tcase_add_test(tc_core, test_degree);
    tcase_add_test(tc_core, test_div_0);
    tcase_add_test(tc_core, test_div_1);
    tcase_add_test(tc_core, test_div_2);
    tcase_add_test(tc_core, test_gcd_single);
    tcase_add_test(tc_core, test_gcd);
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

    s = poly32_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


