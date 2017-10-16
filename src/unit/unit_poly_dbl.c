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
#include "utils/arith/poly_dbl.c"
#include "utils/crypto/prng.c"
#include "utils/sampling/gaussian_cdf.c"

static const DOUBLE epsilon = 0.0001;

static SINT32 fequal(DOUBLE a, DOUBLE b)
{
    DOUBLE thresh = (a == 0 || b == 0)? epsilon :
                                        fmax(fabs(a),fabs(b)) * epsilon;
   return fabs(a-b) < thresh;
}


START_TEST(test_dot_product)
{
    DOUBLE poly[4] = {1, 2, 3, 4};
    DOUBLE value;
    value = poly_dbl_dot_product(NULL, 4);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_dbl_dot_product(poly, 0);
    ck_assert_int_eq(1, fequal(value, 0));
    value = poly_dbl_dot_product(poly, 4);
    ck_assert_int_eq(1, fequal(value, 30));
}
END_TEST

START_TEST(test_modulus)
{
    DOUBLE poly[4] = {1, 2, 3, 4};
    DOUBLE value;
    value = poly_dbl_modulus(NULL, 4);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_dbl_modulus(poly, 0);
    ck_assert_int_eq(1, fequal(value, 0));
    value = poly_dbl_modulus(poly, 4);
    ck_assert_int_eq(1, fequal(value, sqrt(30)));
}
END_TEST

START_TEST(test_degree)
{
    DOUBLE poly[4] = {1, 2, 3, 4};
    DOUBLE value;
    value = poly_dbl_degree(NULL, 4);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_dbl_degree(poly, 0);
    ck_assert_int_eq(1, fequal(value, -1));
    value = poly_dbl_degree(poly, 4);
    ck_assert_int_eq(1, fequal(value, 3));
}
END_TEST

START_TEST(test_div_0)
{
    size_t i;
    DOUBLE num[4] = {1, 2, 3, 4};
    DOUBLE den[4] = {2, 0, 0, 0};
    DOUBLE quo[4], rem[4];
    poly_dbl_div(num, den, 4, quo, rem);
    DOUBLE prod[8];
    poly_dbl_mul(prod, 4, den, quo);
    poly_dbl_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, prod[i] == num[i]);
    }
}
END_TEST

START_TEST(test_div_1)
{
    size_t i;
    DOUBLE num[4] = {1, 2, 3, 4};
    DOUBLE den[4] = {0, 0, 2, 0};
    DOUBLE quo[4], rem[4];
    poly_dbl_div(num, den, 4, quo, rem);
    DOUBLE prod[8];
    poly_dbl_mul(prod, 4, den, quo);
    poly_dbl_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(prod[i], num[i]);
    }
}
END_TEST

START_TEST(test_div_2)
{
    size_t i;
    DOUBLE num[4] = {1, 0, 0, 2};
    DOUBLE den[4] = {7, 0, 0, 0};
    DOUBLE quo[4], rem[4];
    poly_dbl_div(num, den, 4, quo, rem);
    DOUBLE prod[8];
    poly_dbl_mul(prod, 4, den, quo);
    poly_dbl_add(prod, 4, prod, rem);
    for (i=0; i<4; i++) {
        ck_assert_int_eq(prod[i], num[i]);
    }
}
END_TEST

START_TEST(test_div_3)
{
    size_t i;
    DOUBLE num[128];
    DOUBLE den[128];
    DOUBLE quo[128], rem[256];
    DOUBLE prod[256];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    poly_dbl_reset(rem, 0, 256);

    for (int j=0; j<128; j++) {
        for (i=0; i<128; i++) {
            num[i] = (DOUBLE)prng_32(prng_ctx);
            den[i] = (i>=j)? (DOUBLE)prng_32(prng_ctx) : 0;
        }
        fprintf(stderr, "num:\n");
        for (i=0; i<128; i++) {
            fprintf(stderr, "%12.0f", num[i]);
            if (7 == (i&7)) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "den:\n");
        for (i=0; i<128; i++) {
            fprintf(stderr, "%12.0f", den[i]);
            if (7 == (i&7)) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
        poly_dbl_div(num, den, 128, quo, rem);
        fprintf(stderr, "quo:\n");
        for (i=0; i<128; i++) {
            fprintf(stderr, "%12.0f", quo[i]);
            if (7 == (i&7)) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "rem:\n");
        for (i=0; i<128; i++) {
            fprintf(stderr, "%12.0f", rem[i]);
            if (7 == (i&7)) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");

        poly_dbl_mul(prod, 128, den, quo);
        fprintf(stderr, "den * quo:\n");
        for (i=0; i<256; i++) {
            fprintf(stderr, "%12.0f", prod[i]);
            if (7 == (i&7)) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");

        poly_dbl_add(prod, 256, prod, rem);
        fprintf(stderr, "prod:\n");
        for (i=0; i<128; i++) {
            fprintf(stderr, "%12.0f", prod[i]);
            if (7 == (i&7)) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "num:\n");
        for (i=0; i<128; i++) {
            fprintf(stderr, "%12.0f", num[i]);
            if (7 == (i&7)) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
        for (i=0; i<128; i++) {
            ck_assert_int_eq(1, fequal(prod[i], num[i]));
        }
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_gcd_single)
{
    DOUBLE a = 54;
    DOUBLE b = 24;
    DOUBLE tv_gcd = 6;
    DOUBLE gcd;
    DOUBLE result = poly_dbl_gcd_single(a, b, &gcd);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    ck_assert_int_eq(1, fequal(tv_gcd, gcd));
}
END_TEST

START_TEST(test_gcd)
{
    DOUBLE a[4] = {4, 8, 0, 8};
    DOUBLE b[4] = {4, 0, 0, 0};
    DOUBLE tv_gcd[4] = {4, 0, 0, 0};
    DOUBLE gcd;
    DOUBLE temp[8*4];
    DOUBLE quo[4], rem[4];
    DOUBLE result = poly_dbl_gcd(a, b, &gcd, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_dbl_div(a, b, 4, quo, rem);
    ck_assert_int_eq(1, fequal(tv_gcd[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_single)
{
    DOUBLE a = 54;
    DOUBLE b = 24;
    DOUBLE tv_x = 1;
    DOUBLE tv_y = -2;
    DOUBLE gcd, x, y;
    DOUBLE prod;
    DOUBLE result = poly_dbl_ext_euclidean_single(a, b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    prod = a*x + b*y;
    ck_assert_int_eq(1, fequal(prod, gcd));
    ck_assert_int_eq(1, fequal(tv_x, x));
    ck_assert_int_eq(1, fequal(tv_y, y));
}
END_TEST

START_TEST(test_ext_euclidean_0)
{
    DOUBLE a[4] = {4, 8, 0, 8};
    DOUBLE b[4] = {4, 0, 0, 0};
    DOUBLE gcd, x[4], y[4];
    DOUBLE temp[8*4];
    DOUBLE prod[8];
    DOUBLE result = poly_dbl_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_dbl_mul(prod, 4, a, x);
    poly_dbl_mul(temp, 4, b, y);
    poly_dbl_add(prod, 8, prod, temp);
    ck_assert_int_eq(1, fequal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_1)
{
    DOUBLE a[4] = {54, 0, 1, 0};
    DOUBLE b[4] = {24, 0, 0, 0};
    DOUBLE gcd, x[4], y[4];
    DOUBLE temp[8*4];
    DOUBLE prod[8];
    DOUBLE result = poly_dbl_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_dbl_mul(prod, 4, a, x);
    poly_dbl_mul(temp, 4, b, y);
    poly_dbl_add(prod, 8, prod, temp);
    ck_assert_int_eq(1, fequal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_2)
{
    DOUBLE a[4] = {8, 0, 0, 0x61437152};
    DOUBLE b[4] = {7, 0, 0, 0};
    DOUBLE gcd, x[4], y[4];
    DOUBLE temp[8*4];
    DOUBLE prod[8];
    DOUBLE result = poly_dbl_ext_euclidean(a, b, &gcd, x, y, temp, 4);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_dbl_mul(prod, 4, a, x);
    poly_dbl_mul(temp, 4, b, y);
    poly_dbl_add(prod, 8, prod, temp);
    ck_assert_int_eq(1, fequal(prod[0], gcd));
}
END_TEST

START_TEST(test_ext_euclidean_3)
{
    size_t i;
    DOUBLE a[8];
    DOUBLE b[8];
    DOUBLE factor[4], gcd, x[8], y[8];
    DOUBLE temp[8*8];
    DOUBLE prod[16];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    void *gauss = gaussian_cdf_create_64(prng_ctx, 12, 3.33, NORMAL_SAMPLES);
    ck_assert_ptr_ne(gauss, NULL);

    for (i=0; i<4; i++) {
        factor[i] = 0;
        temp[i]   = (DOUBLE)gaussian_cdf_sample_64(gauss);
        temp[4+i] = (DOUBLE)gaussian_cdf_sample_64(gauss);
    }
    factor[0] = 2;
    poly_dbl_mul(a, 4, temp, factor);
    poly_dbl_mul(b, 4, temp+4, factor);
    DOUBLE result = poly_dbl_ext_euclidean(a, b, &gcd, x, y, temp, 8);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    poly_dbl_mul(prod, 8, a, x);
    poly_dbl_mul(temp, 8, b, y);
    poly_dbl_add(prod, 16, prod, temp);

    ck_assert_int_eq(1, fequal(prod[0], gcd));

    gaussian_cdf_destroy_64(&gauss);
    prng_destroy(prng_ctx);
}
END_TEST

Suite *poly32_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly_dbl");

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


