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
#include "utils/arith/poly_16.c"
#include "utils/crypto/prng.c"

START_TEST(test_scalar_add)
{
    SINT16 a[8] = {0, 1, 2, 3, 0x7FFC, 0x7FFD, 0x7FFE, 0x7FFF};
    poly_16_add_scalar(a, 8, 1);
    ck_assert_int_eq(a[0], 1);
    ck_assert_int_eq(a[1], 1);
    ck_assert_int_eq(a[2], 2);
    ck_assert_int_eq(a[3], 3);
    ck_assert_int_eq(a[4], 0x7FFC);
    ck_assert_int_eq(a[5], 0x7FFD);
    ck_assert_int_eq(a[6], 0x7FFE);
    ck_assert_int_eq(a[7], 0x7FFF);

    poly_16_add_scalar(a, 8, 32767);
    ck_assert_int_eq(a[0], -32768);

    poly_16_add_scalar(a, 8, 1);
    ck_assert_int_eq(a[0], -32767);
}
END_TEST

START_TEST(test_scalar_sub)
{
    SINT16 a[8] = {0, 1, 2, 3, 0x7FFC, 0x7FFD, 0x7FFE, 0x7FFF};
    poly_16_sub_scalar(a, 8, 1);
    ck_assert_int_eq(a[0], -1);
    ck_assert_int_eq(a[1], 1);
    ck_assert_int_eq(a[2], 2);
    ck_assert_int_eq(a[3], 3);
    ck_assert_int_eq(a[4], 0x7FFC);
    ck_assert_int_eq(a[5], 0x7FFD);
    ck_assert_int_eq(a[6], 0x7FFE);
    ck_assert_int_eq(a[7], 0x7FFF);

    poly_16_sub_scalar(a, 8, 32767);
    ck_assert_int_eq(a[0], -32768);

    poly_16_sub_scalar(a, 8, 1);
    ck_assert_int_eq(a[0], 32767);
}
END_TEST

START_TEST(test_scalar_mul)
{
    SINT16 a[8] = {0, 1, 2, 3, 0x7FFC, 0x7FFD, 0x7FFE, 0x7FFF};
    poly_16_mul_scalar(a, 8, 0);
    ck_assert_int_eq(a[0], 0);
    ck_assert_int_eq(a[1], 0);
    ck_assert_int_eq(a[2], 0);
    ck_assert_int_eq(a[3], 0);
    ck_assert_int_eq(a[4], 0);
    ck_assert_int_eq(a[5], 0);
    ck_assert_int_eq(a[6], 0);
    ck_assert_int_eq(a[7], 0);

    SINT16 b[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    poly_16_mul_scalar(b, 8, 1);
    ck_assert_int_eq(b[0], 0);
    ck_assert_int_eq(b[1], 1);
    ck_assert_int_eq(b[2], 2);
    ck_assert_int_eq(b[3], 3);
    ck_assert_int_eq(b[4], 4);
    ck_assert_int_eq(b[5], 5);
    ck_assert_int_eq(b[6], 6);
    ck_assert_int_eq(b[7], 7);

    poly_16_mul_scalar(b, 8, 2);
    ck_assert_int_eq(b[0], 0);
    ck_assert_int_eq(b[1], 2);
    ck_assert_int_eq(b[2], 4);
    ck_assert_int_eq(b[3], 6);
    ck_assert_int_eq(b[4], 8);
    ck_assert_int_eq(b[5], 10);
    ck_assert_int_eq(b[6], 12);
    ck_assert_int_eq(b[7], 14);

    SINT16 c[8] = {1, 0, 0, 0, 0, 0, 0x4000, 0x8000};
    poly_16_mul_scalar(c, 8, 2);
    ck_assert_int_eq(c[0], 2);
    ck_assert_int_eq(c[1], 0);
    ck_assert_int_eq(c[2], 0);
    ck_assert_int_eq(c[3], 0);
    ck_assert_int_eq(c[4], 0);
    ck_assert_int_eq(c[5], 0);
    ck_assert_int_eq(c[6], -32768);
    ck_assert_int_eq(c[7], 0);
}
END_TEST

START_TEST(test_add)
{
    SINT16 a[8] = {0, 1, 2, 3, 32764, 32765, 32766, 32767};
    SINT16 b[8] = {-1, -1, -1, -1, 1, 1, 1, 1};
    SINT16 c[8];
    poly_16_add(c, 8, a, b);
    ck_assert_int_eq(c[0], -1);
    ck_assert_int_eq(c[1], 0);
    ck_assert_int_eq(c[2], 1);
    ck_assert_int_eq(c[3], 2);
    ck_assert_int_eq(c[4], 32765);
    ck_assert_int_eq(c[5], 32766);
    ck_assert_int_eq(c[6], 32767);
    ck_assert_int_eq(c[7], -32768);
}
END_TEST

START_TEST(test_sub)
{
    SINT16 a[8] = {0, 1, 2, 3, 32764, 32765, 32766, 32767};
    SINT16 b[8] = {-1, -1, -1, -1, 1, 1, 1, 1};
    SINT16 c[8];
    poly_16_sub(c, 8, a, b);
    ck_assert_int_eq(c[0], 1);
    ck_assert_int_eq(c[1], 2);
    ck_assert_int_eq(c[2], 3);
    ck_assert_int_eq(c[3], 4);
    ck_assert_int_eq(c[4], 32763);
    ck_assert_int_eq(c[5], 32764);
    ck_assert_int_eq(c[6], 32765);
    ck_assert_int_eq(c[7], 32766);
}
END_TEST

START_TEST(test_add_single)
{
    SINT16 a[8] = {0, 1, 2, 3, 32764, 32765, 32766, 32767};
    SINT16 b[8] = {-1, -1, -1, -1, 1, 1, 1, 1};
    poly_16_add_single(a, 8, b);
    ck_assert_int_eq(a[0], -1);
    ck_assert_int_eq(a[1], 0);
    ck_assert_int_eq(a[2], 1);
    ck_assert_int_eq(a[3], 2);
    ck_assert_int_eq(a[4], 32765);
    ck_assert_int_eq(a[5], 32766);
    ck_assert_int_eq(a[6], 32767);
    ck_assert_int_eq(a[7], -32768);
}
END_TEST

START_TEST(test_sub_single)
{
    SINT16 a[8] = {0, 1, 2, 3, 32764, 32765, 32766, 32767};
    SINT16 b[8] = {-1, -1, -1, -1, 1, 1, 1, 1};
    poly_16_sub_single(a, 8, b);
    ck_assert_int_eq(a[0], 1);
    ck_assert_int_eq(a[1], 2);
    ck_assert_int_eq(a[2], 3);
    ck_assert_int_eq(a[3], 4);
    ck_assert_int_eq(a[4], 32763);
    ck_assert_int_eq(a[5], 32764);
    ck_assert_int_eq(a[6], 32765);
    ck_assert_int_eq(a[7], 32766);
}
END_TEST

START_TEST(test_mul)
{
    SINT16 a[8] = {0, 0, 0, 0x2000, 0, 0, 0, 0};
    SINT16 b[8] = {2, 0, 0, 0, 0, 0, 0, 0};
    SINT16 c[15];
    poly_16_mul(c, 8, a, b);
    ck_assert_int_eq(c[0], 0);
    ck_assert_int_eq(c[1], 0);
    ck_assert_int_eq(c[2], 0);
    ck_assert_int_eq(c[3], 0x4000);
    ck_assert_int_eq(c[4], 0);
    ck_assert_int_eq(c[5], 0);
    ck_assert_int_eq(c[6], 0);
    ck_assert_int_eq(c[7], 0);
    ck_assert_int_eq(c[8], 0);
    ck_assert_int_eq(c[9], 0);
    ck_assert_int_eq(c[10], 0);
    ck_assert_int_eq(c[11], 0);
    ck_assert_int_eq(c[12], 0);
    ck_assert_int_eq(c[13], 0);
    ck_assert_int_eq(c[14], 0);
}
END_TEST

START_TEST(test_mul_2)
{
    SINT16 a[4] = {0, 0, 0, 0x2000};
    SINT16 b[4] = {1, 0, 0, 2};
    SINT16 c[7];
    poly_16_mul(c, 4, a, b);
    ck_assert_int_eq(c[0], 0);
    ck_assert_int_eq(c[1], 0);
    ck_assert_int_eq(c[2], 0);
    ck_assert_int_eq(c[3], 0x2000);
    ck_assert_int_eq(c[4], 0);
    ck_assert_int_eq(c[5], 0);
    ck_assert_int_eq(c[6], 0x4000);
}
END_TEST

START_TEST(test_uniform)
{
    size_t i;
    const UINT16 c[9] = {1, 2, 3, 4, 5, 6, 7, 8, 28};
    SINT16 a[64];

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    poly_16_uniform_rand(prng_ctx, a, 64, c, 8);
    SINT16 bins[9] = {0};
    for (i=0; i<64; i++) {
        SINT16 value = (a[i] < 0)? -a[i] : a[i];
        bins[value]++;
    }
    ck_assert_int_eq(bins[0], c[8]);
    ck_assert_int_eq(bins[1], c[7]);
    ck_assert_int_eq(bins[2], c[6]);
    ck_assert_int_eq(bins[3], c[5]);
    ck_assert_int_eq(bins[4], c[4]);
    ck_assert_int_eq(bins[5], c[3]);
    ck_assert_int_eq(bins[6], c[2]);
    ck_assert_int_eq(bins[7], c[1]);
    ck_assert_int_eq(bins[8], c[0]);

    prng_destroy(prng_ctx);
}
END_TEST

Suite *poly16_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly16");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_scalar_add);
    tcase_add_test(tc_core, test_scalar_sub);
    tcase_add_test(tc_core, test_scalar_mul);
    tcase_add_test(tc_core, test_add);
    tcase_add_test(tc_core, test_sub);
    tcase_add_test(tc_core, test_add_single);
    tcase_add_test(tc_core, test_sub_single);
    tcase_add_test(tc_core, test_mul);
    tcase_add_test(tc_core, test_mul_2);
    tcase_add_test(tc_core, test_uniform);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = poly16_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


