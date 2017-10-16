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
#include "utils/arith/vectors.c"


START_TEST(test_vec_absmax)
{
    size_t i;
    SINT32 v[1024];
    for (i=0; i<1024; i++) {
        v[i] = 0;
    }
    SINT32 absmax = vecabsmax_32(v, 1024);
    ck_assert_int_eq(absmax, 0);

    v[1023] = 1;
    absmax = vecabsmax_32(v, 1024);
    ck_assert_int_eq(absmax, 1);
}
END_TEST

START_TEST(test_vec_absmax_2)
{
    SINT32 absmax = vecabsmax_32(NULL, 1024);
    ck_assert_int_eq(absmax, 0);
}
END_TEST

START_TEST(test_vec_absmax_3)
{
    size_t i;
    SINT32 v[32768];
    for (i=0; i<32768; i++) {
        v[i] = i;
    }
    SINT32 absmax = vecabsmax_32(v, 32768);
    ck_assert_int_eq(absmax, 32767);
}
END_TEST

START_TEST(test_vec_scalar_product)
{
    size_t i;
    SINT32 t[128], u[128], sum = 0;
    for (i=0; i<128; i++) {
        t[i] = i;
        u[i] = i;
        sum += i * i;
    }
    SINT32 product = vecscalar_32(t, u, 128);
    ck_assert_int_eq(product, sum);

    sum = 0;
    for (i=0; i<128; i++) {
        t[i] = i;
        u[i] = -i;
        sum += -i * i;
    }
    product = vecscalar_32(t, u, 128);
    ck_assert_int_eq(product, sum);
}
END_TEST

START_TEST(test_vec_scalar_product_2)
{
    size_t i;
    SINT32 t[128], u[128], sum = 0;
    for (i=0; i<128; i++) {
        t[i] = i;
        u[i] = i;
        sum += i * i;
    }
    SINT32 product = vecscalar_32(NULL, u, 128);
    ck_assert_int_eq(product, 0);

    product = vecscalar_32(t, NULL, 128);
    ck_assert_int_eq(product, 0);

    product = vecscalar_32(NULL, NULL, 128);
    ck_assert_int_eq(product, 0);

    product = vecscalar_32(t, u, 128);
    ck_assert_int_eq(product, sum);
}
END_TEST


Suite *vectors_suite(void)
{
    Suite *s;
    TCase *tc_absmax, *tc_scalar;

    s = suite_create("vectors");

    /* Test cases */
    tc_absmax = tcase_create("ABSMAX");
    tcase_add_test(tc_absmax, test_vec_absmax);
    tcase_add_test(tc_absmax, test_vec_absmax_2);
    tcase_add_test(tc_absmax, test_vec_absmax_3);
    suite_add_tcase(s, tc_absmax);

    tc_scalar = tcase_create("SCALAR_PRODUCT");
    tcase_add_test(tc_scalar, test_vec_scalar_product);
    tcase_add_test(tc_scalar, test_vec_scalar_product_2);
    suite_add_tcase(s, tc_scalar);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = vectors_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


