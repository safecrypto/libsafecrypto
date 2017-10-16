/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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
#include "utils/arith/gpv.c"

START_TEST(test_gpv_1)
{
    SINT32 retval;
    SINT32 g[2] = {0, 1}, f[2] = {2, 3}, G[2] = {4, 5}, F[2] = {6, 7};
    gpv_t gpv;
    gpv.g = g;
    gpv.f = f;
    gpv.G = G;
    gpv.F = F;
    gpv.n = 2;
    retval = gpv_read_basis(&gpv, 0, 0);
    ck_assert_int_eq(retval, 0);
    retval = gpv_read_basis(&gpv, 0, 1);
    ck_assert_int_eq(retval, 1);
    retval = gpv_read_basis(&gpv, 0, 2);
    ck_assert_int_eq(retval, -2);
    retval = gpv_read_basis(&gpv, 0, 3);
    ck_assert_int_eq(retval, -3);
    retval = gpv_read_basis(&gpv, 1, 0);
    ck_assert_int_eq(retval, -1);
    retval = gpv_read_basis(&gpv, 1, 1);
    ck_assert_int_eq(retval, 0);
    retval = gpv_read_basis(&gpv, 1, 2);
    ck_assert_int_eq(retval, 3);
    retval = gpv_read_basis(&gpv, 1, 3);
    ck_assert_int_eq(retval, -2);
    retval = gpv_read_basis(&gpv, 2, 0);
    ck_assert_int_eq(retval, 4);
    retval = gpv_read_basis(&gpv, 2, 1);
    ck_assert_int_eq(retval, 5);
    retval = gpv_read_basis(&gpv, 2, 2);
    ck_assert_int_eq(retval, -6);
    retval = gpv_read_basis(&gpv, 2, 3);
    ck_assert_int_eq(retval, -7);
    retval = gpv_read_basis(&gpv, 3, 0);
    ck_assert_int_eq(retval, -5);
    retval = gpv_read_basis(&gpv, 3, 1);
    ck_assert_int_eq(retval, 4);
    retval = gpv_read_basis(&gpv, 3, 2);
    ck_assert_int_eq(retval, 7);
    retval = gpv_read_basis(&gpv, 3, 3);
    ck_assert_int_eq(retval, -6);
}
END_TEST

Suite *gpv_static_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("gpv");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_gpv_1);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = gpv_static_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


