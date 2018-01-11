/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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
#include "utils/ecc/ecc.c"

START_TEST(test_ecc_bad_double)
{
}
END_TEST

START_TEST(test_ecc_bad_add)
{
}
END_TEST

START_TEST(test_ecc_double_add_basic)
{
}
END_TEST

Suite *entropy_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ECC");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_ecc_bad_double);
    tcase_add_test(tc_core, test_ecc_bad_add);
    tcase_add_test(tc_core, test_ecc_double_add_basic);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = entropy_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


