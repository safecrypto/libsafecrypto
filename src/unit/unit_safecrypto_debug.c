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
#include "safecrypto_debug.h"

#ifdef DEBUG

START_TEST(test_safecrypto_debug_get)
{
    UINT32 flags[1] = {0};
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_debug_level_e level = sc_get_verbosity(sc);
    ck_assert_int_ge(level, SC_LEVEL_NONE);
    ck_assert_int_le(level, SC_LEVEL_DEBUG);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_debug_set_none)
{
	int32_t sc_retcode;
    UINT32 flags[1] = {0};

	sc_debug_level_e level;
	safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_retcode = sc_set_verbosity(sc, SC_LEVEL_NONE);
    ck_assert_int_eq(sc_retcode, SC_FUNC_SUCCESS);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_NONE);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_debug_set_error)
{
	int32_t sc_retcode;
    UINT32 flags[1] = {0};
	sc_debug_level_e level;
	safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_retcode = sc_set_verbosity(sc, SC_LEVEL_ERROR);
    ck_assert_int_eq(sc_retcode, SC_FUNC_SUCCESS);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_ERROR);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_debug_set_warning)
{
	int32_t sc_retcode;
	sc_debug_level_e level;
	safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_retcode = sc_set_verbosity(sc, SC_LEVEL_WARNING);
    ck_assert_int_eq(sc_retcode, SC_FUNC_SUCCESS);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_WARNING);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_debug_set_info)
{
	int32_t sc_retcode;
	sc_debug_level_e level;
	safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_retcode = sc_set_verbosity(sc, SC_LEVEL_INFO);
    ck_assert_int_eq(sc_retcode, SC_FUNC_SUCCESS);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_INFO);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_debug_set_debug)
{
	int32_t sc_retcode;
	sc_debug_level_e level;
	safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_retcode = sc_set_verbosity(sc, SC_LEVEL_DEBUG);
    ck_assert_int_eq(sc_retcode, SC_FUNC_SUCCESS);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_DEBUG);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_debug_set_bad_negative)
{
	int32_t sc_retcode;
	sc_debug_level_e level;
	safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_retcode = sc_set_verbosity(sc, SC_LEVEL_INFO);
    ck_assert_int_eq(sc_retcode, SC_FUNC_SUCCESS);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_INFO);

    sc_retcode = sc_set_verbosity(sc, -1);
    ck_assert_int_eq(sc_retcode, SC_FUNC_FAILURE);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_INFO);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_debug_set_bad_positive)
{
	int32_t sc_retcode;
	sc_debug_level_e level;
	safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_retcode = sc_set_verbosity(sc, SC_LEVEL_WARNING);
    ck_assert_int_eq(sc_retcode, SC_FUNC_SUCCESS);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_WARNING);

    sc_retcode = sc_set_verbosity(sc, 5);
    ck_assert_int_eq(sc_retcode, SC_FUNC_FAILURE);
    level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_WARNING);

    safecrypto_destroy(sc);
}
END_TEST

Suite * safecrypto_debug_suite(void)
{
    Suite *s;
    TCase *tc_get, *tc_set_error, *tc_set_warning, *tc_set_info,
          *tc_set_debug, *tc_set_none,
          *tc_set_bad1, *tc_set_bad2;

    s = suite_create("safecrypto_debug");

    /* Test cases */
    tc_get = tcase_create("GET");
    tcase_add_test(tc_get, test_safecrypto_debug_get);
    suite_add_tcase(s, tc_get);

    tc_set_error = tcase_create("SET ERROR");
    tcase_add_test(tc_set_error, test_safecrypto_debug_set_error);
    suite_add_tcase(s, tc_set_error);

    tc_set_warning = tcase_create("SET WARNING");
    tcase_add_test(tc_set_warning, test_safecrypto_debug_set_warning);
    suite_add_tcase(s, tc_set_warning);

    tc_set_info = tcase_create("SET INFO");
    tcase_add_test(tc_set_info, test_safecrypto_debug_set_info);
    suite_add_tcase(s, tc_set_info);

    tc_set_debug = tcase_create("SET DEBUG");
    tcase_add_test(tc_set_debug, test_safecrypto_debug_set_debug);
    suite_add_tcase(s, tc_set_debug);

    tc_set_none = tcase_create("SET NONE");
    tcase_add_test(tc_set_none, test_safecrypto_debug_set_none);
    suite_add_tcase(s, tc_set_none);

    tc_set_bad1 = tcase_create("SET NEGATIVE UNKNOWN");
    tcase_add_test(tc_set_bad1, test_safecrypto_debug_set_bad_negative);
    suite_add_tcase(s, tc_set_bad1);

    tc_set_bad2 = tcase_create("SET POSITIVE UNKNOWN");
    tcase_add_test(tc_set_bad2, test_safecrypto_debug_set_bad_positive);
    suite_add_tcase(s, tc_set_bad2);

    return s;
}

#else

START_TEST(test_safecrypto_debug_get)
{
	safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    sc_debug_level_e level = sc_get_verbosity(sc);
    ck_assert_int_eq(level, SC_LEVEL_NONE);

    safecrypto_destroy(sc);
}
END_TEST

Suite * safecrypto_debug_suite(void)
{
	Suite *s;
    TCase *tc_get;

    s = suite_create("safecrypto_debug");

    /* Test cases */
    tc_get = tcase_create("GET");
    tcase_add_test(tc_get, test_safecrypto_debug_get);
    suite_add_tcase(s, tc_get);

    return s;
}

#endif

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = safecrypto_debug_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

