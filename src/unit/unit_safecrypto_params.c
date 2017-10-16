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
#include "safecrypto_params.h"


START_TEST(test_safecrypto_params_init)
{
	safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    ck_assert_ptr_eq(NULL, sc->params);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_get_empty)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "Param Name", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_FAILURE, retcode);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_get_bad)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    retcode = params_get(NULL, SC_SCHEME_SIG_HELLO_WORLD, "Param Name", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_FAILURE, retcode);

    retcode = params_get(sc, NULL, "Param Name", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_FAILURE, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, NULL, &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_FAILURE, retcode);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_add)
{
    int32_t retcode;
    sc_param_type_e type = SC_PARAM_UINT32;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    value.u32 = 0xDEADBEEF;

    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT32, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xDEADBEEF, value.u32);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_add_multiple)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    type = SC_PARAM_UINT32;
    value.u32 = 0xDEADBEEF;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    type = SC_PARAM_UINT16;
    value.u32 = 0xDEBE;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "A very long name for a parameter", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    type = SC_PARAM_UINT8;
    value.u32 = 0xDB;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "a", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT32, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xDEADBEEF, value.u32);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "A very long name for a parameter", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT16, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xDEBE, value.u32);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "a", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT8, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xDB, value.u32);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_add_all)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    type = SC_PARAM_UINT8;
    value.u8 = 0xFF;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "u8", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    type = SC_PARAM_UINT16;
    value.u16 = 0xFFFF;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "u16", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    type = SC_PARAM_UINT32;
    value.u32 = 0xFFFFFFFF;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "u32", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    type = SC_PARAM_INT8;
    value.i8 = -128;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "i8", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    type = SC_PARAM_INT16;
    value.i16 = -32768;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "i16", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    type = SC_PARAM_INT32;
    value.i32 = -2147483648;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "i32", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    type = SC_PARAM_FLOAT;
    value.f = 99.99f;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "float", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "u8", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT8, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xFF, value.u8);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "u16", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT16, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xFFFF, value.u16);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "u32", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT32, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xFFFFFFFF, value.u32);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "i8", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_INT8, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(-128, value.i8);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "i16", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_INT16, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(-32768, value.i16);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "i32", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_INT32, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(-2147483648, value.i32);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "float", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_FLOAT, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(99.99f, value.f);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_add_same)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    type = SC_PARAM_UINT32;
    value.u32 = 0xDEADBEEF;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    type = SC_PARAM_UINT16;
    value.u32 = 0xDEBE;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "A very long name for a parameter", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    type = SC_PARAM_FLOAT;
    value.f = 0.99f;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "a", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    type = SC_PARAM_UINT32;
    value.u32 = 0xDEADBEEF;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", type, value);
    ck_assert_int_eq(SC_FUNC_FAILURE, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "a", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_FLOAT, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0.99f, value.f);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "A very long name for a parameter", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT16, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xDEBE, value.u32);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT32, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xDEADBEEF, value.u32);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_add_array)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    static const uint32_t array[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    retcode = params_add_array(sc, SC_SCHEME_SIG_HELLO_WORLD, "Param Array", SC_PARAM_UINT32, array, 16);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "Param Array", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT32, type);
    ck_assert_int_eq(16, length);
    ck_assert_ptr_eq(array, (uint32_t*)value.v);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_add_array_null)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    retcode = params_add_array(sc, SC_SCHEME_SIG_HELLO_WORLD, "Param Array", SC_PARAM_UINT32, NULL, 16);
    ck_assert_int_eq(SC_FUNC_FAILURE, retcode);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_params_clear)
{
    int32_t retcode;
    sc_param_type_e type;
    sc_data_u value;
    size_t length;
    safecrypto_t *sc;
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0);

    retcode = params_clear(sc, SC_SCHEME_SIG_HELLO_WORLD);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    type = SC_PARAM_UINT32;
    value.u32 = 0xDEADBEEF;
    retcode = params_add(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", type, value);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);
    ck_assert_int_eq(SC_PARAM_UINT32, type);
    ck_assert_int_eq(1, length);
    ck_assert_uint_eq(0xDEADBEEF, value.u32);

    retcode = params_clear(sc, SC_SCHEME_SIG_HELLO_WORLD);
    ck_assert_int_eq(SC_FUNC_SUCCESS, retcode);

    retcode = params_get(sc, SC_SCHEME_SIG_HELLO_WORLD, "DEADBEEF", &type, &value, &length);
    ck_assert_int_eq(SC_FUNC_FAILURE, retcode);

    safecrypto_destroy(sc);
}
END_TEST

Suite * safecrypto_params_suite(void)
{
    Suite *s;
    TCase *tc_get, *tc_set, *tc_clear;

    s = suite_create("safecrypto_params");

    /* Test cases */
    tc_get = tcase_create("GET");
    tcase_add_test(tc_get, test_safecrypto_params_init);
    tcase_add_test(tc_get, test_safecrypto_params_get_empty);
    tcase_add_test(tc_get, test_safecrypto_params_get_bad);
    suite_add_tcase(s, tc_get);

    tc_set = tcase_create("SET");
    tcase_add_test(tc_set, test_safecrypto_params_add);
    tcase_add_test(tc_set, test_safecrypto_params_add_multiple);
    tcase_add_test(tc_set, test_safecrypto_params_add_all);
    tcase_add_test(tc_set, test_safecrypto_params_add_same);
    tcase_add_test(tc_set, test_safecrypto_params_add_array);
    tcase_add_test(tc_set, test_safecrypto_params_add_array_null);
    suite_add_tcase(s, tc_set);

    tc_clear = tcase_create("CLEAR");
    tcase_add_test(tc_clear, test_safecrypto_params_clear);
    suite_add_tcase(s, tc_clear);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = safecrypto_params_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

