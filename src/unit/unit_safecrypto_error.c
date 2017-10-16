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
#include "safecrypto_error.h"
#include "safecrypto_private.h"

START_TEST(test_safecrypto_error_init)
{
	uint32_t retcode;
    const char *file;
    int32_t line;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    retcode = err_get_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    retcode = err_peek_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OK);

    retcode = err_peek_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_clear)
{
    uint32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    SC_LOG_ERROR(sc, SC_ERROR);

    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_ERROR);
    err_clear_error(sc->error_queue);
    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_check)
{
    uint32_t retcode;
    const char *file;
    int32_t line, lineref;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    lineref = __LINE__ + 1;
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS);

    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = err_peek_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref);
    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_overflow)
{
    uint32_t retcode;
    const char *file;
    int32_t line, lineref;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    lineref = __LINE__ + 1;
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 1
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 2
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 3
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 4
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 5
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 6
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 7
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 8
    SC_LOG_ERROR(sc, SC_ERROR);         // overflow, should be ignored

    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 1);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 2);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 3);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 4);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 5);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 6);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 7);
    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_peak)
{
    uint32_t retcode;
    const char *file;
    int32_t line, lineref;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    lineref = __LINE__ + 1;
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 1
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 2
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 3
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 4
    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 5
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 6
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 7
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 8
    SC_LOG_ERROR(sc, SC_ERROR);         // overflow, should be ignored

    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 1);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 2);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 3);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 6);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 7);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 8);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 9);
    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_get)
{
    uint32_t retcode;
    const char *file;
    int32_t line, lineref;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    lineref = __LINE__ + 1;
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 1
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 2
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 3
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 4
    retcode = err_get_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 5
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 6
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 7
    SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS); // 8
    SC_LOG_ERROR(sc, SC_ERROR);         // overflow, should be ignored

    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 1);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 2);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 3);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 6);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 7);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 8);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 9);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_ERROR);
    ck_assert_str_eq(file, __FILE__);
    ck_assert_int_eq(line, lineref + 10);
    retcode = err_peek_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_limit_1)
{
    uint32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    SC_LOG_ERROR(sc, -1); // Bad error code

    retcode = err_get_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_limit_2)
{
    uint32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    SC_LOG_ERROR(sc, SC_NUM_ERROR_CODES); // Bad error code

    retcode = err_get_error(sc->error_queue);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_limit_3)
{
    uint32_t retcode;
    const char *file;
    int32_t line;
    char test_filename[SC_MAX_FILENAME_LEN+1];
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    // Contains a SC_MAX_FILENAME_LEN-1 characters - no truncation
    sprintf(test_filename, "%0*d", SC_MAX_FILENAME_LEN - 2, 0);
    add_err_code(sc->error_queue, SC_ERROR, test_filename, __LINE__);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_ERROR);
    ck_assert_str_eq(file, test_filename);

    // Identical C-string - no truncation
    sprintf(test_filename, "%0*d", SC_MAX_FILENAME_LEN - 1, 0);
    add_err_code(sc->error_queue, SC_ERROR, test_filename, __LINE__);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_ERROR);
    ck_assert_str_eq(file, test_filename);

    // Contains an extra character - truncation
    sprintf(test_filename, "%0*d", SC_MAX_FILENAME_LEN, 0);
    add_err_code(sc->error_queue, SC_ERROR, test_filename, __LINE__);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_ERROR);
    ck_assert_str_ne(file, test_filename);

    // Reduce by one character using a null terminator - no truncation
    test_filename[SC_MAX_FILENAME_LEN-1] = 0;
    ck_assert_str_eq(file, test_filename);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_limit_4)
{
    uint32_t retcode;
    const char *file;
    int32_t line;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    // Contains a null string pointer - ignored
    add_err_code(sc->error_queue, SC_ERROR, NULL, __LINE__);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_safecrypto_error_limit_5)
{
    uint32_t retcode;
    const char *file;
    int32_t line;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    err_clear_error(sc->error_queue);

    // Contains a null string pointer - ignored
    add_err_code(sc->error_queue, SC_ERROR, __FILE__, -1);
    retcode = err_get_error_line(sc->error_queue, &file, &line);
    ck_assert_int_eq(retcode, SC_OK);

    safecrypto_destroy(sc);
}
END_TEST

Suite *safecrypto_error_suite(void)
{
    Suite *s;
    TCase *tc_core;
    TCase *tc_buffer;
    TCase *tc_limits;

    s = suite_create("safecrypto_error");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_safecrypto_error_init);
    tcase_add_test(tc_core, test_safecrypto_error_clear);
    tcase_add_test(tc_core, test_safecrypto_error_check);
    suite_add_tcase(s, tc_core);

    tc_buffer = tcase_create("BUFFER");
    tcase_add_test(tc_buffer, test_safecrypto_error_overflow);
    tcase_add_test(tc_buffer, test_safecrypto_error_peak);
    tcase_add_test(tc_buffer, test_safecrypto_error_get);
    suite_add_tcase(s, tc_buffer);

    tc_limits = tcase_create("LIMITS");
    tcase_add_test(tc_limits, test_safecrypto_error_limit_1);
    tcase_add_test(tc_limits, test_safecrypto_error_limit_2);
    tcase_add_test(tc_limits, test_safecrypto_error_limit_3);
    tcase_add_test(tc_limits, test_safecrypto_error_limit_4);
    tcase_add_test(tc_limits, test_safecrypto_error_limit_5);
    suite_add_tcase(s, tc_limits);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = safecrypto_error_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

