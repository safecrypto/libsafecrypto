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
#include "utils/entropy/exp_golomb.c"

START_TEST(test_exp_golomb_encode)
{
    UINT32 code;
    SINT32 bits;
    
    exp_golomb_encode(0, &code, &bits);
    ck_assert_uint_eq(code, 1);
    ck_assert_int_eq(bits, 1);

    exp_golomb_encode(1, &code, &bits);
    ck_assert_uint_eq(code, 2);
    ck_assert_int_eq(bits, 3);

    exp_golomb_encode(2, &code, &bits);
    ck_assert_uint_eq(code, 3);
    ck_assert_int_eq(bits, 3);

    exp_golomb_encode(3, &code, &bits);
    ck_assert_uint_eq(code, 4);
    ck_assert_int_eq(bits, 5);

    exp_golomb_encode(254, &code, &bits);
    ck_assert_uint_eq(code, 255);
    ck_assert_int_eq(bits, 15);

    exp_golomb_encode(255, &code, &bits);
    ck_assert_uint_eq(code, 256);
    ck_assert_int_eq(bits, 17);
}
END_TEST

START_TEST(test_exp_golomb_decode)
{
    size_t i;
    UINT32 code;
    SINT32 bits;
    UINT8 value;
    
    for (i=0; i<256; i++) {
        exp_golomb_encode((UINT8)i, &code, &bits);
        code &= (1 << bits) - 1;
        value = exp_golomb_decode(code);
        ck_assert_uint_eq(value, i);
    }
}
END_TEST

START_TEST(test_exp_golomb_sign_encode)
{
    UINT32 code;
    SINT32 bits;
    
    exp_golomb_sign_encode(0, &code, &bits);
    ck_assert_uint_eq(code, 1);
    ck_assert_int_eq(bits, 1);

    exp_golomb_sign_encode(1, &code, &bits);
    ck_assert_uint_eq(code, 2);
    ck_assert_int_eq(bits, 3);

    exp_golomb_sign_encode(-1, &code, &bits);
    ck_assert_uint_eq(code, 3);
    ck_assert_int_eq(bits, 3);

    exp_golomb_sign_encode(2, &code, &bits);
    ck_assert_uint_eq(code, 4);
    ck_assert_int_eq(bits, 5);

    exp_golomb_sign_encode(-2, &code, &bits);
    ck_assert_uint_eq(code, 5);
    ck_assert_int_eq(bits, 5);

    exp_golomb_sign_encode(126, &code, &bits);
    ck_assert_uint_eq(code, 252);
    ck_assert_int_eq(bits, 15);

    exp_golomb_sign_encode(-126, &code, &bits);
    ck_assert_uint_eq(code, 253);
    ck_assert_int_eq(bits, 15);

    exp_golomb_sign_encode(127, &code, &bits);
    ck_assert_uint_eq(code, 254);
    ck_assert_int_eq(bits, 15);

    exp_golomb_sign_encode(-127, &code, &bits);
    ck_assert_uint_eq(code, 255);
    ck_assert_int_eq(bits, 15);

    // NOTE: +/- 128 is out of range
}
END_TEST

START_TEST(test_exp_golomb_sign_decode)
{
    SINT32 i;
    UINT32 code;
    SINT32 bits;
    SINT8 value;
    
    for (i=-127; i<128; i++) {
        exp_golomb_sign_encode(i, &code, &bits);
        code &= (1 << bits) - 1;
        value = exp_golomb_sign_decode(code);
        ck_assert_int_eq(value, i);
    }
}
END_TEST

Suite *exp_golomb_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("exp_golomb");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_exp_golomb_encode);
    tcase_add_test(tc_core, test_exp_golomb_decode);
    tcase_add_test(tc_core, test_exp_golomb_sign_encode);
    tcase_add_test(tc_core, test_exp_golomb_sign_decode);
    suite_add_tcase(s, tc_core);
    
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = exp_golomb_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


