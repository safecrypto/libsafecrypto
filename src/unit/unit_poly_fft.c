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
#include "utils/arith/poly_fft.c"
#include "utils/crypto/prng.c"

static const float flt_epsilon = 0.0001;

static SINT32 flt_equal(float a, float b)
{
 return fabs(a-b) < flt_epsilon;
}

static const DOUBLE dbl_epsilon = 0.0001;

static SINT32 dbl_equal(DOUBLE a, DOUBLE b)
{
   return fabs(a-b) < dbl_epsilon;
}


START_TEST(test_create)
{
    sc_fft_t *ctx;
    SINT32 retval;
    ctx = create_fft(0);
    ck_assert_ptr_eq(ctx, NULL);
    ctx = create_fft(257);
    ck_assert_ptr_eq(ctx, NULL);
    ctx = create_fft(256);
    ck_assert_ptr_ne(ctx, NULL);

    retval = destroy_fft(NULL);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_simple_dbl_2)
{
    sc_fft_t *ctx;
    SINT32 retval;
    DOUBLE data[2], output[2];
    sc_complex_t fft[2];
    size_t i;
    for (i=0; i<2; i++) {
        data[i] = (DOUBLE) i;
    }

    ctx = create_fft(2);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_dbl(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_dbl(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_dbl(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<2; i++) {
        ck_assert_int_eq(1, dbl_equal(data[i], output[i]));
    }
}
END_TEST

START_TEST(test_simple_dbl_4)
{
    sc_fft_t *ctx;
    SINT32 retval;
    DOUBLE data[4], output[4];
    sc_complex_t fft[4];
    size_t i;
    for (i=0; i<4; i++) {
        data[i] = (DOUBLE) i;
    }

    ctx = create_fft(4);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_dbl(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_dbl(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_dbl(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, dbl_equal(data[i], output[i]));
    }
}
END_TEST

START_TEST(test_simple_dbl_256)
{
    sc_fft_t *ctx;
    SINT32 retval;
    DOUBLE data[256], output[256];
    sc_complex_t fft[256];
    size_t i;
    for (i=0; i<256; i++) {
        data[i] = (DOUBLE) i;
    }

    ctx = create_fft(256);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_dbl(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_dbl(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_dbl(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<256; i++) {
        ck_assert_int_eq(1, dbl_equal(data[i], output[i]));
    }
}
END_TEST

START_TEST(test_simple_flt_2)
{
    sc_fft_t *ctx;
    SINT32 retval;
    FLOAT data[2], output[2];
    sc_complex_t fft[2];
    size_t i;
    for (i=0; i<2; i++) {
        data[i] = (FLOAT) i;
    }

    ctx = create_fft(2);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_flt(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_flt(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_flt(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<2; i++) {
        ck_assert_int_eq(1, flt_equal(data[i], output[i]));
    }
}
END_TEST

START_TEST(test_simple_flt_4)
{
    sc_fft_t *ctx;
    SINT32 retval;
    FLOAT data[4], output[4];
    sc_complex_t fft[4];
    size_t i;
    for (i=0; i<4; i++) {
        data[i] = (FLOAT) i;
    }

    ctx = create_fft(4);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_flt(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_flt(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_flt(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<4; i++) {
        ck_assert_int_eq(1, flt_equal(data[i], output[i]));
    }
}
END_TEST

START_TEST(test_simple_flt_256)
{
    sc_fft_t *ctx;
    SINT32 retval;
    FLOAT data[256], output[256];
    sc_complex_t fft[256];
    size_t i;
    for (i=0; i<256; i++) {
        data[i] = (FLOAT) i;
    }

    ctx = create_fft(256);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_flt(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_flt(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_flt(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<256; i++) {
        ck_assert_int_eq(1, flt_equal(data[i], output[i]));
    }
}
END_TEST

START_TEST(test_simple_int_2)
{
    sc_fft_t *ctx;
    SINT32 retval;
    SINT32 data[2], output[2];
    sc_complex_t fft[2];
    size_t i;
    for (i=0; i<2; i++) {
        data[i] = (SINT32) i;
    }

    ctx = create_fft(2);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_int(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_int(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_int(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<2; i++) {
        ck_assert_int_eq(data[i], output[i]);
    }
}
END_TEST

START_TEST(test_simple_int_4)
{
    sc_fft_t *ctx;
    SINT32 retval;
    SINT32 data[4], output[4];
    sc_complex_t fft[4];
    size_t i;
    for (i=0; i<4; i++) {
        data[i] = (SINT32) i;
    }

    ctx = create_fft(4);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_int(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_int(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_int(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<4; i++) {
        ck_assert_int_eq(data[i], output[i]);
    }
}
END_TEST

START_TEST(test_simple_int_256)
{
    sc_fft_t *ctx;
    SINT32 retval;
    SINT32 data[256], output[256];
    sc_complex_t fft[256];
    size_t i;
    for (i=0; i<256; i++) {
        data[i] = (SINT32) i;
    }

    ctx = create_fft(256);
    ck_assert_ptr_ne(ctx, NULL);

    retval = fwd_fft_int(NULL, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = fwd_fft_int(ctx, fft, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    retval = inv_fft_int(ctx, output, fft);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    retval = destroy_fft(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);

    for (i=0; i<256; i++) {
        ck_assert_int_eq(data[i], output[i]);
    }
}
END_TEST

Suite *poly_fft_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly_fft");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_create);
    tcase_add_test(tc_core, test_simple_dbl_2);
    tcase_add_test(tc_core, test_simple_dbl_4);
    tcase_add_test(tc_core, test_simple_dbl_256);
    tcase_add_test(tc_core, test_simple_flt_2);
    tcase_add_test(tc_core, test_simple_flt_4);
    tcase_add_test(tc_core, test_simple_flt_256);
    tcase_add_test(tc_core, test_simple_int_2);
    tcase_add_test(tc_core, test_simple_int_4);
    tcase_add_test(tc_core, test_simple_int_256);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = poly_fft_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


