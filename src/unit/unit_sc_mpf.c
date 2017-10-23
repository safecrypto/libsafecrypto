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
#include "utils/arith/sc_mpf.c"


START_TEST(test_mpf_init)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
    sc_mpf_t inout;
    sc_mpf_set_precision(256);
    sc_mpf_init(&inout);
    ck_assert_int_eq(inout.exponent, SC_MPF_EXP_NAN);
    ck_assert_int_eq(inout.precision, 256);
    ck_assert_int_eq(inout.sign, 0);
    ck_assert_int_eq(inout.alloc, 256/SC_LIMB_BITS);
    ck_assert_ptr_ne(inout.mantissa, NULL);
    sc_mpf_clear(&inout);
    ck_assert_ptr_eq(inout.mantissa, NULL);
#endif
}
END_TEST

START_TEST(test_mpf_set_get_ui)
{
    sc_ulimb_t value, retvalue;
    sc_mpf_t inout;
    sc_mpf_set_precision(128);

    sc_mpf_init(&inout);
    value = SC_LIMB_UMAX;
    sc_mpf_set_ui(&inout, value);
    retvalue = sc_mpf_get_ui(&inout);
    ck_assert_uint_eq(value, retvalue);
    sc_mpf_clear(&inout);
}
END_TEST

START_TEST(test_mpf_set_get_si)
{
    sc_ulimb_t value, retvalue;
    sc_mpf_t inout;
    sc_mpf_set_precision(128);

    sc_mpf_init(&inout);
    value = SC_LIMB_SMIN;
    sc_mpf_set_si(&inout, value);
    retvalue = sc_mpf_get_si(&inout);
    ck_assert_int_eq(value, retvalue);
    sc_mpf_clear(&inout);
}
END_TEST

START_TEST(test_mpf_cmp)
{
    SINT32 retval;
    sc_mpf_t a, b;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    sc_mpf_set_si(&b, SC_LIMB_SMAX);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, -1);
    sc_mpf_set_si(&b, SC_LIMB_SMIN);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpf_set_si(&b, SC_LIMB_SMAX);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, 0);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, -1);
    sc_mpf_set_si(&b, 0);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, -1);
    sc_mpf_set_si(&a, 1);
    sc_mpf_set_si(&b, 0);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpf_set_si(&a, -1);
    sc_mpf_set_si(&b, -1);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_set_si(&b, 1);
    retval = sc_mpf_cmp(&a, &b);
    ck_assert_int_eq(retval, 0);
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
}
END_TEST

START_TEST(test_mpf_cmp_ui)
{
    SINT32 retval;
    sc_mpf_t a, nan, inf;
    sc_mpf_set_precision(128);
    sc_mpf_init(&a);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);

    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpf_cmp_ui(&a, SC_LIMB_UMAX);
    ck_assert_int_eq(retval, -1);
    retval = sc_mpf_cmp_ui(&a, 0);
    ck_assert_int_eq(retval, -1);
    sc_mpf_set_ui(&a, SC_LIMB_UMAX);
    retval = sc_mpf_cmp_ui(&a, 0);
    ck_assert_int_eq(retval, 1);
    retval = sc_mpf_cmp_ui(&a, SC_LIMB_UMAX);
    ck_assert_int_eq(retval, 0);
    retval = sc_mpf_cmp_ui(&inf, SC_LIMB_UMAX);
    ck_assert_int_eq(retval, 1);
    sc_mpf_negate(&inf, &inf);
    retval = sc_mpf_cmp_ui(&inf, SC_LIMB_UMAX);
    ck_assert_int_eq(retval, -1);
    retval = sc_mpf_cmp_ui(&nan, SC_LIMB_UMAX);
    ck_assert_int_eq(retval, 0);

    sc_mpf_clear(&a);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_fits_limb)
{
    SINT32 retval;
    sc_mpf_t a;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpf_fits_slimb(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpf_fits_slimb(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_set_ui(&a, SC_LIMB_UMIN);
    retval = sc_mpf_fits_slimb(&a);
    ck_assert_int_ne(retval, 0);
    retval = sc_mpf_fits_ulimb(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_set_ui(&a, SC_LIMB_UMAX);
    retval = sc_mpf_fits_slimb(&a);
    ck_assert_int_eq(retval, 0);
    retval = sc_mpf_fits_ulimb(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_clear(&a);
}
END_TEST

START_TEST(test_mpf_abs)
{
    sc_slimb_t retval;
    sc_mpf_t a, b;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    sc_mpf_abs(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, SC_LIMB_SMAX);
    sc_mpf_set_si(&a, SC_LIMB_SMAX);
    sc_mpf_abs(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, SC_LIMB_SMAX);
    sc_mpf_set_si(&a, -1);
    sc_mpf_abs(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, 1);
    sc_mpf_set_si(&a, 0);
    sc_mpf_abs(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, 0);
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
}
END_TEST

START_TEST(test_mpf_negate)
{
    sc_slimb_t retval;
    sc_mpf_t a, b;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    sc_mpf_set_si(&a, -SC_LIMB_SMAX);
    sc_mpf_negate(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, SC_LIMB_SMAX);
    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    sc_mpf_negate(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, SC_LIMB_SMAX);
    sc_mpf_set_si(&a, SC_LIMB_SMAX);
    sc_mpf_negate(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, -SC_LIMB_SMAX);
    sc_mpf_set_si(&a, -1);
    sc_mpf_negate(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, 1);
    sc_mpf_set_si(&a, 1);
    sc_mpf_negate(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, -1);
    sc_mpf_set_si(&a, 0);
    sc_mpf_negate(&b, &a);
    retval = sc_mpf_get_si(&b);
    ck_assert_int_eq(retval, 0);
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
}
END_TEST

START_TEST(test_mpf_is_zero)
{
    SINT32 retval;
    sc_mpf_t a;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpf_is_zero(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, -1);
    retval = sc_mpf_is_zero(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, 0);
    retval = sc_mpf_is_zero(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_set_si(&a, 1);
    retval = sc_mpf_is_zero(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpf_is_zero(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_clear(&a);
}
END_TEST

START_TEST(test_mpf_is_nan)
{
    SINT32 retval;
    sc_mpf_t a;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    retval = sc_mpf_is_nan(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_set_si(&a, 0);
    retval = sc_mpf_is_nan(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_clear(&a);
}
END_TEST

START_TEST(test_mpf_is_inf)
{
    SINT32 retval;
    sc_mpf_t a, b;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    retval = sc_mpf_is_inf(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&b, &a, 0);
    retval = sc_mpf_is_inf(&b);
    ck_assert_int_ne(retval, 0);
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
}
END_TEST

START_TEST(test_mpf_is_neg)
{
    SINT32 retval;
    sc_mpf_t a;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    retval = sc_mpf_is_neg(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, -1);
    retval = sc_mpf_is_neg(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_set_si(&a, 0);
    retval = sc_mpf_is_neg(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, 1);
    retval = sc_mpf_is_neg(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpf_is_neg(&a);
    ck_assert_int_ne(retval, 0);
    sc_mpf_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpf_is_neg(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_clear(&a);
}
END_TEST

START_TEST(test_mpf_sign)
{
    SINT32 retval;
    sc_mpf_t a;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    retval = sc_mpf_sign(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, -1);
    retval = sc_mpf_sign(&a);
    ck_assert_int_eq(retval, -1);
    sc_mpf_set_si(&a, 0);
    retval = sc_mpf_sign(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpf_set_si(&a, 1);
    retval = sc_mpf_sign(&a);
    ck_assert_int_eq(retval, 1);
    sc_mpf_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpf_sign(&a);
    ck_assert_int_eq(retval, -1);
    sc_mpf_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpf_sign(&a);
    ck_assert_int_eq(retval, 1);
    sc_mpf_clear(&a);
}
END_TEST

START_TEST(test_mpf_add)
{
    SINT32 retval;
    sc_mpf_t a, b, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, 0);
    sc_mpf_add(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_set_si(&b, 0);
    sc_mpf_add(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), -1024);
    sc_mpf_set_si(&a, -16);
    sc_mpf_set_si(&b, -16);
    sc_mpf_add(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), -32);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, -512);
    sc_mpf_add(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), -512);
    sc_mpf_set_si(&a, 15);
    sc_mpf_set_si(&b, 31);
    sc_mpf_add(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 46);
    sc_mpf_add(&out, &a, &nan);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_add(&out, &a, &inf);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_add_ui)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_add_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_add_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), -1024);
    sc_mpf_set_si(&a, -16);
    sc_mpf_add_ui(&out, &a, 16);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_add_ui(&out, &a, 512);
    ck_assert_int_eq(sc_mpf_get_si(&out), 512);
    sc_mpf_set_si(&a, 15);
    sc_mpf_add_ui(&out, &a, 31);
    ck_assert_int_eq(sc_mpf_get_si(&out), 46);
    sc_mpf_add_ui(&out, &nan, 15);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_add_ui(&out, &inf, 15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_add_si)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_add_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_add_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), -1024);
    sc_mpf_set_si(&a, -16);
    sc_mpf_add_si(&out, &a, -16);
    ck_assert_int_eq(sc_mpf_get_si(&out), -32);
    sc_mpf_set_si(&a, 0);
    sc_mpf_add_si(&out, &a, -512);
    ck_assert_int_eq(sc_mpf_get_si(&out), -512);
    sc_mpf_set_si(&a, 15);
    sc_mpf_add_si(&out, &a, 31);
    ck_assert_int_eq(sc_mpf_get_si(&out), 46);
    sc_mpf_add_si(&out, &nan, 15);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_add_si(&out, &inf, 15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_add_si(&out, &inf, -15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_sub)
{
    SINT32 retval;
    sc_mpf_t a, b, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, 0);
    sc_mpf_sub(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_set_si(&b, 0);
    sc_mpf_sub(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), -1024);
    sc_mpf_set_si(&a, -16);
    sc_mpf_set_si(&b, -16);
    sc_mpf_sub(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, -512);
    sc_mpf_sub(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 512);
    sc_mpf_set_si(&a, 15);
    sc_mpf_set_si(&b, 31);
    sc_mpf_sub(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), -16);
    sc_mpf_sub(&out, &a, &nan);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_sub(&out, &a, &inf);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_ne(sc_mpf_is_neg(&out), 0);  // i.e. -inf
    sc_mpf_sub(&out, &inf, &a);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_sub_ui)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_sub_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_sub_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), -1024);
    sc_mpf_set_si(&a, -16);
    sc_mpf_sub_ui(&out, &a, 16);
    ck_assert_int_eq(sc_mpf_get_si(&out), -32);
    sc_mpf_set_si(&a, 0);
    sc_mpf_sub_ui(&out, &a, 512);
    ck_assert_int_eq(sc_mpf_get_si(&out), -512);
    sc_mpf_set_si(&a, 15);
    sc_mpf_sub_ui(&out, &a, 31);
    ck_assert_int_eq(sc_mpf_get_si(&out), -16);
    sc_mpf_sub_ui(&out, &nan, 15);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_sub_ui(&out, &inf, 15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_sub_si)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_sub_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_sub_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), -1024);
    sc_mpf_set_si(&a, -16);
    sc_mpf_sub_si(&out, &a, -16);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_sub_si(&out, &a, -512);
    ck_assert_int_eq(sc_mpf_get_si(&out), 512);
    sc_mpf_set_si(&a, 15);
    sc_mpf_sub_si(&out, &a, 31);
    ck_assert_int_eq(sc_mpf_get_si(&out), -16);
    sc_mpf_sub_si(&out, &nan, 15);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_sub_si(&out, &inf, 15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_sub_si(&out, &inf, -15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_mul)
{
    SINT32 retval;
    sc_mpf_t a, b, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, 0);
    sc_mpf_mul(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_set_si(&b, 0);
    sc_mpf_mul(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -16);
    sc_mpf_set_si(&b, -16);
    sc_mpf_mul(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 256);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, -512);
    sc_mpf_mul(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 15);
    sc_mpf_set_si(&b, 31);
    sc_mpf_mul(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 465);
    sc_mpf_mul(&out, &a, &nan);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_mul(&out, &a, &inf);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_set_si(&a, -1);
    sc_mpf_mul(&out, &inf, &a);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_ne(sc_mpf_is_neg(&out), 0);  // i.e. -inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_mul_ui)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_mul_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_mul_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -16);
    sc_mpf_mul_ui(&out, &a, 16);
    ck_assert_int_eq(sc_mpf_get_si(&out), -256);
    sc_mpf_set_si(&a, 0);
    sc_mpf_mul_ui(&out, &a, 512);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 15);
    sc_mpf_mul_ui(&out, &a, 31);
    ck_assert_int_eq(sc_mpf_get_si(&out), 465);
    sc_mpf_mul_ui(&out, &nan, 15);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_mul_ui(&out, &inf, 15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_mul_si)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_mul_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1024);
    sc_mpf_mul_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -16);
    sc_mpf_mul_si(&out, &a, -16);
    ck_assert_int_eq(sc_mpf_get_si(&out), 256);
    sc_mpf_set_si(&a, 0);
    sc_mpf_mul_si(&out, &a, -512);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 15);
    sc_mpf_mul_si(&out, &a, -31);
    ck_assert_int_eq(sc_mpf_get_si(&out), -465);
    sc_mpf_mul_si(&out, &nan, 15);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_mul_si(&out, &inf, 15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);  // i.e. +inf
    sc_mpf_mul_si(&out, &inf, -15);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_ne(sc_mpf_is_neg(&out), 0);  // i.e. -inf
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_div)
{
    SINT32 retval;
    sc_mpf_t a, b, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&b);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_set_si(&b, 0);
    sc_mpf_div(&out, &a, &b);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_set_si(&b, 0);
    sc_mpf_div(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_is_nan(&out), 0);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, -1);
    sc_mpf_set_si(&b, 0);
    sc_mpf_div(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_is_nan(&out), 0);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_ne(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, 9999999);
    sc_mpf_set_si(&b, 3);
    sc_mpf_div(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 3333333);
    sc_mpf_set_si(&a, 32768);
    sc_mpf_set_si(&b, -4);
    sc_mpf_div(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), -8192);
    sc_mpf_set_si(&a, -16);
    sc_mpf_set_si(&b, -8);
    sc_mpf_div(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), 2);
    sc_mpf_set_si(&a, -8192);
    sc_mpf_set_si(&b, 4);
    sc_mpf_div(&out, &a, &b);
    ck_assert_int_eq(sc_mpf_get_si(&out), -2048);
    sc_mpf_clear(&a);
    sc_mpf_clear(&b);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_div_2exp)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_div_2exp(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_2exp(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_2exp(&out, &nan, 0);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    ck_assert_int_eq(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, -1);
    sc_mpf_div_2exp(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), -1);
    sc_mpf_set_si(&a, -32768);
    sc_mpf_div_2exp(&out, &a, 4);
    ck_assert_int_eq(sc_mpf_get_si(&out), -2048);
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_div_ui)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_div_ui(&out, &a, 0);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_is_nan(&out), 0);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, -1);
    sc_mpf_div_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_is_nan(&out), 0);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_ne(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, 9999999);
    sc_mpf_div_ui(&out, &a, 3);
    ck_assert_int_eq(sc_mpf_get_si(&out), 3333333);
    sc_mpf_set_si(&a, -8192);
    sc_mpf_div_ui(&out, &a, 4);
    ck_assert_int_eq(sc_mpf_get_si(&out), -2048);
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_div_si)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_div_si(&out, &a, 0);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_is_nan(&out), 0);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, -1);
    sc_mpf_div_si(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_is_nan(&out), 0);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    ck_assert_int_ne(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, 9999999);
    sc_mpf_div_si(&out, &a, 3);
    ck_assert_int_eq(sc_mpf_get_si(&out), 3333333);
    sc_mpf_set_si(&a, 32768);
    sc_mpf_div_si(&out, &a, -4);
    ck_assert_int_eq(sc_mpf_get_si(&out), -8192);
    sc_mpf_set_si(&a, -16);
    sc_mpf_div_si(&out, &a, -8);
    ck_assert_int_eq(sc_mpf_get_si(&out), 2);
    sc_mpf_set_si(&a, -8192);
    sc_mpf_div_si(&out, &a, 4);
    ck_assert_int_eq(sc_mpf_get_si(&out), -2048);
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_sqrt)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_sqrt(&out, &a);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_sqrt(&out, &a);
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_set_si(&a, -1);
    sc_mpf_sqrt(&out, &a);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_set_si(&a, 4096);
    sc_mpf_sqrt(&out, &a);
    ck_assert_int_eq(sc_mpf_get_si(&out), 64);
    sc_mpf_set_si(&a, 5);
    sc_mpf_sqrt(&out, &a);
    ck_assert_int_eq(sc_mpf_get_si(&out), 2);
    sc_mpf_sqrt(&out, &nan);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_sqrt(&out, &inf);
    ck_assert_int_eq(sc_mpf_is_nan(&out), 0);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    sc_mpf_negate(&inf, &inf);
    sc_mpf_sqrt(&out, &inf);
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_sqrt_ui)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_sqrt_ui(&out, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_sqrt_ui(&out, 1);
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_sqrt_ui(&out, 4096);
    ck_assert_int_eq(sc_mpf_get_si(&out), 64);
    sc_mpf_sqrt_ui(&out, 5);
    ck_assert_int_eq(sc_mpf_get_si(&out), 2);
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST

START_TEST(test_mpf_pow_ui)
{
    SINT32 retval;
    sc_mpf_t a, out, nan, inf;
    sc_mpf_set_precision(128);

    sc_mpf_init(&a);
    sc_mpf_init(&out);
    sc_mpf_init(&nan);
    sc_mpf_init(&inf);
    sc_mpf_set_si(&a, 1);
    sc_mpf_div_ui(&inf, &a, 0);
    sc_mpf_set_si(&a, 0);
    sc_mpf_pow_ui(&out, &a, 0);  // 0^0 returns 1
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_pow_ui(&out, &a, 1);  // 0^1 returns 0
    ck_assert_int_eq(sc_mpf_get_si(&out), 0);
    sc_mpf_set_si(&a, -1);
    sc_mpf_pow_ui(&out, &a, 0);  // -1^0 returns 1
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_pow_ui(&out, &inf, 0);  // inf^0 returns 1
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_pow_ui(&out, &nan, 0);  // NaN^0 returns 1
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_pow_ui(&out, &nan, 1);  // NaN^1 returns NaN
    ck_assert_int_ne(sc_mpf_is_nan(&out), 0);
    sc_mpf_pow_ui(&out, &inf, 2);
    ck_assert_int_ne(sc_mpf_is_inf(&out), 0);
    sc_mpf_negate(&inf, &inf);
    sc_mpf_pow_ui(&out, &inf, 0);  // -inf^0 returns 1
    ck_assert_int_eq(sc_mpf_is_inf(&out), 0);
    ck_assert_int_eq(sc_mpf_is_zero(&out), 0);
    ck_assert_int_eq(sc_mpf_is_neg(&out), 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_pow_ui(&out, &inf, 1);  // -inf^1 returns +inf
    ck_assert_int_eq(sc_mpf_is_inf(&out), 1);
    ck_assert_int_ne(sc_mpf_is_neg(&out), 0);
    sc_mpf_set_si(&a, 1);
    sc_mpf_pow_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_set_si(&a, 16);
    sc_mpf_pow_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_pow_ui(&out, &a, 1);
    ck_assert_int_eq(sc_mpf_get_si(&out), 16);
    sc_mpf_pow_ui(&out, &a, 2);
    ck_assert_int_eq(sc_mpf_get_si(&out), 256);
    sc_mpf_set_si(&a, -16);
    sc_mpf_pow_ui(&out, &a, 0);
    ck_assert_int_eq(sc_mpf_get_si(&out), 1);
    sc_mpf_pow_ui(&out, &a, 1);
    ck_assert_int_eq(sc_mpf_get_si(&out), -16);
    sc_mpf_pow_ui(&out, &a, 2);
    ck_assert_int_eq(sc_mpf_get_si(&out), -16*-16);
    sc_mpf_pow_ui(&out, &a, 3);
    ck_assert_int_eq(sc_mpf_get_si(&out), -16*-16*-16);
    sc_mpf_clear(&a);
    sc_mpf_clear(&out);
    sc_mpf_clear(&nan);
    sc_mpf_clear(&inf);
}
END_TEST


Suite *sc_mpf_suite(void)
{
    Suite *s;
    TCase *tc_mpf;

    s = suite_create("SC_MPF");

    /* Test cases */
    tc_mpf = tcase_create("mpf");
    tcase_add_test(tc_mpf, test_mpf_init);
    tcase_add_test(tc_mpf, test_mpf_set_get_ui);
    tcase_add_test(tc_mpf, test_mpf_set_get_si);
    tcase_add_test(tc_mpf, test_mpf_cmp);
    tcase_add_test(tc_mpf, test_mpf_cmp_ui);
    tcase_add_test(tc_mpf, test_mpf_fits_limb);
    tcase_add_test(tc_mpf, test_mpf_abs);
    tcase_add_test(tc_mpf, test_mpf_negate);
    tcase_add_test(tc_mpf, test_mpf_is_zero);
    tcase_add_test(tc_mpf, test_mpf_is_nan);
    tcase_add_test(tc_mpf, test_mpf_is_inf);
    tcase_add_test(tc_mpf, test_mpf_is_neg);
    tcase_add_test(tc_mpf, test_mpf_sign);
    tcase_add_test(tc_mpf, test_mpf_add);
    tcase_add_test(tc_mpf, test_mpf_add_ui);
    tcase_add_test(tc_mpf, test_mpf_add_si);
    tcase_add_test(tc_mpf, test_mpf_sub);
    tcase_add_test(tc_mpf, test_mpf_sub_ui);
    tcase_add_test(tc_mpf, test_mpf_sub_si);
    tcase_add_test(tc_mpf, test_mpf_mul);
    tcase_add_test(tc_mpf, test_mpf_mul_ui);
    tcase_add_test(tc_mpf, test_mpf_mul_si);
    tcase_add_test(tc_mpf, test_mpf_div);
    tcase_add_test(tc_mpf, test_mpf_div_2exp);
    tcase_add_test(tc_mpf, test_mpf_div_ui);
    tcase_add_test(tc_mpf, test_mpf_div_si);
    tcase_add_test(tc_mpf, test_mpf_sqrt);
    tcase_add_test(tc_mpf, test_mpf_sqrt_ui);
    tcase_add_test(tc_mpf, test_mpf_pow_ui);
    suite_add_tcase(s, tc_mpf);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = sc_mpf_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}



