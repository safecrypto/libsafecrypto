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
#include "utils/arith/sc_mpz.c"
#include "utils/crypto/prng.c"
#include "utils/sampling/gaussian_cdf.c"

#include <float.h>


START_TEST(test_mpz_init)
{
#ifdef USE_SAFECRYPTO_INTEGER_MP    
    sc_mpz_t inout;
    mpz_init(&inout);
    ck_assert_int_eq(inout.alloc, 0);
    ck_assert_int_eq(inout.used, 0);
    ck_assert_ptr_eq(inout.limbs, NULL);
#endif
}
END_TEST

START_TEST(test_mpi_negate)
{
    sc_mpz_t in, out;
    sc_mpz_init(&in);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in, SC_LIMB_WORD(0));
    sc_mpz_negate(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), 0);
    sc_mpz_set_si(&in, SC_LIMB_WORD(1));
    ck_assert_int_eq(sc_mpz_get_si(&in), 1);
    sc_mpz_negate(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), -1);
    sc_mpz_set_si(&in, SC_LIMB_WORD(-1));
    sc_mpz_negate(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), 1);
    sc_mpz_set_si(&in, SC_LIMB_WORD(2));
    sc_mpz_negate(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), -2);
    sc_mpz_set_si(&in, SC_LIMB_WORD(-2));
    sc_mpz_negate(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), 2);
    sc_mpz_clear(&in);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_is_zero)
{
    SINT32 result;
    sc_mpz_t in;
    sc_mpz_init(&in);
    sc_mpz_set_si(&in, SC_LIMB_WORD(0));
    result = sc_mpz_is_zero(&in);
    ck_assert_int_eq(result, 1);
    sc_mpz_set_si(&in, SC_LIMB_WORD(1));
    result = sc_mpz_is_zero(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_set_si(&in, SC_LIMB_SMIN);
    result = sc_mpz_is_zero(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_set_ui(&in, SC_LIMB_UMAX);
    result = sc_mpz_is_zero(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_clear(&in);
}
END_TEST

START_TEST(test_mpi_is_one)
{
    SINT32 result;
    sc_mpz_t in;
    sc_mpz_init(&in);
    sc_mpz_set_si(&in, SC_LIMB_WORD(0));
    result = sc_mpz_is_one(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_set_si(&in, SC_LIMB_WORD(1));
    result = sc_mpz_is_one(&in);
    ck_assert_int_eq(result, 1);
    sc_mpz_set_si(&in, SC_LIMB_SMIN);
    result = sc_mpz_is_one(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_set_ui(&in, SC_LIMB_UMAX);
    result = sc_mpz_is_one(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_clear(&in);
}
END_TEST

START_TEST(test_mpi_is_neg)
{
    SINT32 result;
    sc_mpz_t in;
    sc_mpz_init(&in);
    sc_mpz_set_si(&in, SC_LIMB_WORD(0));
    result = sc_mpz_is_neg(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_set_si(&in, SC_LIMB_WORD(1));
    result = sc_mpz_is_neg(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_set_si(&in, SC_LIMB_SMIN);
    result = sc_mpz_is_neg(&in);
    ck_assert_int_eq(result, 1);
    sc_mpz_set_ui(&in, SC_LIMB_UMAX);
    result = sc_mpz_is_neg(&in);
    ck_assert_int_eq(result, 0);
    sc_mpz_clear(&in);
}
END_TEST

START_TEST(test_mpi_add)
{
    sc_mpz_t in1, in2, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&in2);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(0));
    sc_mpz_add(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(0));
    sc_mpz_add(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_add(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1) << (SC_LIMB_BITS-2));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1) << (SC_LIMB_BITS-3));
    sc_mpz_add(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)(SC_LIMB_WORD(3) << (SC_LIMB_BITS-3)));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(-1));
    sc_mpz_add(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)(SC_LIMB_WORD(-1)));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&in2);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_add_ui)
{
    sc_mpz_t in1, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_add_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_add_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_add_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1) << (SC_LIMB_BITS-2));
    sc_mpz_add_ui(&out, &in1, SC_LIMB_WORD(1) << (SC_LIMB_BITS-3));
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)(SC_LIMB_WORD(3) << (SC_LIMB_BITS-3)));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_sub)
{
    sc_mpz_t in1, in2, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&in2);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(0));
    sc_mpz_sub(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(0));
    sc_mpz_sub(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_sub(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)(SC_LIMB_WORD(-1)));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    sc_mpz_sub(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(-1));
    sc_mpz_sub(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&in2);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_sub_ui)
{
    sc_mpz_t in1, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_sub_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_sub_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_sub_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)(SC_LIMB_WORD(-1)));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    sc_mpz_sub_ui(&out, &in1, SC_LIMB_WORD(1) << (SC_LIMB_BITS-1));
    ck_assert_int_eq(sc_mpz_get_ui(&out), SC_LIMB_WORD(0));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_mul)
{
    sc_mpz_t in1, in2, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&in2);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(0));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(0));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(-1));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)(SC_LIMB_WORD(-2)));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(2));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(4));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(256));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(256));
    sc_mpz_mul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(65536));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&in2);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_mul_scalar)
{
    sc_mpz_t in, out;
    sc_mpz_init(&in);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in, SC_LIMB_WORD(0));
    sc_mpz_set_si(&out, SC_LIMB_WORD(0));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in, SC_LIMB_WORD(1));
    sc_mpz_set_si(&out, SC_LIMB_WORD(0));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in, SC_LIMB_WORD(0));
    sc_mpz_set_si(&out, SC_LIMB_WORD(1));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in, SC_LIMB_WORD(1));
    sc_mpz_set_si(&out, SC_LIMB_WORD(1));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in, SC_LIMB_WORD(2));
    sc_mpz_set_si(&out, SC_LIMB_WORD(1));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(2));
    sc_mpz_set_si(&in, SC_LIMB_WORD(2));
    sc_mpz_set_si(&out, SC_LIMB_WORD(-1));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)(SC_LIMB_WORD(-2)));
    sc_mpz_set_si(&in, SC_LIMB_WORD(2));
    sc_mpz_set_si(&out, SC_LIMB_WORD(2));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(4));
    sc_mpz_set_si(&in, SC_LIMB_WORD(256));
    sc_mpz_set_si(&out, SC_LIMB_WORD(256));
    sc_mpz_mul_scalar(&out, &in);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(65536));
    sc_mpz_clear(&in);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_mul_ui)
{
    sc_mpz_t in1, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_mul_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_mul_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_mul_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_mul_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_mul_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_mul_ui(&out, &in1, 2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(4));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(256));
    sc_mpz_mul_ui(&out, &in1, 256);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(65536));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(-1));
    sc_mpz_mul_ui(&out, &in1, 256);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), SC_LIMB_WORD(-256));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_mul_si)
{
    sc_mpz_t in1, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_mul_si(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_mul_si(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_mul_si(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(0));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_mul_si(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_mul_si(&out, &in1, -1);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), -SC_LIMB_WORD(2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_mul_si(&out, &in1, -2);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)SC_LIMB_WORD(-4));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(256));
    sc_mpz_mul_si(&out, &in1, -256);
    ck_assert_int_eq(sc_mpz_get_si(&out), (sc_slimb_t)SC_LIMB_WORD(-65536));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_addmul)
{
    sc_mpz_t in1, in2, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&in2);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_set_si(&out, SC_LIMB_WORD(0));
    sc_mpz_addmul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_addmul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(12));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(-1));
    sc_mpz_addmul(&out, &in1, &in2);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), SC_LIMB_WORD(-10));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&in2);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_submul)
{
    sc_mpz_t in1, in2, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&in2);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_set_si(&out, SC_LIMB_WORD(0));
    sc_mpz_submul(&out, &in1, &in2);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), SC_LIMB_WORD(-1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(1));
    sc_mpz_submul(&out, &in1, &in2);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), SC_LIMB_WORD(-2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2048));
    sc_mpz_set_si(&in2, SC_LIMB_WORD(-2));
    sc_mpz_submul(&out, &in1, &in2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(4094));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&in2);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_addmul_ui)
{
    sc_mpz_t in1, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&out, SC_LIMB_WORD(0));
    sc_mpz_addmul_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_addmul_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(-1));
    sc_mpz_addmul_ui(&out, &in1, 12);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), SC_LIMB_WORD(-10));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_submul_ui)
{
    sc_mpz_t in1, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_set_si(&out, SC_LIMB_WORD(0));
    sc_mpz_submul_ui(&out, &in1, 1);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), SC_LIMB_WORD(-1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_submul_ui(&out, &in1, 1);
    ck_assert_int_eq(SC_LIMB_WORD(sc_mpz_get_si(&out)), SC_LIMB_WORD(-2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(-2));
    sc_mpz_submul_ui(&out, &in1, 2048);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(4094));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_pow_ui)
{
    sc_mpz_t in1, out;
    sc_mpz_init(&in1);
    sc_mpz_init(&out);
    sc_mpz_set_si(&in1, SC_LIMB_WORD(0));
    sc_mpz_pow_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(1));
    sc_mpz_pow_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_pow_ui(&out, &in1, 0);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(1));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_pow_ui(&out, &in1, 1);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_WORD(2));
    sc_mpz_set_si(&in1, SC_LIMB_WORD(2));
    sc_mpz_pow_ui(&out, &in1, SC_LIMB_BITS2);
    ck_assert_int_eq(sc_mpz_get_si(&out), SC_LIMB_LSHIFT(SC_LIMB_WORD(1), SC_LIMB_BITS2));
    sc_mpz_clear(&in1);
    sc_mpz_clear(&out);
}
END_TEST

START_TEST(test_mpi_div)
{
    sc_mpz_t n, d, q, r;
    sc_mpz_init(&n);
    sc_mpz_init(&d);
    sc_mpz_init(&q);
    sc_mpz_init(&r);
    sc_mpz_set_si(&n, SC_LIMB_WORD(0));
    sc_mpz_set_si(&d, SC_LIMB_WORD(1));
    sc_mpz_div(&q, &r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(0));
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(0));
    sc_mpz_set_si(&n, SC_LIMB_WORD(1));
    sc_mpz_set_si(&d, SC_LIMB_WORD(1));
    sc_mpz_div(&q, &r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(1));
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(0));
    sc_mpz_set_si(&n, SC_LIMB_WORD(1) << (SC_LIMB_BITS-2));
    sc_mpz_set_si(&d, SC_LIMB_WORD(2));
    sc_mpz_div(&q, &r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(1) << (SC_LIMB_BITS-3));
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(0));
    sc_mpz_set_si(&n, SC_LIMB_WORD(129));
    sc_mpz_set_si(&d, SC_LIMB_WORD(16));
    sc_mpz_div(&q, &r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(8));
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(1));
    sc_mpz_set_si(&n, SC_LIMB_WORD(-129));
    sc_mpz_set_si(&d, SC_LIMB_WORD(16));
    sc_mpz_div(&q, &r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), (sc_slimb_t)(SC_LIMB_WORD(-9)));
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(15));
    sc_mpz_clear(&n);
    sc_mpz_clear(&d);
    sc_mpz_clear(&q);
    sc_mpz_clear(&r);
}
END_TEST

START_TEST(test_mpi_divrem)
{
    sc_mpz_t n, d, r;
    sc_mpz_init(&n);
    sc_mpz_init(&d);
    sc_mpz_init(&r);
    sc_mpz_set_si(&n, SC_LIMB_WORD(0));
    sc_mpz_set_si(&d, SC_LIMB_WORD(1));
    sc_mpz_divrem(&r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(0));
    sc_mpz_set_si(&n, SC_LIMB_WORD(1));
    sc_mpz_set_si(&d, SC_LIMB_WORD(1));
    sc_mpz_divrem(&r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(0));
    sc_mpz_set_si(&n, SC_LIMB_WORD(1) << (SC_LIMB_BITS-2));
    sc_mpz_set_si(&d, SC_LIMB_WORD(2));
    sc_mpz_divrem(&r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(0));
    sc_mpz_set_si(&n, SC_LIMB_WORD(129));
    sc_mpz_set_si(&d, SC_LIMB_WORD(16));
    sc_mpz_divrem(&r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(1));
    sc_mpz_set_si(&n, SC_LIMB_WORD(-129));
    sc_mpz_set_si(&d, SC_LIMB_WORD(16));
    sc_mpz_divrem(&r, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&r), SC_LIMB_WORD(15));
    sc_mpz_clear(&n);
    sc_mpz_clear(&d);
    sc_mpz_clear(&r);
}
END_TEST

START_TEST(test_mpi_divquo)
{
    sc_mpz_t n, d, q;
    sc_mpz_init(&n);
    sc_mpz_init(&d);
    sc_mpz_init(&q);
    sc_mpz_set_si(&n, SC_LIMB_WORD(0));
    sc_mpz_set_si(&d, SC_LIMB_WORD(1));
    sc_mpz_divquo(&q, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(0));
    sc_mpz_set_si(&n, SC_LIMB_WORD(1));
    sc_mpz_set_si(&d, SC_LIMB_WORD(1));
    sc_mpz_divquo(&q, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(1));
    sc_mpz_set_si(&n, SC_LIMB_WORD(1) << (SC_LIMB_BITS-2));
    sc_mpz_set_si(&d, SC_LIMB_WORD(2));
    sc_mpz_divquo(&q, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(1) << (SC_LIMB_BITS-3));
    sc_mpz_set_si(&n, SC_LIMB_WORD(129));
    sc_mpz_set_si(&d, SC_LIMB_WORD(16));
    sc_mpz_divquo(&q, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), SC_LIMB_WORD(8));
    sc_mpz_set_si(&n, SC_LIMB_WORD(-129));
    sc_mpz_set_si(&d, SC_LIMB_WORD(16));
    sc_mpz_divquo(&q, &n, &d);
    ck_assert_int_eq(sc_mpz_get_si(&q), (sc_slimb_t)(SC_LIMB_WORD(-9)));
    sc_mpz_clear(&n);
    sc_mpz_clear(&d);
    sc_mpz_clear(&q);
}
END_TEST

START_TEST(test_mpi_get_ui_mod)
{
    sc_ulimb_t retval;
    sc_mpz_t a;
    sc_mod_t mod;
    sc_mpz_init(&a);
    limb_mod_init(&mod, 2);
    sc_mpz_set_si(&a, SC_LIMB_WORD(0));
    retval = sc_mpz_get_ui_mod(&a, &mod);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, SC_LIMB_WORD(1));
    retval = sc_mpz_get_ui_mod(&a, &mod);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, SC_LIMB_WORD(2));
    retval = sc_mpz_get_ui_mod(&a, &mod);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, SC_LIMB_WORD(3));
    retval = sc_mpz_get_ui_mod(&a, &mod);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, SC_LIMB_WORD(4));
    retval = sc_mpz_get_ui_mod(&a, &mod);
    ck_assert_int_eq(retval, 0);

#if SC_LIMB_BITS == 64
    limb_mod_init(&mod, 9223372036854775837U);
#else
    limb_mod_init(&mod, 3221226240);
#endif
    sc_mpz_set_si(&a, SC_LIMB_WORD(768));
    retval = sc_mpz_get_ui_mod(&a, &mod);
    ck_assert_int_eq(retval, 768);

    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpi_gcd)
{
    sc_mpz_t a, b, tv_gcd, gcd;
    sc_mpz_init(&a);
    sc_mpz_init(&b);
    sc_mpz_init(&gcd);
    sc_mpz_init(&tv_gcd);
    sc_mpz_set_ui(&a, 54);
    sc_mpz_set_ui(&b, 24);
    sc_mpz_set_ui(&tv_gcd, 6);
    SINT32 result = sc_mpz_gcd(&a, &b, &gcd);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    ck_assert_int_eq(sc_mpz_get_si(&tv_gcd),
                     sc_mpz_get_si(&gcd));
    sc_mpz_clear(&a);
    sc_mpz_clear(&b);
    sc_mpz_clear(&gcd);
    sc_mpz_clear(&tv_gcd);
}
END_TEST

START_TEST(test_mpi_xgcd)
{
    sc_mpz_t a, b, gcd, x, y, temp;
    sc_mpz_init(&a);
    sc_mpz_init(&b);
    sc_mpz_init(&gcd);
    sc_mpz_init(&x);
    sc_mpz_init(&y);
    sc_mpz_init(&temp);
    sc_mpz_set_ui(&a, 54);
    sc_mpz_set_ui(&b, 24);
    SINT32 result = sc_mpz_xgcd(&a, &b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    sc_ulimb_big_t prod = (sc_ulimb_big_t)sc_mpz_get_si(&a)*(sc_ulimb_big_t)sc_mpz_get_si(&x) +
                  (sc_ulimb_big_t)sc_mpz_get_si(&b)*(sc_ulimb_big_t)sc_mpz_get_si(&y);
    ck_assert_int_eq(sc_mpz_get_ui(&gcd), prod);
    ck_assert_int_eq(SC_LIMB_WORD(1), sc_mpz_get_si(&x));
    ck_assert_int_eq((sc_slimb_t)(SC_LIMB_WORD(-2)), sc_mpz_get_si(&y));
    sc_mpz_clear(&a);
    sc_mpz_clear(&b);
    sc_mpz_clear(&gcd);
    sc_mpz_clear(&x);
    sc_mpz_clear(&y);
    sc_mpz_clear(&temp);
}
END_TEST

START_TEST(test_mpi_xgcd_2)
{
    sc_mpz_t a, b, gcd, x, y, temp;
    sc_mpz_init(&a);
    sc_mpz_init(&b);
    sc_mpz_init(&gcd);
    sc_mpz_init(&x);
    sc_mpz_init(&y);
    sc_mpz_init(&temp);
    sc_mpz_set_ui(&a, 1);
    sc_mpz_set_ui(&b, 2);
    SINT32 result = sc_mpz_xgcd(&a, &b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    ck_assert_int_eq(sc_mpz_get_ui(&gcd), 1);
    //ck_assert_int_eq(SC_LIMB_WORD(1), sc_mpz_get_si(&x));
    //ck_assert_int_eq((sc_slimb_t)(SC_LIMB_WORD(-2)), sc_mpz_get_si(&y));
    sc_mpz_clear(&a);
    sc_mpz_clear(&b);
    sc_mpz_clear(&gcd);
    sc_mpz_clear(&x);
    sc_mpz_clear(&y);
    sc_mpz_clear(&temp);
}
END_TEST

START_TEST(test_mpi_sign)
{
    SINT32 retval = 0;
    sc_mpz_t a;
    sc_mpz_init(&a);
    sc_mpz_set_ui(&a, 0);
    retval = sc_mpz_sign(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_ui(&a, SC_LIMB_UMAX);
    retval = sc_mpz_sign(&a);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, 0);
    retval = sc_mpz_sign(&a);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, 1);
    retval = sc_mpz_sign(&a);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpz_sign(&a);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, -1);
    retval = sc_mpz_sign(&a);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpz_sign(&a);
    ck_assert_int_eq(retval, -1);
    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpi_copy)
{
    SINT32 retval = 0;
    sc_mpz_t a, b;
    sc_mpz_init(&a);
    sc_mpz_init(&b);
    sc_mpz_set_ui(&a, 0);
    sc_mpz_set_ui(&b, 1);
    sc_mpz_copy(&a, &b);
    ck_assert_int_eq(sc_mpz_get_ui(&a), 1);
    sc_mpz_set_ui(&a, 0);
    sc_mpz_set_ui(&b, SC_LIMB_UMAX);
    sc_mpz_copy(&a, &b);
    ck_assert_int_eq(sc_mpz_get_ui(&a), SC_LIMB_UMAX);
    sc_mpz_clear(&a);
    sc_mpz_clear(&b);
}
END_TEST

START_TEST(test_mpi_cmp)
{
    SINT32 retval = 0;
    sc_mpz_t a, b;
    sc_mpz_init(&a);
    sc_mpz_init(&b);
    sc_mpz_set_ui(&a, 1);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmp(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, 0);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmp(&a, &b);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, -1);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmp(&a, &b);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_si(&a, SC_LIMB_SMIN);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmp(&a, &b);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_si(&a, SC_LIMB_SMAX);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmp(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpz_clear(&a);
    sc_mpz_clear(&b);
}
END_TEST

START_TEST(test_mpi_cmp_d)
{
    SINT32 retval = 0;
    sc_mpz_t a;
    sc_mpz_init(&a);
    sc_mpz_set_ui(&a, 1);
    retval = sc_mpz_cmp_d(&a, 0.0);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, 0);
    retval = sc_mpz_cmp_d(&a, 0.0);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, -1);
    retval = sc_mpz_cmp_d(&a, 0.0);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpz_cmp_d(&a, DBL_MAX);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpz_cmp_d(&a, DBL_MIN);
    ck_assert_int_eq(retval, 1);
    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpi_cmp_ui)
{
    SINT32 retval = 0;
    sc_mpz_t a;
    sc_mpz_init(&a);
    sc_mpz_set_ui(&a, 1);
    retval = sc_mpz_cmp_ui(&a, 0);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, 0);
    retval = sc_mpz_cmp_ui(&a, 0);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, -1);
    retval = sc_mpz_cmp_ui(&a, 0);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_ui(&a, SC_LIMB_UMIN);
    retval = sc_mpz_cmp_ui(&a, SC_LIMB_UMAX);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_ui(&a, SC_LIMB_UMAX);
    retval = sc_mpz_cmp_ui(&a, SC_LIMB_UMIN);
    ck_assert_int_eq(retval, 1);
    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpi_cmp_si)
{
    SINT32 retval = 0;
    sc_mpz_t a;
    sc_mpz_init(&a);
    sc_mpz_set_ui(&a, 1);
    retval = sc_mpz_cmp_si(&a, 0);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, 0);
    retval = sc_mpz_cmp_si(&a, 0);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, -1);
    retval = sc_mpz_cmp_si(&a, 0);
    ck_assert_int_lt(retval, 0);
    sc_mpz_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpz_cmp_si(&a, SC_LIMB_SMAX);
    ck_assert_int_lt(retval, 0);
    sc_mpz_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpz_cmp_si(&a, SC_LIMB_SMIN);
    ck_assert_int_gt(retval, 0);
    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpi_cmpabs)
{
    SINT32 retval = 0;
    sc_mpz_t a, b;
    sc_mpz_init(&a);
    sc_mpz_init(&b);
    sc_mpz_set_ui(&a, 1);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmpabs(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, 0);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmpabs(&a, &b);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, -1);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmpabs(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, SC_LIMB_SMIN);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmpabs(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, SC_LIMB_SMAX);
    sc_mpz_set_ui(&b, 0);
    retval = sc_mpz_cmpabs(&a, &b);
    ck_assert_int_eq(retval, 1);
    sc_mpz_clear(&a);
    sc_mpz_clear(&b);
}
END_TEST

START_TEST(test_mpi_cmpabs_d)
{
    SINT32 retval = 0;
    sc_mpz_t a;
    sc_mpz_init(&a);
    sc_mpz_set_ui(&a, 1);
    retval = sc_mpz_cmpabs_d(&a, 0.0);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, 0);
    retval = sc_mpz_cmpabs_d(&a, 0.0);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, -1);
    retval = sc_mpz_cmpabs_d(&a, 0.0);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, SC_LIMB_SMIN);
    retval = sc_mpz_cmpabs_d(&a, DBL_MAX);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_si(&a, SC_LIMB_SMAX);
    retval = sc_mpz_cmpabs_d(&a, DBL_MIN);
    ck_assert_int_eq(retval, 1);
    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpi_cmpabs_ui)
{
    SINT32 retval = 0;
    sc_mpz_t a;
    sc_mpz_init(&a);
    sc_mpz_set_ui(&a, 1);
    retval = sc_mpz_cmpabs_ui(&a, 0);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, 0);
    retval = sc_mpz_cmpabs_ui(&a, 0);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, -1);
    retval = sc_mpz_cmpabs_ui(&a, 0);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_si(&a, -1);
    retval = sc_mpz_cmpabs_ui(&a, 1);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_si(&a, 2);
    retval = sc_mpz_cmpabs_ui(&a, 1);
    ck_assert_int_eq(retval, 1);
    sc_mpz_set_ui(&a, SC_LIMB_UMIN);
    retval = sc_mpz_cmpabs_ui(&a, SC_LIMB_UMAX);
    ck_assert_int_eq(retval, -1);
    sc_mpz_set_ui(&a, SC_LIMB_UMAX);
    retval = sc_mpz_cmpabs_ui(&a, SC_LIMB_UMIN);
    ck_assert_int_eq(retval, 1);
    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpi_invert)
{
    SINT32 retval = 0;
    sc_mpz_t a, b, mod;
    sc_mpz_init(&a);
    sc_mpz_init(&b);
    sc_mpz_init(&mod);
    sc_mpz_set_ui(&a, 0);
    sc_mpz_set_ui(&mod, 256);
    retval = sc_mpz_invmod(&b, &a, &mod);
    ck_assert_int_eq(retval, 0); // i.e. failure for 0 modulo 256
    sc_mpz_set_ui(&a, 37);
    sc_mpz_set_ui(&mod, 0);
    retval = sc_mpz_invmod(&b, &a, &mod);
    ck_assert_int_eq(retval, 0); // i.e. modulo 0 is indeterminate
    sc_mpz_set_ui(&a, 2);
    sc_mpz_set_ui(&mod, 256);
    retval = sc_mpz_invmod(&b, &a, &mod);
    ck_assert_int_eq(retval, 0);
    sc_mpz_set_ui(&a, 1);
    sc_mpz_set_si(&mod, -1);
    retval = sc_mpz_invmod(&b, &a, &mod);
    ck_assert_int_ne(retval, 0);
    ck_assert_int_eq(sc_mpz_get_ui(&b), 0);
    sc_mpz_set_ui(&a, 1);
    sc_mpz_set_si(&mod, SC_LIMB_SMIN);
    retval = sc_mpz_invmod(&b, &a, &mod);
    ck_assert_int_ne(retval, 0);
    ck_assert_int_eq(sc_mpz_get_ui(&b), 1);
    sc_mpz_set_ui(&a, 1);
    sc_mpz_set_ui(&mod, 2);
    retval = sc_mpz_invmod(&b, &a, &mod);
    ck_assert_int_ne(retval, 0);
    ck_assert_int_eq(sc_mpz_get_ui(&b), 1);
    sc_mpz_set_ui(&a, 1);
    sc_mpz_set_ui(&mod, 256);
    retval = sc_mpz_invmod(&b, &a, &mod);
    ck_assert_int_ne(retval, 0);
    ck_assert_int_eq(sc_mpz_get_ui(&b), 1);
    sc_mpz_clear(&a);
    sc_mpz_clear(&b);
    sc_mpz_clear(&mod);
}
END_TEST

START_TEST(test_mpz_set_str)
{
    SINT32 result;
    sc_mpz_t a;
    sc_ulimb_t *limbs;

    sc_mpz_init(&a);
    sc_mpz_set_str(&a, 16, "0");
    result = sc_mpz_is_zero(&a);
    ck_assert_int_eq(result, 1);
    sc_mpz_clear(&a);

    sc_mpz_init(&a);
    sc_mpz_set_str(&a, 16, "1");
    result = sc_mpz_is_one(&a);
    ck_assert_int_eq(result, 1);
    sc_mpz_clear(&a);

    sc_mpz_init(&a);

    sc_mpz_set_str(&a, 16, "10000000000000000");
    limbs = sc_mpz_get_limbs(&a);
    ck_assert_ptr_ne(limbs, NULL);
#if 64 == SC_LIMB_BITS
    ck_assert_uint_eq(limbs[0], 0);
    ck_assert_uint_eq(limbs[1], 1);
#else
    ck_assert_uint_eq(limbs[0], 0);
    ck_assert_uint_eq(limbs[1], 0);
    ck_assert_uint_eq(limbs[2], 1);
#endif

    // DON'T clear and initialise

    sc_mpz_set_str(&a, 16, "100000002000000030000000400000005");
    limbs = sc_mpz_get_limbs(&a);
    ck_assert_ptr_ne(limbs, NULL);
#if 64 == SC_LIMB_BITS
    ck_assert_uint_eq(limbs[0], 0x400000005);
    ck_assert_uint_eq(limbs[1], 0x200000003);
    ck_assert_uint_eq(limbs[2], 1);
#else
    ck_assert_uint_eq(limbs[0], 5);
    ck_assert_uint_eq(limbs[1], 4);
    ck_assert_uint_eq(limbs[2], 3);
    ck_assert_uint_eq(limbs[3], 2);
    ck_assert_uint_eq(limbs[4], 1);
#endif

    // DON'T clear and initialise

    sc_mpz_set_str(&a, 10, "18446744073709551617"); // 2^64 + 1
    limbs = sc_mpz_get_limbs(&a);
    ck_assert_ptr_ne(limbs, NULL);
#if 64 == SC_LIMB_BITS
    ck_assert_uint_eq(limbs[0], 1);
    ck_assert_uint_eq(limbs[1], 1);
#else
    ck_assert_uint_eq(limbs[0], 1);
    ck_assert_uint_eq(limbs[1], 0);
    ck_assert_uint_eq(limbs[2], 1);
#endif

    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpz_set_limbs)
{
    SINT32 result;
    sc_mpz_t a;
    sc_ulimb_t *out_limbs;
#if 64 == SC_LIMB_BITS
    sc_ulimb_t limbs[2];
    limbs[1] = 1;
    limbs[0] = 2;
#else
    sc_ulimb_t limbs[3];
    limbs[2] = 1;
    limbs[1] = 2;
    limbs[0] = 3;
#endif

    sc_mpz_init(&a);
    sc_mpz_set_limbs(&a, limbs, sizeof(limbs));
    out_limbs = sc_mpz_get_limbs(&a);
    ck_assert_ptr_ne(out_limbs, NULL);
#if 64 == SC_LIMB_BITS
    ck_assert_uint_eq(out_limbs[0], 2);
    ck_assert_uint_eq(out_limbs[1], 1);
#else
    ck_assert_uint_eq(out_limbs[0], 3);
    ck_assert_uint_eq(out_limbs[1], 2);
    ck_assert_uint_eq(out_limbs[2], 1);
#endif
    sc_mpz_clear(&a);
}
END_TEST

START_TEST(test_mpz_set_bytes)
{
    size_t i;
    SINT32 result;
    sc_mpz_t a;
    sc_ulimb_t *out_limbs;
    UINT8 bytes[17];
    for (i=0; i<17; i++) {
        bytes[i] = i;
    }

    sc_mpz_init(&a);
    sc_mpz_set_bytes(&a, bytes, 17);
    out_limbs = sc_mpz_get_limbs(&a);
    ck_assert_ptr_ne(out_limbs, NULL);
#if 64 == SC_LIMB_BITS
    ck_assert_uint_eq(out_limbs[0], 0x0706050403020100);
    ck_assert_uint_eq(out_limbs[1], 0x0F0E0D0C0B0A0908);
    ck_assert_uint_eq(out_limbs[2], 0x0000000000000010);
#else
    ck_assert_uint_eq(out_limbs[0], 0x03020100);
    ck_assert_uint_eq(out_limbs[1], 0x07060504);
    ck_assert_uint_eq(out_limbs[2], 0x0B0A0908);
    ck_assert_uint_eq(out_limbs[3], 0x0F0E0D0C);
    ck_assert_uint_eq(out_limbs[4], 0x00000010);
#endif
    sc_mpz_clear(&a);
}
END_TEST

Suite *mpi_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("mpi");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_mpz_init);
    tcase_add_test(tc_core, test_mpi_negate);
    tcase_add_test(tc_core, test_mpi_is_zero);
    tcase_add_test(tc_core, test_mpi_is_one);
    tcase_add_test(tc_core, test_mpi_is_neg);
    tcase_add_test(tc_core, test_mpi_add);
    tcase_add_test(tc_core, test_mpi_add_ui);
    tcase_add_test(tc_core, test_mpi_sub);
    tcase_add_test(tc_core, test_mpi_sub_ui);
    tcase_add_test(tc_core, test_mpi_mul);
    tcase_add_test(tc_core, test_mpi_mul_scalar);
    tcase_add_test(tc_core, test_mpi_mul_ui);
    tcase_add_test(tc_core, test_mpi_mul_si);
    tcase_add_test(tc_core, test_mpi_addmul);
    tcase_add_test(tc_core, test_mpi_submul);
    tcase_add_test(tc_core, test_mpi_addmul_ui);
    tcase_add_test(tc_core, test_mpi_submul_ui);
    tcase_add_test(tc_core, test_mpi_pow_ui);
    tcase_add_test(tc_core, test_mpi_div);
    tcase_add_test(tc_core, test_mpi_divrem);
    tcase_add_test(tc_core, test_mpi_divquo);
    tcase_add_test(tc_core, test_mpi_get_ui_mod);
    tcase_add_test(tc_core, test_mpi_gcd);
    tcase_add_test(tc_core, test_mpi_xgcd);
    tcase_add_test(tc_core, test_mpi_xgcd_2);
    tcase_add_test(tc_core, test_mpi_sign);
    tcase_add_test(tc_core, test_mpi_copy);
    tcase_add_test(tc_core, test_mpi_cmp);
    tcase_add_test(tc_core, test_mpi_cmp_d);
    tcase_add_test(tc_core, test_mpi_cmp_ui);
    tcase_add_test(tc_core, test_mpi_cmp_si);
    tcase_add_test(tc_core, test_mpi_cmpabs);
    tcase_add_test(tc_core, test_mpi_cmpabs_d);
    tcase_add_test(tc_core, test_mpi_cmpabs_ui);
    tcase_add_test(tc_core, test_mpi_invert);
    tcase_add_test(tc_core, test_mpz_set_str);
    tcase_add_test(tc_core, test_mpz_set_limbs);
    tcase_add_test(tc_core, test_mpz_set_bytes);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = mpi_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


