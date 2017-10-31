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
#include "prng_types.h"
#include "prng.c"

START_TEST(test_prng_create)
{
    SINT32 retval;
    prng_ctx_t *prng;
    prng = prng_create(-1, -1, SC_PRNG_THREADING_NONE, 0x00100000);
    ck_assert_ptr_eq(prng, NULL);
    prng = prng_create(-1, SC_PRNG_SYSTEM, SC_PRNG_THREADING_NONE, 0x00100000);
    ck_assert_ptr_eq(prng, NULL);
    prng = prng_create(SC_ENTROPY_RANDOM, -1, SC_PRNG_THREADING_NONE, 0x00100000);
    ck_assert_ptr_eq(prng, NULL);
    prng = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM, SC_PRNG_THREADING_NONE, 0x00100000);
    ck_assert_ptr_ne(prng, NULL);
    retval = prng_destroy(NULL);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);
    retval = prng_destroy(prng);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

static void prng_entropy_source(size_t n, UINT8 *data)
{
    size_t i;
    for (i=0; i<n; i++) {
        data[i] = i;
    }
}

START_TEST(test_prng_entropy_callback)
{
    size_t i;
    SINT32 retval;
    UINT32 sum = 0, ave;
    int32_t bit;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_CALLBACK, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy_callback((void*)prng_entropy_source);
    prng_init(prng_ctx, NULL, 0);

    UINT8 mem[16];
    (void)prng_mem(prng_ctx, mem, 16);
    for (i=0; i<16; i++)
        sum += (double)mem[i];
    ave = sum / 16;
    ck_assert_int_ne(ave, 0);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

#ifdef ENABLE_ISAAC
START_TEST(test_prng_bit_isaac)
{
    SINT32 retval;
    int32_t bit;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    bit = prng_bit(prng_ctx);
    ck_assert_int_lt(bit, 2);
    ck_assert_int_ge(bit, 0);
    bit = prng_bit(prng_ctx);
    ck_assert_int_lt(bit, 2);
    ck_assert_int_ge(bit, 0);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_var_isaac)
{
    SINT32 retval;
    int32_t bit;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    for (size_t i=0; i<16384; i++) {
        bit = prng_var(prng_ctx, 0);
        ck_assert_int_eq(bit, 0);
        bit = prng_var(prng_ctx, 1);
        ck_assert_int_lt(bit, 2);
        ck_assert_int_ge(bit, 0);
        bit = prng_var(prng_ctx, 2);
        ck_assert_int_lt(bit, 4);
        ck_assert_int_ge(bit, 0);
        bit = prng_var(prng_ctx, 27);
        ck_assert_int_lt(bit, 0x08000000);
        ck_assert_int_ge(bit, 0);
        bit = prng_var(prng_ctx, 31);
        ck_assert_int_lt(bit, 0x80000000);
        ck_assert_int_ge(bit, 0);
    }
    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_u32_isaac)
{
    SINT32 retval;
    size_t i;
    uint32_t u32_or = 0;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    prng_reset(prng_ctx);
    for (i=0; i<16384; i++) {
        uint32_t u32 = prng_32(prng_ctx);
        u32_or |= u32;
    }
    ck_assert_int_eq(u32_or, 0xFFFFFFFF);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_u64_isaac)
{
    SINT32 retval;
    size_t i;
    uint64_t u64_or = 0;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    prng_reset(prng_ctx);
    for (i=0; i<16384; i++) {
        uint64_t u64 = prng_64(prng_ctx);
        u64_or |= u64;
    }
    ck_assert_uint_eq(u64_or, 0xFFFFFFFFFFFFFFFF);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_u128_isaac)
{
#ifdef HAVE_128BIT
    SINT32 retval;
    size_t i;
    uint128_t u128_or = 0;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    prng_reset(prng_ctx);
    for (i=0; i<16384; i++) {
        uint128_t u128 = prng_128(prng_ctx);
        u128_or |= u128;
    }
    ck_assert_uint_eq(u128_or & 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
    ck_assert_uint_eq(u128_or >> 64, 0xFFFFFFFFFFFFFFFF);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
#endif
}
END_TEST

START_TEST(test_prng_mem_isaac)
{
    SINT32 retval;
    int32_t i;
    double sum = 0;
    int ave;
    uint8_t *mem;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    mem = malloc(16);
    prng_reset(prng_ctx);
    (void)prng_mem(prng_ctx, mem, 16);
    for (i=0; i<16; i++)
        sum += (double)mem[i];
    ave = sum / 16;
    ck_assert_int_ne(ave, 0);
    free(mem);

    mem = malloc(32768);
    prng_reset(prng_ctx);
    (void)prng_mem(prng_ctx, mem, 32768);
    for (i=0; i<32768; i++)
        sum += (double)mem[i];
    ave = sum / (double)32768;
    ck_assert_int_gt(ave, 0);
    ck_assert_int_lt(ave, 255);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST
#endif

#ifdef ENABLE_KISS
START_TEST(test_prng_bit_kiss)
{
    SINT32 retval;
    int32_t bit;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_KISS,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    bit = prng_bit(prng_ctx);
    ck_assert_int_lt(bit, 2);
    ck_assert_int_ge(bit, 0);
    bit = prng_bit(prng_ctx);
    ck_assert_int_lt(bit, 2);
    ck_assert_int_ge(bit, 0);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_var_kiss)
{
    SINT32 retval;
    int32_t bit;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_KISS,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    for (size_t i=0; i<16384; i++) {
        bit = prng_var(prng_ctx, 0);
        ck_assert_int_eq(bit, 0);
        bit = prng_var(prng_ctx, 1);
        ck_assert_int_lt(bit, 2);
        ck_assert_int_ge(bit, 0);
        bit = prng_var(prng_ctx, 2);
        ck_assert_int_lt(bit, 4);
        ck_assert_int_ge(bit, 0);
        bit = prng_var(prng_ctx, 27);
        ck_assert_int_lt(bit, 0x08000000);
        ck_assert_int_ge(bit, 0);
        bit = prng_var(prng_ctx, 31);
        ck_assert_int_lt(bit, 0x80000000);
        ck_assert_int_ge(bit, 0);
    }

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_u32_kiss)
{
    SINT32 retval;
    size_t i;
    uint32_t u32_or = 0;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_KISS,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    prng_reset(prng_ctx);
    for (i=0; i<16384; i++) {
        uint32_t u32 = prng_32(prng_ctx);
        u32_or |= u32;
    }
    ck_assert_int_eq(u32_or, 0xFFFFFFFF);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_u64_kiss)
{
    SINT32 retval;
    size_t i;
    uint64_t u64_or = 0;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_KISS,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    prng_reset(prng_ctx);
    for (i=0; i<16384; i++) {
        uint64_t u64 = prng_64(prng_ctx);
        u64_or |= u64;
    }
    ck_assert_uint_eq(u64_or, 0xFFFFFFFFFFFFFFFF);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_prng_u128_kiss)
{
#ifdef HAVE_128BIT
    SINT32 retval;
    size_t i;
    uint128_t u128_or = 0;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_KISS,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    prng_reset(prng_ctx);
    for (i=0; i<16384; i++) {
        uint128_t u128 = prng_128(prng_ctx);
        u128_or |= u128;
    }
    ck_assert_uint_eq(u128_or & 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
    ck_assert_uint_eq(u128_or >> 64, 0xFFFFFFFFFFFFFFFF);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
#endif
}
END_TEST

START_TEST(test_prng_mem_kiss)
{
    SINT32 retval;
    int32_t i;
    double sum = 0;
    int ave;
    uint8_t *mem;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_KISS,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    mem = malloc(16);
    prng_reset(prng_ctx);
    (void)prng_mem(prng_ctx, mem, 16);
    for (i=0; i<16; i++)
        sum += (double)mem[i];
    ave = sum / 16;
    ck_assert_int_ne(ave, 0);
    free(mem);

    mem = malloc(32768);
    prng_reset(prng_ctx);
    (void)prng_mem(prng_ctx, mem, 32768);
    for (i=0; i<32768; i++)
        sum += (double)mem[i];
    ave = sum / (double)32768;
    ck_assert_int_gt(ave, 0);
    ck_assert_int_lt(ave, 255);

    retval = prng_destroy(prng_ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST
#endif

Suite *prng_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_isaac, *tc_kiss;

    s = suite_create("PRNG");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_prng_create);
    tcase_add_test(tc_core, test_prng_entropy_callback);
    suite_add_tcase(s, tc_core);

#ifdef ENABLE_ISAAC
    tc_isaac = tcase_create("ISAAC");
    tcase_add_test(tc_isaac, test_prng_bit_isaac);
    tcase_add_test(tc_isaac, test_prng_var_isaac);
    tcase_add_test(tc_isaac, test_prng_u32_isaac);
    tcase_add_test(tc_isaac, test_prng_u64_isaac);
    tcase_add_test(tc_isaac, test_prng_u128_isaac);
    tcase_add_test(tc_isaac, test_prng_mem_isaac);
    suite_add_tcase(s, tc_isaac);
#endif

#ifdef ENABLE_KISS
    tc_kiss = tcase_create("KISS");
    tcase_add_test(tc_kiss, test_prng_bit_kiss);
    tcase_add_test(tc_kiss, test_prng_var_kiss);
    tcase_add_test(tc_kiss, test_prng_u32_kiss);
    tcase_add_test(tc_kiss, test_prng_u64_kiss);
    tcase_add_test(tc_kiss, test_prng_u128_kiss);
    tcase_add_test(tc_kiss, test_prng_mem_kiss);
    suite_add_tcase(s, tc_kiss);
#endif
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = prng_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


