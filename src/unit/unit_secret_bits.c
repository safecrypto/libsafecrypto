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
#include "utils/ecc/secret_bits.c"

START_TEST(test_secret_bits_init_binary)
{
    size_t bits;
    ecc_k_coding_e coding = ECC_K_BINARY;
    point_secret_t bit_ctx;
    sc_ulimb_t secret[2] = {0};

    bits = secret_bits_init(coding, NULL, secret, NULL, 0);
    ck_assert_uint_eq(bits, 0);

    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 0);
    ck_assert_uint_eq(bits, 0);

    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 1);
    ck_assert_uint_eq(bits, 0);

    secret[0] = 2;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 1);
    ck_assert_uint_eq(bits, 0);

    secret[0] = 4;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 3);
    ck_assert_uint_eq(bits, 3);

    secret[0] = SC_LIMB_HIGHBIT;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, SC_LIMB_BITS);
    ck_assert_uint_eq(bits, SC_LIMB_BITS);

    secret[1] = SC_LIMB_HIGHBIT2;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, SC_LIMB_BITS + SC_LIMB_BITS2 - 1);
    ck_assert_uint_eq(bits, SC_LIMB_BITS);
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, SC_LIMB_BITS + SC_LIMB_BITS2);
    ck_assert_uint_eq(bits, SC_LIMB_BITS + SC_LIMB_BITS2);

    secret[0] = SC_LIMB_MASK;
    secret[1] = SC_LIMB_MASK_LOW;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, SC_LIMB_BITS + SC_LIMB_BITS2 - 1);
    ck_assert_uint_eq(bits, SC_LIMB_BITS + SC_LIMB_BITS2 - 1);
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, SC_LIMB_BITS + SC_LIMB_BITS2);
    ck_assert_uint_eq(bits, SC_LIMB_BITS + SC_LIMB_BITS2);
}
END_TEST

START_TEST(test_secret_bits_init_naf)
{
    size_t bits;
    ecc_k_coding_e coding = ECC_K_NAF_2;
    point_secret_t bit_ctx;
    sc_ulimb_t secret[3] = {0};

    bits = secret_bits_init(coding, NULL, secret, NULL, 0);
    ck_assert_uint_eq(bits, 0);

    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 1);
    ck_assert_uint_eq(bits, 0);

    secret[0] = 2;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 1);
    ck_assert_uint_eq(bits, 0);

    secret[0] = 4;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 3);
    ck_assert_uint_eq(bits, 3);

    secret[0] = 12;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 3);
    ck_assert_uint_eq(bits, 3);

    secret[0] = 0xFFFF;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 16);
    ck_assert_uint_eq(bits, 17);

    secret[0] = SC_LIMB_MASK;
    secret[1] = SC_LIMB_MASK_LOW;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, SC_LIMB_BITS + SC_LIMB_BITS2);
    ck_assert_uint_eq(bits, SC_LIMB_BITS + SC_LIMB_BITS2 + 1);

    secret[0] = SC_LIMB_MASK;
    secret[1] = SC_LIMB_MASK;
    secret[2] = SC_LIMB_MASK;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 3*SC_LIMB_BITS);
    ck_assert_uint_eq(bits, 3*SC_LIMB_BITS + 1);
}
END_TEST

START_TEST(test_secret_bits_naf)
{
    UINT32 data;
    size_t bits, i;
    ecc_k_coding_e coding = ECC_K_NAF_2;
    point_secret_t bit_ctx;
    sc_ulimb_t secret[4] = {0};

    secret[0] = SC_LIMB_MASK;
    secret[1] = SC_LIMB_MASK_LOW;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, SC_LIMB_BITS + SC_LIMB_BITS2);
    ck_assert_uint_eq(bits, SC_LIMB_BITS + SC_LIMB_BITS2 + 1);

    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_HIGH);
    for (i=0; i<SC_LIMB_BITS + SC_LIMB_BITS2 - 1; i++) {
        data = secret_bits_pull(&bit_ctx);
        ck_assert_uint_eq(data, ECC_K_IS_LOW);
    }
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
}
END_TEST

START_TEST(test_secret_bits_naf_2)
{
    UINT32 data;
    size_t bits, i;
    ecc_k_coding_e coding = ECC_K_NAF_2;
    point_secret_t bit_ctx;
    sc_ulimb_t secret[9] = {0};

    secret[0] = SC_LIMB_MASK;
    secret[1] = SC_LIMB_MASK;
    secret[2] = SC_LIMB_MASK;
    secret[3] = SC_LIMB_MASK;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 4*SC_LIMB_BITS);
    ck_assert_uint_eq(bits, 4*SC_LIMB_BITS + 1);

    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_HIGH);
    for (i=0; i<4*SC_LIMB_BITS - 1; i++) {
        data = secret_bits_pull(&bit_ctx);
        ck_assert_uint_eq(data, ECC_K_IS_LOW);
    }
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
}
END_TEST

START_TEST(test_secret_bits_naf_3)
{
    UINT32 data;
    size_t bits, i;
    ecc_k_coding_e coding = ECC_K_NAF_2;
    point_secret_t bit_ctx;
    sc_ulimb_t secret[9] = {0};

    secret[0] = 0;
    secret[1] = SC_LIMB_MASK;
    secret[2] = 0;
    secret[3] = SC_LIMB_MASK;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 4*SC_LIMB_BITS);
    ck_assert_uint_eq(bits, 4*SC_LIMB_BITS + 1);

    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_HIGH);
    for (i=0; i<SC_LIMB_BITS - 1; i++) {
        data = secret_bits_pull(&bit_ctx);
        ck_assert_uint_eq(data, ECC_K_IS_LOW);
    }
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
    for (i=0; i<SC_LIMB_BITS - 1; i++) {
        data = secret_bits_pull(&bit_ctx);
        ck_assert_uint_eq(data, ECC_K_IS_LOW);
    }
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_HIGH);
    for (i=0; i<SC_LIMB_BITS - 1; i++) {
        data = secret_bits_pull(&bit_ctx);
        ck_assert_uint_eq(data, ECC_K_IS_LOW);
    }
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
}
END_TEST

START_TEST(test_secret_bits_naf_4)
{
    UINT32 data;
    size_t bits, i;
    ecc_k_coding_e coding = ECC_K_NAF_2;
    point_secret_t bit_ctx;
    sc_ulimb_t secret[2] = {0};

    secret[0] = 0xacb;
    bits = secret_bits_init(coding, &bit_ctx, secret, NULL, 12);
    ck_assert_uint_eq(bits, 13);

    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_HIGH);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_LOW);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_LOW);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_LOW);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_LOW);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_HIGH);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_LOW);
    data = secret_bits_pull(&bit_ctx);
    ck_assert_uint_eq(data, ECC_K_IS_MINUS_ONE);
}
END_TEST

Suite *secret_bits_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("SECRET_BITS");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_secret_bits_init_binary);
    tcase_add_test(tc_core, test_secret_bits_init_naf);
    tcase_add_test(tc_core, test_secret_bits_naf);
    tcase_add_test(tc_core, test_secret_bits_naf_2);
    tcase_add_test(tc_core, test_secret_bits_naf_3);
    tcase_add_test(tc_core, test_secret_bits_naf_4);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = secret_bits_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


