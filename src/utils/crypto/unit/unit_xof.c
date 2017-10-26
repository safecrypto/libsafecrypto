/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <stdlib.h>
#include <check.h>
#include "prng_types.h"
#include "xof.c"

#include <stdio.h>

START_TEST(test_create_destroy)
{
    size_t i;
    SINT32 retval;
    utils_crypto_xof_t *xof;

    // Create an instance of every type of xof and then destroy it
    for (i=0; i<(size_t)CRYPTO_XOF_MAX; i++) {
        xof = utils_crypto_xof_create((crypto_xof_e)i);
#ifdef ENABLE_SHAKE
        if ((crypto_xof_e)i == CRYPTO_XOF_SHAKE256 ||
            (crypto_xof_e)i == CRYPTO_XOF_SHAKE128) {
            ck_assert_ptr_ne(xof, NULL);
        }
#ifdef HAVE_AVX2
        if ((crypto_xof_e)i == CRYPTO_XOF_SHAKE256_4X ||
            (crypto_xof_e)i == CRYPTO_XOF_SHAKE128_4X) {
            ck_assert_ptr_ne(xof, NULL);
        }
#else
        if ((crypto_xof_e)i == CRYPTO_XOF_SHAKE256_4X ||
            (crypto_xof_e)i == CRYPTO_XOF_SHAKE128_4X) {
            ck_assert_ptr_eq(xof, NULL);
        }
#endif
#endif

        if (xof) {
            retval = utils_crypto_xof_destroy(xof);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
        }
    }
}
END_TEST

START_TEST(test_create_destroy_bad)
{
    SINT32 retval;
    utils_crypto_xof_t *xof;

    // Ensure that SC_HASH_MAX is not a valid xof type
    xof = utils_crypto_xof_create(CRYPTO_XOF_MAX);
    ck_assert_ptr_eq(xof, NULL);

    // Ensure that SC_HASH_MAX + 1 is not a valid xof type
    xof = utils_crypto_xof_create(CRYPTO_XOF_MAX + 1);
    ck_assert_ptr_eq(xof, NULL);

    // Ensure that 0xFFFFFFFF is not a valid xof type
    xof = utils_crypto_xof_create((crypto_xof_e)0xFFFFFFFF);
    ck_assert_ptr_eq(xof, NULL);

    // ENsure that a NULL pointer cannot be destroyed
    retval = utils_crypto_xof_destroy(NULL);
    ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
}
END_TEST

START_TEST(test_create_destroy_init)
{
    SINT32 retval;
    utils_crypto_xof_t *xof;

    // Create/destroy an instance of every type of hash and
    // ensure that its initial state can be setup

#ifdef ENABLE_SHAKE
    xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE256);
    ck_assert_ptr_ne(xof, NULL);
    retval = xof_init(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_xof_destroy(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128);
    ck_assert_ptr_ne(xof, NULL);
    retval = xof_init(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_xof_destroy(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

#ifdef HAVE_AVX2
    xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE256_4X);
    ck_assert_ptr_ne(xof, NULL);
    retval = xof_init(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_xof_destroy(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128_4X);
    ck_assert_ptr_ne(xof, NULL);
    retval = xof_init(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_xof_destroy(xof);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
#else
    xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE256_4X);
    ck_assert_ptr_eq(xof, NULL);

    xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128_4X);
    ck_assert_ptr_eq(xof, NULL);
#endif
#endif
}
END_TEST

START_TEST(test_input_bad)
{
    size_t i;
    SINT32 retval;
    utils_crypto_xof_t *xof;
    UINT8 md[64];
    static const UINT8 msg[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };

    // Create an instance of every type of hash and perform a full
    // hash operation, but try to use NULL pointers
    for (i=0; i<(size_t)CRYPTO_XOF_MAX; i++) {
        xof = utils_crypto_xof_create((crypto_xof_e)i);

        // Some hash algorithms may be disabled, if not test their interface
        if (NULL != xof) {
            retval = xof_init(NULL);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = xof_init(xof);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = xof_absorb(NULL, NULL, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = xof_absorb(NULL, msg, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = xof_absorb(xof, NULL, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = xof_absorb(xof, msg, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            xof_final(xof);

            retval = xof_squeeze(NULL, NULL, 64);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = xof_squeeze(NULL, md, 64);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = xof_squeeze(xof, NULL, 64);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = xof_squeeze(xof, md, 64);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = utils_crypto_xof_destroy(xof);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
        }
    }
}
END_TEST

START_TEST(test_full)
{
    size_t i, j;
    SINT32 retval;
    utils_crypto_xof_t *xof;
    UINT8 md[512];
    static const UINT8 msg[127] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
    };

    // Create an instance of every type of XOF, perform a small
    // operation and then destroy the instance
    for (i=0; i<(size_t)CRYPTO_XOF_MAX; i++) {
        xof = utils_crypto_xof_create((crypto_xof_e)i);

        // Some hash algorithms may be disabled, if not test their interface
        if (NULL != xof) {
            SINT32 equal = 1;
            retval = xof_init(xof);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = xof_absorb(xof, msg, 127);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = xof_absorb(xof, msg, 127);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = xof_final(xof);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = xof_squeeze(xof, md, 256);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = xof_squeeze(xof, md+256, 256);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            fprintf(stderr, "output[%zu] = ", i);
            for (j=0; j<512; j++) {
                fprintf(stderr, "%02X ", md[j]);
            }
            fprintf(stderr, "\n");

            for (j=0; j<256; j++) {
                if (md[j] != md[j+256]) equal = 0;
            }
            ck_assert_uint_eq(equal, 0);

            retval = utils_crypto_xof_destroy(xof);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
        }
    }
}
END_TEST

Suite *xof_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("xof");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_create_destroy);
    tcase_add_test(tc_core, test_create_destroy_bad);
    tcase_add_test(tc_core, test_create_destroy_init);
    tcase_add_test(tc_core, test_input_bad);
    tcase_add_test(tc_core, test_full);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = xof_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


