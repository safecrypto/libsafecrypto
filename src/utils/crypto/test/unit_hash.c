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
#include "hash.c"


START_TEST(test_create_destroy)
{
    size_t i;
    SINT32 retval;
    utils_crypto_hash_t *hash;

    // Create an instance of every type of hash and then destroy it
    for (i=0; i<(size_t)SC_HASH_MAX; i++) {
        hash = utils_crypto_hash_create((safecrypto_hash_e)i);
#ifdef ENABLE_SHA3
        if ((safecrypto_hash_e)i == SC_HASH_SHA3_512 ||
            (safecrypto_hash_e)i == SC_HASH_SHA3_384 ||
            (safecrypto_hash_e)i == SC_HASH_SHA3_256 ||
            (safecrypto_hash_e)i == SC_HASH_SHA3_224) {
            ck_assert_ptr_ne(hash, NULL);
        }
#endif
#ifdef ENABLE_SHA2
        if ((safecrypto_hash_e)i == SC_HASH_SHA2_512 ||
            (safecrypto_hash_e)i == SC_HASH_SHA2_384 ||
            (safecrypto_hash_e)i == SC_HASH_SHA2_256 ||
            (safecrypto_hash_e)i == SC_HASH_SHA2_224) {
            ck_assert_ptr_ne(hash, NULL);
        }
#endif
#ifdef ENABLE_BLAKE2
        if ((safecrypto_hash_e)i == SC_HASH_BLAKE2_512 ||
            (safecrypto_hash_e)i == SC_HASH_BLAKE2_384 ||
            (safecrypto_hash_e)i == SC_HASH_BLAKE2_256 ||
            (safecrypto_hash_e)i == SC_HASH_BLAKE2_224) {
            ck_assert_ptr_ne(hash, NULL);
        }
#endif
#ifdef ENABLE_WHIRLPOOl
        if ((safecrypto_hash_e)i == SSC_HASH_WHIRLPOOL_512) {
            ck_assert_ptr_ne(hash, NULL);
        }
#endif

        if (hash) {
            retval = utils_crypto_hash_destroy(hash);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
        }
    }
}
END_TEST

START_TEST(test_create_destroy_bad)
{
    SINT32 retval;
    utils_crypto_hash_t *hash;

    // Ensure that SC_HASH_MAX is not a valid hash type
    hash = utils_crypto_hash_create(SC_HASH_MAX);
    ck_assert_ptr_eq(hash, NULL);

    // Ensure that SC_HASH_MAX + 1 is not a valid hash type
    hash = utils_crypto_hash_create(SC_HASH_MAX + 1);
    ck_assert_ptr_eq(hash, NULL);

    // Ensure that 0xFFFFFFFF is not a valid hash type
    hash = utils_crypto_hash_create((safecrypto_hash_e)0xFFFFFFFF);
    ck_assert_ptr_eq(hash, NULL);

    // ENsure that a NULL pointer cannot be destroyed
    retval = utils_crypto_hash_destroy(NULL);
    ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
}
END_TEST

START_TEST(test_create_destroy_init)
{
    SINT32 retval;
    utils_crypto_hash_t *hash;

    // Create/destroy an instance of every type of hash and
    // ensure that its initial state can be setup

#ifdef ENABLE_SHA3
    hash = utils_crypto_hash_create(SC_HASH_SHA3_512);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_SHA3_384);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_SHA3_256);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_SHA3_224);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
#endif

#ifdef ENABLE_SHA2
    hash = utils_crypto_hash_create(SC_HASH_SHA2_512);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_SHA2_384);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_SHA2_256);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_SHA2_224);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
#endif

#ifdef ENABLE_BLAKE2
    hash = utils_crypto_hash_create(SC_HASH_BLAKE2_512);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_BLAKE2_384);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_BLAKE2_256);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

    hash = utils_crypto_hash_create(SC_HASH_BLAKE2_224);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
#endif

#ifdef ENABLE_WHIRLPOOL
    hash = utils_crypto_hash_create(SC_HASH_WHIRLPOOL_512);
    ck_assert_ptr_ne(hash, NULL);
    retval = hash_init(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    retval = utils_crypto_hash_destroy(hash);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
#endif
}
END_TEST

START_TEST(test_input_bad)
{
    size_t i;
    SINT32 retval;
    utils_crypto_hash_t *hash;
    UINT8 md[64];
    static const UINT8 msg[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };

    // Create an instance of every type of hash and perform a full
    // hash operation, but try to use NULL pointers
    for (i=0; i<(size_t)SC_HASH_MAX; i++) {
        hash = utils_crypto_hash_create((safecrypto_hash_e)i);

        // Some hash algorithms may be disabled, if not test their interface
        if (NULL != hash) {
            retval = hash_init(NULL);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = hash_init(hash);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = hash_update(NULL, NULL, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = hash_update(NULL, msg, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = hash_update(hash, NULL, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = hash_update(hash, msg, 16);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = hash_final(NULL, NULL);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = hash_final(NULL, md);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = hash_final(hash, NULL);
            ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);
            retval = hash_final(hash, md);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = utils_crypto_hash_destroy(hash);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
        }
    }
}
END_TEST

START_TEST(test_full)
{
    size_t i;
    SINT32 retval;
    utils_crypto_hash_t *hash;
    UINT8 md[64];
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

    // Create an instance of every type of hash, perform a small
    // hash operation and then destroy the instance
    for (i=0; i<(size_t)SC_HASH_MAX; i++) {
        hash = utils_crypto_hash_create((safecrypto_hash_e)i);

        // Some hash algorithms may be disabled, if not test their interface
        if (NULL != hash) {
            retval = hash_init(hash);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = hash_update(hash, msg, 127);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = hash_final(hash, md);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);

            retval = utils_crypto_hash_destroy(hash);
            ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
        }
    }
}
END_TEST

Suite *hash_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("hash");

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

    s = hash_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


