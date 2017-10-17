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
#include "hash_drbg.h"

#ifndef CONSTRAINED_SYSTEM

#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
static void get_entropy(size_t n, UINT8 *data, user_entropy_t *p)
{
    UINT32 word;
    size_t i = 0;
    while (i < n) {
        if (0 == (i&3)) {
            word = random() ^ (random() << 1);
        }
        data[i] = word >> (8*(i&3));
        n--;
    }
}
#else // WINDOWS
#endif

START_TEST(test_hash_drbg_0)
{
    SINT32 retval;
    hash_drbg_t *ctx;
    static const UINT8 nonce[16] = "SAFEcrypto nonce";

    retval = hash_drbg_destroy(NULL);
    ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);

    // Invalid nonce pointer but correct length
    ctx = hash_drbg_create(get_entropy, NULL,
        CRYPTO_HASH_SHA3_512, 0, NULL, 16);
    ck_assert_ptr_eq(ctx, NULL);

    // Valid nonce pointer and correct length
    ctx = hash_drbg_create(get_entropy, NULL,
        CRYPTO_HASH_SHA3_512, 0, nonce, 16);
    ck_assert_ptr_ne(ctx, NULL);

    retval = hash_drbg_destroy(ctx);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_hash_drbg_1)
{
    size_t i;
    SINT32 retval;
    hash_drbg_t *ctx;
    UINT8 data[16];
    static const UINT8 nonce[16] = "SAFEcrypto nonce";

    // Invalid nonce length, must be half security strength
    ctx = hash_drbg_create(get_entropy, NULL,
        CRYPTO_HASH_SHA3_512, 0xFFFFFFFF, nonce, 0);
    ck_assert_ptr_eq(ctx, NULL);

    // Invalid nonce length, must be half security strength
    ctx = hash_drbg_create(get_entropy, NULL,
        CRYPTO_HASH_SHA3_512, 0, nonce, 15);
    ck_assert_ptr_eq(ctx, NULL);

    // Invalid nonce length, must be half security strength
    ctx = hash_drbg_create(get_entropy, NULL,
        CRYPTO_HASH_SHA3_512, 0, nonce, 16);
    ck_assert_ptr_ne(ctx, NULL);

    retval = hash_drbg_update(NULL, data, 16);
    ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);

    retval = hash_drbg_update(ctx, NULL, 16);
    ck_assert_int_eq(retval, PRNG_FUNC_FAILURE);

    retval = hash_drbg_update(ctx, data, 16);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    UINT8 OR = 0;
    for (i=0; i<16; i++) {
        OR |= data[i];
    }
    ck_assert_uint_ne(OR, 0);

    retval = hash_drbg_destroy(ctx);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_hash_drbg_2)
{
    size_t i;
    SINT32 retval;
    UINT8 data[16];
    static const UINT8 nonce[16] = "SAFEcrypto nonce";

    hash_drbg_t *ctx = hash_drbg_create(get_entropy, NULL,
        CRYPTO_HASH_SHA3_512, 0x00010000, nonce, 16);
    ck_assert_ptr_ne(ctx, NULL);

    for (i=0; i<4096; i++) {
        retval = hash_drbg_update(ctx, data, 16);
        ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
    }

    retval = hash_drbg_destroy(ctx);
    ck_assert_int_eq(retval, PRNG_FUNC_SUCCESS);
}
END_TEST

Suite *hash_drbg_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("HASH_DRBG");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_hash_drbg_0);
    tcase_add_test(tc_core, test_hash_drbg_1);
    tcase_add_test(tc_core, test_hash_drbg_2);
    suite_add_tcase(s, tc_core);

    return s;
}

#endif

int main(void)
{
#ifndef CONSTRAINED_SYSTEM
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = hash_drbg_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
#else
    return EXIT_SUCCESS;
#endif
}


