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

// To get access to static functions in C ...
#include "schemes/enc/rlwe_enc/rlwe_enc.c"


START_TEST(test_rlwe_enc_create_null)
{
    int32_t retcode;
    UINT32 flags[1] = {0};
    retcode = rlwe_enc_create(NULL, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = rlwe_enc_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
}
END_TEST

START_TEST(test_rlwe_enc_create_good)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = rlwe_enc_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = rlwe_enc_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Ensure that the sampler and key pair memory are NULL pointers
    ck_assert_ptr_eq(sc->sampler, NULL);
    ck_assert_ptr_eq(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, 0);
    ck_assert_ptr_eq(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, 0);

    retcode = safecrypto_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Ensure that the key pair memory are NULL pointers
    ck_assert_ptr_eq(sc->pubkey, NULL);
    ck_assert_ptr_eq(sc->privkey, NULL);
}
END_TEST

START_TEST(test_rlwe_enc_keygen)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = rlwe_enc_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = rlwe_enc_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    ck_assert_ptr_ne(sc->privkey, NULL);
    ck_assert_ptr_ne(sc->pubkey, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, sc->rlwe_enc->params->n);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, 2 * sc->rlwe_enc->params->n);

    retcode = rlwe_enc_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_rlwe_enc_keygen_null)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = rlwe_enc_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = rlwe_enc_keygen(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = rlwe_enc_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

Suite *rlwe_enc_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_keygen;

    s = suite_create("RLWE Enc");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_rlwe_enc_create_null);
    tcase_add_test(tc_core, test_rlwe_enc_create_good);
    suite_add_tcase(s, tc_core);

    tc_keygen = tcase_create("KEYGEN");
    tcase_add_test(tc_keygen, test_rlwe_enc_keygen);
    tcase_add_test(tc_keygen, test_rlwe_enc_keygen_null);
    suite_add_tcase(s, tc_keygen);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = rlwe_enc_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

