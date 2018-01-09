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
#include "schemes/sig/ring_tesla/ring_tesla.c"


START_TEST(test_ring_tesla_create_null)
{
    int32_t retcode;
    UINT32 flags[1] = {0};
    retcode = ring_tesla_create(NULL, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = ring_tesla_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
}
END_TEST

START_TEST(test_ring_tesla_create_good)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = ring_tesla_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = ring_tesla_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Ensure that the sampler and key pair memory are NULL pointers
    ck_assert_ptr_eq(sc->sampler, NULL);
    ck_assert_ptr_eq(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, 0);
    ck_assert_ptr_eq(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, 0);

    safecrypto_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Ensure that the key pair memory are NULL pointers
    ck_assert_ptr_eq(sc->pubkey, NULL);
    ck_assert_ptr_eq(sc->privkey, NULL);
}
END_TEST

START_TEST(test_ring_tesla_keygen)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = ring_tesla_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = ring_tesla_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    ck_assert_ptr_ne(sc->privkey, NULL);
    ck_assert_ptr_ne(sc->pubkey, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, 3 * sc->ring_tesla->params->n);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, 2 * sc->ring_tesla->params->n);

    retcode = ring_tesla_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_f_function)
{
    size_t i;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_RING_TESLA, 0, flags);
    UINT8 md[64] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    SINT32 s[512], c1[512] = {0}, c2[512] = {0};
    UINT16 omega = sc->ring_tesla->params->omega;

    f_function(sc, md, s, c1);
    f_function(sc, md, s, c2);

    for (i=0; i<omega; i++) {
        ck_assert_int_eq(c1[i], c2[i]);
    }

    safecrypto_destroy(sc);
}
END_TEST

Suite *ring_tesla_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_keygen, *tc_keys, *tc_f, *tc_sign;

    s = suite_create("ring_tesla");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_set_timeout(tc_core, 30.0f);
    tcase_add_test(tc_core, test_ring_tesla_create_null);
    tcase_add_test(tc_core, test_ring_tesla_create_good);
    tcase_add_test(tc_core, test_ring_tesla_keygen);
    suite_add_tcase(s, tc_core);

    tc_keygen = tcase_create("KEYGEN");
    suite_add_tcase(s, tc_keygen);

    tc_keys = tcase_create("KEYS");
    suite_add_tcase(s, tc_keys);

    tc_f = tcase_create("F_FUNCTION");
    tcase_set_timeout(tc_f, 20.0f);
    tcase_add_test(tc_f, test_f_function);
    suite_add_tcase(s, tc_f);

    tc_sign = tcase_create("SIGN");
    suite_add_tcase(s, tc_sign);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;
    s = ring_tesla_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

