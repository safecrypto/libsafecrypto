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
#include "schemes/sig/bliss_b/bliss_b.c"


START_TEST(test_bliss_b_create_null)
{
    int32_t retcode;
    UINT32 flags[1] = {0};
    retcode = bliss_b_create(NULL, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = bliss_b_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
}
END_TEST

START_TEST(test_bliss_b_create_good)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = bliss_b_destroy(sc);
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

START_TEST(test_bliss_b_keygen)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = bliss_b_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    ck_assert_ptr_ne(sc->privkey, NULL);
    ck_assert_ptr_ne(sc->pubkey, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, 2 * sc->bliss->params->n);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, sc->bliss->params->n);

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_keygen_null)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = bliss_b_keygen(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_oracle_bad)
{
    int32_t retcode;
    int32_t *c_idx= NULL;
    int16_t *z = NULL;
    uint16_t n = 0, mask=0, kappa = 0;
    uint8_t *m = NULL;
    int32_t m_len = 0;
    safecrypto_t *sc = NULL;
    UINT32 flags[1] = {0};

    retcode = oracle(sc, c_idx, kappa, m, m_len, z, n, mask);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    c_idx = NULL;
    m = (void*) 1;
    z = (void*) 1;
    retcode = oracle(sc, c_idx, kappa, m, m_len, z, n, mask);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    m = NULL;
    c_idx = (void*) 1;
    z = (void*) 1;
    retcode = oracle(sc, c_idx, kappa, m, m_len, z, n, mask);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    z = NULL;
    c_idx = (void*) 1;
    m = (void*) 1;
    retcode = oracle(sc, c_idx, kappa, m, m_len, z, n, mask);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_oracle_good)
{
    int32_t retcode;
    int32_t c_idx[6] = {0};
    int16_t z[8] = {0};
    uint16_t n = 8, mask = 7, kappa = 6;
    uint8_t m[4] = {0x01, 0x23, 0x45, 0x67};
    int32_t m_len = 4;
    safecrypto_t *sc = NULL;
    UINT32 flags[1] = {0};

    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = oracle(sc, c_idx, kappa, m, m_len, z, n, mask);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_greedy_sc_bad)
{
    int32_t retcode;
    int32_t *c_idx = NULL;
    uint16_t n = 0, kappa = 0;
    int16_t *f = NULL;
    int16_t *g = NULL;
    int32_t *x = NULL;
    int32_t *y = NULL;
    safecrypto_t *sc = NULL;
    UINT32 flags[1] = {0};

    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    f = (void*) 1;
    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    g = (void*) 1;
    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    c_idx = (void*) 1;
    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    x = (void*) 1;
    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    y = (void*) 1;
    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    n = 4;
    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    n = 0;
    kappa = 1;
    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_greedy_sc_good)
{
    int32_t retcode;
    int32_t c_idx[6] = {0};
    uint16_t n = 4, kappa = 6;
    int16_t f[4] = {0x01, 0x23, 0x45, 0x67};
    int16_t g[4] = {0x89, 0xAB, 0xCD, 0xEF};
    int32_t x[4] = {0};
    int32_t y[4] = {0};
    safecrypto_t *sc = NULL;
    UINT32 flags[1] = {0};

    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = greedy_sc(sc, f, g, n, c_idx, kappa, x, y);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_keys_pub_load)
{
    SINT32 retcode;
    UINT8 *pubkey = NULL;
    size_t len;
    safecrypto_t *sc = NULL;
    UINT32 flags[1] = {0};

    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Generate a key-pair
    retcode = bliss_b_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Copy the public key for later comparison
    SINT16 *key = malloc(sc->pubkey->len * sizeof(SINT16));
    memcpy(key, sc->pubkey->key, sc->pubkey->len * sizeof(SINT16));

    // Extract the public key
    len = 0;
    retcode = bliss_b_pubkey_encode(sc, &pubkey, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(pubkey, NULL);
    ck_assert_int_ge(len, 0);

    // Destroy and create the SAFEcrypto object (destroying the key-pair)
    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    safecrypto_destroy(sc);
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);
    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(sc->pubkey, NULL);

    // Load the public key
    retcode = bliss_b_pubkey_load(sc, pubkey, len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);

    // Compare the original public key and the encoded/loaded version
    size_t i;
    for (i=0; i<sc->pubkey->len; i++) {
        ck_assert_int_eq(key[i], ((SINT16 *)sc->pubkey->key)[sc->bliss->params->n+i]);
    }

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_keys_priv_load)
{
    size_t i;
    SINT32 retcode;
    UINT8 *pubkey = NULL, *privkey = NULL;
    size_t len, privlen;
    safecrypto_t *sc = NULL;
    UINT32 flags[1] = {0};

    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Generate a key-pair
    retcode = bliss_b_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Copy the key-pair for later comparison
    SINT16 *key = malloc((sc->privkey->len + sc->pubkey->len) * sizeof(SINT16));
    memcpy(key, sc->pubkey->key, sc->pubkey->len * sizeof(SINT16));
    memcpy(key + sc->pubkey->len, sc->privkey->key, sc->privkey->len * sizeof(SINT16));

    // Extract the private key-pair
    len = 0;
    retcode = bliss_b_pubkey_encode(sc, &pubkey, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    privlen = 0;
    retcode = bliss_b_privkey_encode(sc, &privkey, &privlen);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(pubkey, NULL);
    ck_assert_int_ge(len, 0);
    ck_assert_ptr_ne(privkey, NULL);
    ck_assert_int_ge(privlen, 0);

    // Destroy and create the SAFEcrypto object (destroying the key-pair)
    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    safecrypto_destroy(sc);
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);
    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(sc->pubkey, NULL);

    // Load the private key
    retcode = bliss_b_pubkey_load(sc, pubkey, len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = bliss_b_privkey_load(sc, privkey, privlen);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);

    // Compare the original public key and the encoded/loaded version
    for (i=0; i<sc->pubkey->len; i++) {
        ck_assert_int_eq(key[i], ((SINT16 *)sc->pubkey->key)[i]);
    }
    for (i=0; i<sc->privkey->len; i++) {
        ck_assert_int_eq(key[sc->pubkey->len + i], ((SINT16 *)sc->privkey->key)[i]);
    }

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_coding)
{
    size_t i;
    SINT32 retcode;
    UINT8 *pubkey = NULL, *privkey = NULL;
    size_t len, privlen;
    safecrypto_t *sc = NULL;
    UINT32 flags[1] = {0};
    sc_entropy_type_e pub, priv;

    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Generate a key-pair with key coding 
    retcode = bliss_b_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = bliss_b_set_key_coding(sc, SC_ENTROPY_NONE, SC_ENTROPY_NONE);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = bliss_b_get_key_coding(sc, &pub, &priv);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_eq(pub, SC_ENTROPY_NONE);
    ck_assert_int_eq(priv, SC_ENTROPY_NONE);
    retcode = bliss_b_set_key_coding(sc, SC_ENTROPY_BAC, SC_ENTROPY_HUFFMAN_STATIC);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = bliss_b_get_key_coding(sc, &pub, &priv);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_eq(pub, SC_ENTROPY_NONE);
    ck_assert_int_eq(priv, SC_ENTROPY_HUFFMAN_STATIC);
    retcode = bliss_b_set_key_coding(sc, SC_ENTROPY_HUFFMAN_STATIC, SC_ENTROPY_BAC);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = bliss_b_get_key_coding(sc, &pub, &priv);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_eq(pub, SC_ENTROPY_NONE);
    ck_assert_int_eq(priv, SC_ENTROPY_BAC);
    retcode = bliss_b_set_key_coding(sc, SC_ENTROPY_NONE, SC_ENTROPY_BAC_RLE);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = bliss_b_get_key_coding(sc, &pub, &priv);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_eq(pub, SC_ENTROPY_NONE);
    ck_assert_int_eq(priv, SC_ENTROPY_NONE);

    // Generate a key-pair with key coding 
    retcode = bliss_b_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Copy the key-pair for later comparison
    SINT16 *key = malloc((sc->privkey->len + sc->pubkey->len) * sizeof(SINT16));
    memcpy(key, sc->pubkey->key, sc->pubkey->len * sizeof(SINT16));
    memcpy(key + sc->pubkey->len, sc->privkey->key, sc->privkey->len * sizeof(SINT16));

    // Extract the private key-pair
    len = 0;
    retcode = bliss_b_pubkey_encode(sc, &pubkey, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    privlen = 0;
    retcode = bliss_b_privkey_encode(sc, &privkey, &privlen);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(pubkey, NULL);
    ck_assert_int_ge(len, 0);
    ck_assert_ptr_ne(privkey, NULL);
    ck_assert_int_ge(privlen, 0);

    // Destroy and create the SAFEcrypto object (destroying the key-pair)
    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    safecrypto_destroy(sc);
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);
    retcode = bliss_b_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(sc->pubkey, NULL);

    retcode = bliss_b_set_key_coding(sc, SC_ENTROPY_NONE, SC_ENTROPY_NONE);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Load the private key
    retcode = bliss_b_pubkey_load(sc, pubkey, len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = bliss_b_privkey_load(sc, privkey, privlen);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);

    // Compare the original public key and the encoded/loaded version
    for (i=0; i<sc->pubkey->len; i++) {
        ck_assert_int_eq(key[i], ((SINT16 *)sc->pubkey->key)[i]);
    }
    for (i=0; i<sc->privkey->len; i++) {
        ck_assert_int_eq(key[sc->pubkey->len + i], ((SINT16 *)sc->privkey->key)[i]);
    }

    retcode = bliss_b_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_bliss_b_sign_bad)
{
    int32_t retcode;
    retcode = bliss_b_sign(NULL, NULL, 0, NULL, NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
}
END_TEST

START_TEST(test_bliss_b_verify_bad)
{
    int32_t retcode;
    retcode = bliss_b_verify(NULL, NULL, 0, NULL, 0);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
}
END_TEST

Suite *bliss_b_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_keygen, *tc_keys, *tc_sign;

    s = suite_create("bliss_b");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_bliss_b_create_null);
    tcase_add_test(tc_core, test_bliss_b_create_good);
    suite_add_tcase(s, tc_core);

    tc_keygen = tcase_create("KEYGEN");
    tcase_add_test(tc_keygen, test_bliss_b_keygen);
    tcase_add_test(tc_keygen, test_bliss_b_keygen_null);
    suite_add_tcase(s, tc_keygen);

    tc_keys = tcase_create("KEYS");
    tcase_add_test(tc_keys, test_bliss_b_keys_pub_load);
    tcase_add_test(tc_keys, test_bliss_b_keys_priv_load);
    tcase_add_test(tc_keys, test_bliss_b_coding);
    suite_add_tcase(s, tc_keys);

    tc_sign = tcase_create("SIGN");
    tcase_add_test(tc_sign, test_bliss_b_oracle_bad);
    tcase_add_test(tc_sign, test_bliss_b_oracle_good);
    tcase_add_test(tc_sign, test_bliss_b_greedy_sc_bad);
    tcase_add_test(tc_sign, test_bliss_b_greedy_sc_good);
    tcase_add_test(tc_sign, test_bliss_b_sign_bad);
    tcase_add_test(tc_sign, test_bliss_b_verify_bad);
    suite_add_tcase(s, tc_sign);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = bliss_b_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

