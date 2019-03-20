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
#include "utils/arith/vectors.h"

#include <math.h>

// To get access to static functions in C ...
#include "schemes/kem/ens/ens_kem.c"


START_TEST(test_ens_kem_create_null)
{
    int32_t retcode;
    UINT32 flags[1] = {0};
    retcode = ens_kem_create(NULL, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

    retcode = ens_kem_destroy(NULL);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
}
END_TEST

START_TEST(test_ens_kem_create_good)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = ens_kem_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = ens_kem_destroy(sc);
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

START_TEST(test_ens_kem_keygen)
{
    int32_t retcode;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = ens_kem_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = ens_kem_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    ck_assert_ptr_ne(sc->privkey, NULL);
    ck_assert_ptr_ne(sc->pubkey, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, 2 * sc->ens_kem->params->n);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, sc->ens_kem->params->n);

    retcode = ens_kem_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);
}
END_TEST

START_TEST(test_ens_kem_key_load_store)
{
    size_t i;
    int32_t retcode;
    UINT8 *pubkey, *privkey;
    UINT8 *c, *k, *k2;
    size_t c_len, k_len, k2_len;
    size_t pubkey_len, privkey_len;
    safecrypto_t *sc;
    UINT32 flags[1] = {0};

    // Create a SAFEcrypto object and a KEM, generate a key pair,
    // ciphertext and associated master key.
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = ens_kem_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = ens_kem_keygen(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    ck_assert_ptr_ne(sc->privkey, NULL);
    ck_assert_ptr_ne(sc->pubkey, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, 2 * sc->ens_kem->params->n);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, sc->ens_kem->params->n);

    c_len = 0;
    k_len = 0;
    retcode = ens_kem_encapsulation(sc, &c, &c_len, &k, &k_len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    pubkey_len = 0;
    retcode = ens_kem_pubkey_encode(sc, &pubkey, &pubkey_len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_gt(pubkey_len, 0);
    ck_assert_ptr_ne(pubkey, NULL);

    privkey_len = 0;
    retcode = ens_kem_privkey_encode(sc, &privkey, &privkey_len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_gt(privkey_len, 0);
    ck_assert_ptr_ne(privkey, NULL);

    retcode = ens_kem_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    safecrypto_destroy(sc);

    // Now recreate the SAFEcrypto KEM with the stored keys and
    // decapsulate the ciphertext to reproduce the master key
    sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, flags);

    retcode = ens_kem_create(sc, 0, flags);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = ens_kem_pubkey_load(sc, pubkey, pubkey_len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = ens_kem_privkey_load(sc, privkey, privkey_len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    k2_len = 0;
    retcode = ens_kem_decapsulation(sc, c, c_len, &k2, &k2_len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Compare the two master keys
    ck_assert_uint_gt(k_len, 0);
    ck_assert_uint_eq(k_len, k2_len);
    for (i=0; i<k_len; i++) {
        ck_assert_uint_eq(k[i], k2[i]);
    }

    ck_assert_ptr_ne(sc->privkey, NULL);
    ck_assert_ptr_ne(sc->pubkey, NULL);
    ck_assert_ptr_ne(sc->privkey->key, NULL);
    ck_assert_int_eq(sc->privkey->len, 2 * sc->ens_kem->params->n);
    ck_assert_ptr_ne(sc->pubkey->key, NULL);
    ck_assert_int_eq(sc->pubkey->len, sc->ens_kem->params->n);

    retcode = ens_kem_destroy(sc);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    safecrypto_destroy(sc);

    //ck_assert_int_eq(1, 0);
}
END_TEST

START_TEST(test_small_rand_dist_512_a)
{
    SINT32 v[512] = {0};
    SINT32 w[512] = {0};
    const utils_arith_poly_t *sc_poly = utils_arith_poly();
    const utils_arith_vec_t *sc_vec = utils_arith_vectors();
    const UINT16 *c = param_ens_kem_0.coeff_rnd;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // Call the function under test to generate random vectors
    sc_poly->uniform_32(prng_ctx, v, 512, c, 12);
    sc_poly->uniform_32(prng_ctx, w, 512, c, 12);

    // Calculate the norm of the randomly distributed vector
    SINT32 norm_v = sc_vec->scalar_32(v, v, 512);
    SINT32 norm_w = sc_vec->scalar_32(w, w, 512);

    // Ensure that the norm is within 0.25% of the acceptable
    DOUBLE valid_norm = pow(param_ens_kem_0.sk_norm, 2);
    DOUBLE valid_norm_max = valid_norm * 1.0025f;
    DOUBLE valid_norm_min = valid_norm * 0.9975f;
    ck_assert_int_lt(norm_v+norm_w, valid_norm_max);
    ck_assert_int_gt(norm_v+norm_w, valid_norm_min);
}
END_TEST

START_TEST(test_small_rand_dist_512_b)
{
    SINT32 v[512] = {0};
    SINT32 w[512] = {0};
    const utils_arith_poly_t *sc_poly = utils_arith_poly();
    const utils_arith_vec_t *sc_vec = utils_arith_vectors();
    const UINT16 *c = param_ens_kem_1.coeff_rnd;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // Call the function under test to generate random vectors
    sc_poly->uniform_32(prng_ctx, v, 512, c, 12);
    sc_poly->uniform_32(prng_ctx, w, 512, c, 12);

    // Calculate the norm of the randomly distributed vector
    SINT32 norm_v = sc_vec->scalar_32(v, v, 512);
    SINT32 norm_w = sc_vec->scalar_32(w, w, 512);

    // Ensure that the norm is within 0.25% of the acceptable
    DOUBLE valid_norm = pow(param_ens_kem_1.sk_norm, 2);
    DOUBLE valid_norm_max = valid_norm * 1.0025f;
    DOUBLE valid_norm_min = valid_norm * 0.9975f;
    ck_assert_int_lt(norm_v+norm_w, valid_norm_max);
    ck_assert_int_gt(norm_v+norm_w, valid_norm_min);
}
END_TEST

START_TEST(test_small_rand_dist_1024_a)
{
    SINT32 v[1024] = {0};
    SINT32 w[1024] = {0};
    const utils_arith_poly_t *sc_poly = utils_arith_poly();
    const utils_arith_vec_t *sc_vec = utils_arith_vectors();
    const UINT16 *c = param_ens_kem_2.coeff_rnd;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // Call the function under test to generate random vectors
    sc_poly->uniform_32(prng_ctx, v, 1024, c, 12);
    sc_poly->uniform_32(prng_ctx, w, 1024, c, 12);

    // Calculate the norm of the randomly distributed vector
    SINT32 norm_v = sc_vec->scalar_32(v, v, 1024);
    SINT32 norm_w = sc_vec->scalar_32(w, w, 1024);

    // Ensure that the norm is within 0.25% of the acceptable
    DOUBLE valid_norm = pow(param_ens_kem_2.sk_norm, 2);
    DOUBLE valid_norm_max = valid_norm * 1.0025f;
    DOUBLE valid_norm_min = valid_norm * 0.9975f;
    ck_assert_int_lt(norm_v+norm_w, valid_norm_max);
    ck_assert_int_gt(norm_v+norm_w, valid_norm_min);
}
END_TEST

START_TEST(test_small_rand_dist_1024_b)
{
    SINT32 v[1024] = {0};
    SINT32 w[1024] = {0};
    const utils_arith_poly_t *sc_poly = utils_arith_poly();
    const utils_arith_vec_t *sc_vec = utils_arith_vectors();
    const UINT16 *c = param_ens_kem_3.coeff_rnd;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // Call the function under test to generate random vectors
    sc_poly->uniform_32(prng_ctx, v, 1024, c, 12);
    sc_poly->uniform_32(prng_ctx, w, 1024, c, 12);

    // Calculate the norm of the randomly distributed vector
    SINT32 norm_v = sc_vec->scalar_32(v, v, 1024);
    SINT32 norm_w = sc_vec->scalar_32(w, w, 1024);

    // Ensure that the norm is within 0.25% of the acceptable
    DOUBLE valid_norm = pow(param_ens_kem_3.sk_norm, 2);
    DOUBLE valid_norm_max = valid_norm * 1.0025f;
    DOUBLE valid_norm_min = valid_norm * 0.9975f;
    ck_assert_int_lt(norm_v+norm_w, valid_norm_max);
    ck_assert_int_gt(norm_v+norm_w, valid_norm_min);
}
END_TEST

Suite *ens_kem_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_keygen, *tc_keys, *tc_sign;

    s = suite_create("ens_kem");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_ens_kem_create_null);
    tcase_add_test(tc_core, test_ens_kem_create_good);
    tcase_add_test(tc_core, test_small_rand_dist_512_a);
    tcase_add_test(tc_core, test_small_rand_dist_512_b);
    tcase_add_test(tc_core, test_small_rand_dist_1024_a);
    tcase_add_test(tc_core, test_small_rand_dist_1024_b);
    suite_add_tcase(s, tc_core);

    tc_keygen = tcase_create("KEYGEN");
    tcase_add_test(tc_keygen, test_ens_kem_keygen);
    tcase_add_test(tc_keygen, test_ens_kem_key_load_store);
    suite_add_tcase(s, tc_keygen);

    tc_keys = tcase_create("KEYS");
    suite_add_tcase(s, tc_keys);

    tc_sign = tcase_create("SIGN");
    suite_add_tcase(s, tc_sign);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = ens_kem_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

