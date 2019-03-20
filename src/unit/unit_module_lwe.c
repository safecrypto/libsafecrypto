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
#include "utils/crypto/prng.c"
#include "utils/arith/limb.h"
#include "utils/arith/sc_math.h"

// To get access to static functions in C ...
#include "utils/arith/module_lwe.c"

START_TEST(test_create_rand_product)
{
    size_t i;
    UINT8 seed[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    SINT32 mask = 0;
    SINT32 n = 256;
    SINT32 q = 7681;
    SINT32 *w = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *r = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *y = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *z = SC_MALLOC(sizeof(SINT32) * n * 2);
    SINT32 *c = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *temp = SC_MALLOC(sizeof(SINT32) * n);
    roots_of_unity_s32(w, r, n, q, 0, 0);
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    const utils_arith_poly_t *sc_poly  = utils_arith_poly();
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0 / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Set y to 1 and calculate the product of Ay
    y[0] = 1;
    create_rand_product_32_csprng(prng_ctx, q, 13, z, y, n, 1, 1, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<n; i++) {
        mask |= z[i];
    }
    // Check that Ay is non-zero
    ck_assert_int_ne(mask, 0);

    prng_destroy(prng_ctx);
    prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Verify that Ay is reproducable with the same CSPRNG seed
    create_rand_product_32_csprng(prng_ctx, q, 13, z + n, y, n, 1, 1, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<n; i++) {
        ck_assert_int_eq(z[i], z[n+i]);
    }

    SC_FREE(w, sizeof(SINT32) * n);
    SC_FREE(r, sizeof(SINT32) * n);
    SC_FREE(y, sizeof(SINT32) * n);
    SC_FREE(z, sizeof(SINT32) * n * 2);
    SC_FREE(c, sizeof(SINT32) * n);
    SC_FREE(temp, sizeof(SINT32) * n);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_create_rand_product_16)
{
    size_t i;
    UINT8 seed[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    SINT32 mask = 0;
    SINT32 n = 256;
    SINT32 q = 7681;
    SINT16 *w = SC_MALLOC(sizeof(SINT16) * n);
    SINT16 *r = SC_MALLOC(sizeof(SINT16) * n);
    SINT32 *y = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *z = SC_MALLOC(sizeof(SINT32) * n * 2);
    SINT32 *c = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *temp = SC_MALLOC(sizeof(SINT32) * n);
    roots_of_unity_s16(w, r, n, q, 0, 0);
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    const utils_arith_poly_t *sc_poly  = utils_arith_poly();
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0 / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Set y to 1 and calculate the product of Ay
    y[0] = 1;
    create_rand_product_16_csprng(prng_ctx, q, 13, z, y, n, 1, 1, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<n; i++) {
        mask |= z[i];
    }
    // Check that Ay is non-zero
    ck_assert_int_ne(mask, 0);

    prng_destroy(prng_ctx);
    prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Verify that Ay is reproducable with the same CSPRNG seed
    create_rand_product_16_csprng(prng_ctx, q, 13, z + n, y, n, 1, 1, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<n; i++) {
        ck_assert_int_eq(z[i], z[n+i]);
    }

    SC_FREE(w, sizeof(SINT16) * n);
    SC_FREE(r, sizeof(SINT16) * n);
    SC_FREE(y, sizeof(SINT32) * n);
    SC_FREE(z, sizeof(SINT32) * n * 2);
    SC_FREE(c, sizeof(SINT32) * n);
    SC_FREE(temp, sizeof(SINT32) * n);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_create_rand_product_k)
{
    size_t i;
    UINT8 seed[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    SINT32 mask = 0;
    SINT32 k = 6;
    SINT32 n = 256;
    SINT32 q = 7681;
    SINT32 *w = SC_MALLOC(sizeof(SINT32) * k * n);
    SINT32 *r = SC_MALLOC(sizeof(SINT32) * k * n);
    SINT32 *y = SC_MALLOC(sizeof(SINT32) * k * n);
    SINT32 *z = SC_MALLOC(sizeof(SINT32) * k * n * 2);
    SINT32 *c = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *temp = SC_MALLOC(sizeof(SINT32) * k * n);
    roots_of_unity_s32(w, r, n, q, 0, 0);
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    const utils_arith_poly_t *sc_poly  = utils_arith_poly();
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0 / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Set y to 1 and calculate the product of Ay
    y[0] = 1;
    create_rand_product_32_csprng(prng_ctx, q, 13, z, y, n, k, k, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<k*n; i++) {
        mask |= z[i];
    }
    // Check that Ay is non-zero
    ck_assert_int_ne(mask, 0);

    prng_destroy(prng_ctx);
    prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Verify that Ay is reproducable with the same CSPRNG seed
    create_rand_product_32_csprng(prng_ctx, q, 13, z + k*n, y, n, k, k, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<k*n; i++) {
        ck_assert_int_eq(z[i], z[k*n+i]);
    }

    SC_FREE(w, sizeof(SINT32) * k * n);
    SC_FREE(r, sizeof(SINT32) * k * n);
    SC_FREE(y, sizeof(SINT32) * k * n);
    SC_FREE(z, sizeof(SINT32) * k * n * 2);
    SC_FREE(c, sizeof(SINT32) * n);
    SC_FREE(temp, sizeof(SINT32) * k * n);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_create_rand_product_k_16)
{
    size_t i;
    UINT8 seed[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    SINT32 mask = 0;
    SINT32 k = 6;
    SINT32 n = 256;
    SINT32 q = 7681;
    SINT16 *w = SC_MALLOC(sizeof(SINT16) * k * n);
    SINT16 *r = SC_MALLOC(sizeof(SINT16) * k * n);
    SINT32 *y = SC_MALLOC(sizeof(SINT32) * k * n);
    SINT32 *z = SC_MALLOC(sizeof(SINT32) * k * n * 2);
    SINT32 *c = SC_MALLOC(sizeof(SINT32) * n);
    SINT32 *temp = SC_MALLOC(sizeof(SINT32) * k * n);
    roots_of_unity_s16(w, r, n, q, 0, 0);
    const utils_arith_ntt_t *sc_ntt = utils_arith_ntt(SC_NTT_FLOATING_POINT);
    const utils_arith_poly_t *sc_poly  = utils_arith_poly();
    ntt_params_t ntt;
    ntt.n = n;
    ntt.u.ntt32.q = q;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0 / ntt.q_dbl;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Set y to 1 and calculate the product of Ay
    y[0] = 1;
    create_rand_product_16_csprng(prng_ctx, q, 13, z, y, n, k, k, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<k*n; i++) {
        mask |= z[i];
    }
    // Check that Ay is non-zero
    ck_assert_int_ne(mask, 0);

    prng_destroy(prng_ctx);
    prng_ctx = prng_create(SC_ENTROPY_USER_PROVIDED, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy(prng_ctx, seed, 16);
    prng_init(prng_ctx, NULL, 0);

    // Verify that Ay is reproducable with the same CSPRNG seed
    create_rand_product_16_csprng(prng_ctx, q, 13, z + k*n, y, n, k, k, c, temp, 0, 0, w, r, sc_poly, sc_ntt, &ntt);
    for (i=0; i<k*n; i++) {
        ck_assert_int_eq(z[i], z[k*n+i]);
    }

    SC_FREE(w, sizeof(SINT16) * k * n);
    SC_FREE(r, sizeof(SINT16) * k * n);
    SC_FREE(y, sizeof(SINT32) * k * n);
    SC_FREE(z, sizeof(SINT32) * k * n * 2);
    SC_FREE(c, sizeof(SINT32) * n);
    SC_FREE(temp, sizeof(SINT32) * k * n);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_compress_decompress)
{
    size_t i, j;
    SINT32 z[256];
    SINT32 dz[256];
    SINT32 q = 7681;
    SINT32 q_inv = 0x88840000;
    SINT32 d = 11;
    SINT32 q_norm = 12;
    SINT32 q_bits = 13;
    SINT32 thresh = (q + (q>>1)) >> (d + 1);

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    for (i=0; i<256; i++) {
        for (j=0; j<256; j++) {
            dz[j] = z[j] = prng_var(prng_ctx, q_bits) % q;
        }
        mlwe_compress(dz, 256, 1, d, q, q_inv, q_norm);
        mlwe_decompress(dz, 256, 1, d, q);

        for (j=0; j<256; j++) {
            SINT32 diff = dz[j] - z[j];
            if (diff < 0) diff = -diff;
            if (diff >= (q >> 1)) diff = q - diff;
            ck_assert_int_le(diff, thresh);
        }
    }

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_compress_decompress_1)
{
    size_t i, j;
    SINT32 z[256];
    SINT32 dz[256];
    SINT32 q = 7681;
    SINT32 q_inv = 0x88840000;
    SINT32 d = 1;
    SINT32 q_norm = 12;
    SINT32 thresh = (q + (q>>1)) >> (d + 1);

    for (i=0; i<256; i++) {
        for (j=0; j<256; j++) {
            dz[j] = z[j] = (q >> 1) * (j & 1);
        }
        mlwe_compress(dz, 256, 1, d, q, q_inv, q_norm);
        mlwe_decompress(dz, 256, 1, d, q);

        for (j=0; j<256; j++) {
            SINT32 diff = dz[j] - z[j];
            if (diff < 0) diff = -diff;
            if (diff >= (q >> 1)) diff = q - diff;
            ck_assert_int_le(diff, thresh);
        }
    }
}
END_TEST

Suite *module_lwe_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("module_lwe");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_create_rand_product);
    tcase_add_test(tc_core, test_create_rand_product_16);
    tcase_add_test(tc_core, test_create_rand_product_k);
    tcase_add_test(tc_core, test_create_rand_product_k_16);
    tcase_add_test(tc_core, test_compress_decompress);
    tcase_add_test(tc_core, test_compress_decompress_1);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = module_lwe_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

