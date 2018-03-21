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
#include "schemes/sig/dilithium/dilithium.c"


START_TEST(test_hint)
{
    SINT32 h[1];
    SINT32 r[1] = {3913911};
    SINT32 z[1] = {14410};
    SINT32 q = param_dilithium_0.q;
    SINT32 alpha = param_dilithium_0.gamma_2 * 2;

    ntt_params_t ntt, ntt_alpha;

    ntt.n = 1;
    ntt.u.ntt32.q = q;
    barrett_init(&ntt);
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    ntt_alpha.n = 1;
    ntt_alpha.u.ntt32.q = alpha;
    barrett_init(&ntt_alpha);
    ntt_alpha.q_dbl = ntt_alpha.u.ntt32.q;
    ntt_alpha.inv_q_dbl = 1.0f / ntt_alpha.q_dbl;

    make_hint(h, r, z, 1, 1, &ntt, &ntt_alpha);

    r[0] = 6023423;
    z[0] = 18059;
    make_hint(h, r, z, 1, 1, &ntt, &ntt_alpha);

    r[0] = 794174;
    z[0] = -8498;
    make_hint(h, r, z, 1, 1, &ntt, &ntt_alpha);
    r[0] = 785676;
    low_order_bits(h, r, 1, 1, &ntt, &ntt_alpha);

    ck_assert_int_eq(1, 0);
}
END_TEST

START_TEST(test_hint_g)
{
    size_t i, j;
    SINT32 h[256];
    SINT32 r[256];
    SINT32 z[256];
    SINT32 w1[256];
    SINT32 dw1[256];
    SINT32 dw0[256];
    SINT32 zr_mod_q[256];
    SINT32 q = param_dilithium_g_0.q;
    SINT32 q_bits = param_dilithium_g_0.q_bits;
    SINT32 alpha = param_dilithium_g_0.alpha;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    ntt_params_t ntt, ntt_alpha;

    for (i=1; i<=256; i++) {
        ntt.n = i;
        ntt.u.ntt32.q = q;
        barrett_init(&ntt);
        ntt.q_dbl = ntt.u.ntt32.q;
        ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

        ntt_alpha.n = i;
        ntt_alpha.u.ntt32.q = alpha;
        barrett_init(&ntt_alpha);
        ntt_alpha.q_dbl = ntt_alpha.u.ntt32.q;
        ntt_alpha.inv_q_dbl = 1.0f / ntt_alpha.q_dbl;

        for (j=0; j<i; j++) {
            z[j] = (prng_var(prng_ctx, q_bits) % 512) * alpha;
            r[j] = prng_var(prng_ctx, q_bits) % alpha;
        }
        for (j=0; j<i; j++) {
            zr_mod_q[j] = (z[j] + r[j]) % q;
        }
        make_g_hint(h, r, z, i, 1, &ntt, &ntt_alpha);
        use_g_hint(w1, h, r, i, 1, &ntt, &ntt_alpha);
        decompose_g(dw1, dw0, zr_mod_q, i, 1, &ntt_alpha, q);

        for (j=0; j<i; j++) {
            ck_assert_int_eq(w1[j], dw1[j]);
        }
    }

    prng_destroy(prng_ctx);
}
END_TEST

Suite *dilithium_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("dilithium");

    /* Test cases */
    tc_core = tcase_create("CORE");
    //tcase_add_test(tc_core, test_hint);
    tcase_add_test(tc_core, test_hint_g);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = dilithium_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

