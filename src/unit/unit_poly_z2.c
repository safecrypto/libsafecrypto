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
#include "safecrypto_version.h"
#include "utils/arith/arith.h"
#include "utils/arith/poly_z2.c"
#include "utils/crypto/prng.c"
#include "utils/sampling/gaussian_cdf.c"

static const float epsilon = 0.0001;


START_TEST(test_mul_mod_2)
{
    size_t i;
    SINT32 a[64] = {1, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    1, 1, 1, 1, 1, 1, 1, 1,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    1, 1, 1, 1, 1, 1, 1, 1,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0};
    SINT32 b[64] = {1, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    1, 1, 1, 1, 1, 1, 1, 1,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    1, 1, 1, 1, 1, 1, 1, 1,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 1};
    SINT32 c[64];
    SINT32 d[64] = {0, 0, 1, 0, 1, 0, 1, 0,
                    1, 0, 1, 0, 1, 0, 1, 1,
                    0, 1, 0, 1, 0, 1, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 1,
                    1, 0, 1, 0, 1, 0, 1, 1,
                    0, 1, 0, 1, 0, 1, 0, 1,
                    1, 0, 1, 0, 1, 0, 1, 0,
                    0, 0, 0, 0, 0, 0, 0, 1};
    z2_mul_mod2(a, b, 64, c);
    for (i=0; i<64; i++) {
        ck_assert_int_eq(c[i], d[i]);
    }

    UINT32 a32[2] = {0x8000FF00, 0xFF000000};
    UINT32 b32[2] = {0x8000FF00, 0x00FF0001};
    UINT32 c32[2];
    UINT32 d32[2] = {0x2AAB5401, 0xAB55AA01};
    z2_conv_mod2(a32, b32, 64, c32);
    for (i=0; i<2; i++) {
        ck_assert_uint_eq(c32[i], d32[i]);
    }
}
END_TEST

START_TEST(test_mul_mod_2_2)
{
    size_t i;
    SINT32 a[128] = {1, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     1, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0};
    SINT32 b[128] = {1, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 1,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 1,
                     1, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 1};
    SINT32 c[128];
    SINT32 d[128] = {0, 0, 0, 0, 0, 0, 0, 0,
                     1, 0, 1, 0, 1, 0, 1, 1,
                     1, 0, 1, 0, 1, 0, 1, 0,
                     0, 0, 0, 0, 0, 0, 0, 1,
                     0, 1, 0, 1, 0, 1, 0, 0,
                     1, 0, 1, 0, 1, 0, 1, 1,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 1,
                     0, 0, 0, 0, 0, 0, 0, 1,
                     0, 1, 0, 1, 0, 1, 0, 1,
                     1, 0, 1, 0, 1, 0, 1, 0,
                     0, 0, 0, 0, 0, 0, 0, 1,
                     0, 1, 0, 1, 0, 1, 0, 0,
                     1, 0, 1, 0, 1, 0, 1, 1,
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 1};
    z2_mul_mod2(a, b, 128, c);
    for (i=0; i<128; i++) {
        ck_assert_int_eq(c[i], d[i]);
    }

    UINT32 a32[4] = {0x8000FF00, 0xFF0000FF, 0x8000FF00, 0xFF000000};
    UINT32 b32[4] = {0x8000FF00, 0x00FF0001, 0x8000FF00, 0x00FF8001};
    UINT32 c32[4];
    UINT32 d32[4] = {0x00ABAA01, 0x54ABFF01, 0x0155AA01, 0x54ABFF01};
    z2_conv_mod2(a32, b32, 128, c32);
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(c32[i], d32[i]);
    }
}
END_TEST

START_TEST(test_mul_mod_2_3)
{
    size_t i;
    UINT32 a32[16] = {0x9B51050B, 0x15F3DE44, 0x4C1F23A8, 0x9845DA93,
                      0x86C51247, 0xCBE6EA34, 0x958E23DD, 0x1A202EBA, 
                      0x277FFDCB, 0xBD479196, 0xF7FFB307, 0x29F6CD77,
                      0x6C7EE7C7, 0xA8691750, 0x302F2BB0, 0xA4329B1A};
    UINT32 b32[16] = {0x8D033CC1, 0x3A6813B5, 0x9534BC9E, 0x17B6AC5A,
                      0x11EF0061, 0xCB265B22, 0x17D0121D, 0x79DCD785, 
                      0x1F4EC273, 0x44B05DA5, 0x5B55DA12, 0x07FF3410,
                      0x81031406, 0x29532DBE, 0x4D210134, 0x3417463B};
    UINT32 c32[16];
    UINT32 d32[16] = {0x00808012, 0x42C82418, 0x36203802, 0x48A80001, 
                      0x64234240, 0x12011100, 0x94380410, 0x021C3481, 
                      0x42871002, 0x0015A080, 0x24308104, 0x182600A0, 
                      0x0A822C19, 0x800B2447, 0x0300530A, 0x05FA2884};
    z2_conv_mod2(a32, b32, 32*16, c32);
    for (i=0; i<16; i++) {
        ck_assert_uint_eq(c32[i], d32[i]);
    }
}
END_TEST

START_TEST(test_inverse)
{
    size_t i, iter;
    SINT32 f[8], f_fut[8], f_inv[8+1];
    SINT32 scratch[16];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // For up to 20 iterations
    for (iter=0; iter<20; iter++) {

        // Generate a random GF(2) polynomial
        for (i=0; i<8; i++) {
            f[i] = (SINT32) prng_bit(prng_ctx);
            f_fut[i] = f[i];
        }
        
        // Create the modular inverse of the polynomial, m = 2^8 - 1
        SINT32 retcode = z2_inv(f_inv, f_fut, scratch, 8);
        if (SC_FUNC_FAILURE == retcode)
            continue;
    
        // Multiply the f and 1/f mod m
        SINT32 c[16];
        z2_mul(c, 8, f, f_inv);

        // Confirm that the product is 1
        SINT32 q[16], r[16];
        SINT32 ip[16] = {0};
        ip[0] = 1;
        ip[8] = 1;
        z2_div(q, r, 16, c, ip);
        ck_assert_int_eq(r[0], 1);
        for (i=1; i<8; i++) {
            ck_assert_int_eq(r[i], 0);
        }

        break;
    }

    ck_assert_uint_lt(iter, 20);

    //ck_assert_int_eq(0, 1);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_inverse_2)
{
    size_t i, iter;
    SINT32 f[512], f_fut[512], f_inv[512+1];
    SINT32 scratch[1024];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // For up to 20 iterations
    for (iter=0; iter<20; iter++) {

        // Generate a random GF(2) polynomial
        for (i=0; i<512; i++) {
            f[i] = (SINT32) prng_bit(prng_ctx);
            f_fut[i] = f[i];
        }
        
        // Create the modular inverse of the polynomial, m = 2^512 - 1
        SINT32 retcode = z2_inv(f_inv, f_fut, scratch, 512);
        if (SC_FUNC_FAILURE == retcode)
            continue;
    
        // Multiply the f and 1/f mod m
        SINT32 c[1024];
        z2_mul(c, 512, f, f_inv);

        // Confirm that the product is 1
        SINT32 q[1024], r[1024];
        SINT32 ip[1024] = {0};
        ip[0] = 1;
        ip[512] = 1;
        z2_div(q, r, 1024, c, ip);
        ck_assert_int_eq(r[0], 1);
        for (i=1; i<512; i++) {
            ck_assert_int_eq(r[i], 0);
        }

        break;
    }

    ck_assert_uint_lt(iter, 20);

    //ck_assert_int_eq(0, 1);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_z2_inverse_ext_euclidean)
{
    size_t i, iter;
    SINT32 f[8], f_inv[8+1];
    SINT32 scratch[7*(8+1)];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // For up to 20 iterations
    for (iter=0; iter<20; iter++) {

        // Generate a random GF(2) polynomial
        for (i=0; i<8; i++) {
            f[i] = (SINT32) prng_bit(prng_ctx);
        }
        
        fprintf(stderr, "f = ");
        for (i=8; i--;) {
            fprintf(stderr, "%d", f[i]);
        }
        fprintf(stderr, "\n");

        // Create the modular inverse of the polynomial, m = 2^8 - 1
        SINT32 retcode = z2_ext_euclidean(f_inv, f, scratch, 8);
        if (SC_FUNC_FAILURE == retcode)
            continue;

        fprintf(stderr, "f_inv = ");
        for (i=8; i--;) {
            fprintf(stderr, "%d", f_inv[i]);
        }
        fprintf(stderr, "\n");
    
        // Multiply the f and 1/f mod m
        SINT32 c[16];
        z2_mul(c, 8, f, f_inv);

        fprintf(stderr, "f * f_inv = ");
        for (i=16; i--;) {
            fprintf(stderr, "%d", c[i]);
        }
        fprintf(stderr, "\n");

        // Confirm that the product is 1
        SINT32 q[16], r[16];
        SINT32 ip[16] = {0};
        ip[0] = 1;
        ip[8] = 1;
        z2_div(q, r, 16, c, ip);

        fprintf(stderr, "q = ");
        for (i=8; i--;) {
            fprintf(stderr, "%d", q[i]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "r = ");
        for (i=8; i--;) {
            fprintf(stderr, "%d", r[i]);
        }
        fprintf(stderr, "\n");

        if (r[0] != 1) continue;
        for (i=1; i<8; i++) {
            if (r[i] != 0) break;
        }
        if (i < 8) continue;

        break;
    }

    ck_assert_uint_lt(iter, 20);

    //ck_assert_int_eq(0, 1);

    prng_destroy(prng_ctx);
}
END_TEST

START_TEST(test_z2_inverse_ext_euclidean_2)
{
    size_t i, iter;
    SINT32 f[512], f_inv[512+1];
    SINT32 scratch[7*(512+1)];
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    // For up to 20 iterations
    for (iter=0; iter<20; iter++) {

        // Generate a random GF(2) polynomial
        for (i=0; i<512; i++) {
            f[i] = (SINT32) prng_bit(prng_ctx);
        }
        
        fprintf(stderr, "f = ");
        for (i=512; i--;) {
            fprintf(stderr, "%d", f[i]);
        }
        fprintf(stderr, "\n");

        // Create the modular inverse of the polynomial, m = 2^8 - 1
        SINT32 retcode = z2_ext_euclidean(f_inv, f, scratch, 512);
        if (SC_FUNC_FAILURE == retcode)
            continue;

        fprintf(stderr, "f_inv = ");
        for (i=8; i--;) {
            fprintf(stderr, "%d", f_inv[i]);
        }
        fprintf(stderr, "\n");
    
        // Multiply the f and 1/f mod m
        SINT32 c[2*512];
        z2_mul(c, 512, f, f_inv);

        fprintf(stderr, "f * f_inv = ");
        for (i=2*512; i--;) {
            fprintf(stderr, "%d", c[i]);
        }
        fprintf(stderr, "\n");

        // Confirm that the product is 1
        SINT32 q[2*512], r[2*512];
        SINT32 ip[2*512] = {0};
        ip[0] = 1;
        ip[512] = 1;
        z2_div(q, r, 2*512, c, ip);

        fprintf(stderr, "q = ");
        for (i=512; i--;) {
            fprintf(stderr, "%d", q[i]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "r = ");
        for (i=512; i--;) {
            fprintf(stderr, "%d", r[i]);
        }
        fprintf(stderr, "\n");

        if (r[0] != 1) continue;
        for (i=1; i<512; i++) {
            if (r[i] != 0) break;
        }
        if (i < 512) continue;

        break;
    }

    ck_assert_uint_lt(iter, 20);

    prng_destroy(prng_ctx);

    //ck_assert_int_eq(0, 1);
}
END_TEST

Suite *poly32_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly_z2");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_mul_mod_2);
    tcase_add_test(tc_core, test_mul_mod_2_2);
    tcase_add_test(tc_core, test_mul_mod_2_3);
    tcase_add_test(tc_core, test_inverse);
    tcase_add_test(tc_core, test_inverse_2);
    tcase_add_test(tc_core, test_z2_inverse_ext_euclidean);
    tcase_add_test(tc_core, test_z2_inverse_ext_euclidean_2);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = poly32_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


