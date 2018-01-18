/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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
#include "utils/ecc/ecc.c"

START_TEST(test_ecc_zero_double)
{
    ecc_metadata_t metadata;
    sc_mpz_t a, p;
    ecc_point_t p_base;
#ifdef USE_OPT_ECC
    metadata.a = param_ec_secp256r1.a;
    metadata.m = param_ec_secp256r1.p;
#else
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp256r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp256r1.p);
#endif

    point_init(&p_base, 4);

    point_double(&metadata, &p_base);
    ck_assert_int_eq(1, point_is_zero(&p_base));

#ifndef USE_OPT_ECC
    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
#endif
}
END_TEST

START_TEST(test_ecc_mul_basic)
{
#ifdef USE_OPT_ECC
    const sc_ulimb_t tv_m_1_x[4] = {0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247};
    const sc_ulimb_t tv_m_1_y[4] = {0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b};
    const sc_ulimb_t tv_m_2_x[4] = {0xa60b48fc47669978, 0xc08969e277f21b35, 0x8a52380304b51ac3, 0x7cf27b188d034f7e};
    const sc_ulimb_t tv_m_2_y[4] = {0x9e04b79d227873d1, 0xba7dade63ce98229, 0x293d9ac69f7430db, 0x07775510db8ed040};
#else
    const char *tv_m_1_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const char *tv_m_1_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const char *tv_m_2_x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const char *tv_m_2_y = "7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
#endif

    ecc_metadata_t metadata;
    ecc_point_t point, p_base;
    sc_ulimb_t secret[MAX_ECC_LIMBS] = {0};
#ifdef USE_OPT_ECC
    metadata.a = param_ec_secp256r1.a;
    metadata.m = param_ec_secp256r1.p;
#else
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp256r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp256r1.p);
#endif

    point_init(&point, 4);
    point_init(&p_base, 4);
#ifdef USE_OPT_ECC
    mpn_copy(p_base.x, tv_m_1_x, 4);
    mpn_copy(p_base.y, tv_m_2_y, 4);
#else
    sc_mpz_set_str(&p_base.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_base.y, 16, tv_m_1_y);
#endif

    secret[0] = 1;
    scalar_point_mult(param_ec_secp256r1.num_bits, &metadata, &p_base, secret, &point);
    //ck_assert_str_eq(tv_m_1_x, );

    secret[0] = 2;
    scalar_point_mult(param_ec_secp256r1.num_bits, &metadata, &p_base, secret, &point);
    //ck_assert_str_eq(tv_m_1_x, );

#ifndef USE_OPT_ECC
    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
#endif
}
END_TEST

START_TEST(test_ecc_double_basic)
{
#ifdef USE_OPT_ECC
    const sc_ulimb_t tv_m_1_x[4] = {0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247};
    const sc_ulimb_t tv_m_1_y[4] = {0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b};
    const sc_ulimb_t tv_m_2_x[4] = {0xa60b48fc47669978, 0xc08969e277f21b35, 0x8a52380304b51ac3, 0x7cf27b188d034f7e};
    const sc_ulimb_t tv_m_2_y[4] = {0x9e04b79d227873d1, 0xba7dade63ce98229, 0x293d9ac69f7430db, 0x07775510db8ed040};
#else
    const char *tv_m_1_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const char *tv_m_1_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const char *tv_m_2_x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const char *tv_m_2_y = "7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);
#endif

    // Set the curve parameters a and prime (modulus)
    ecc_point_t p_a;
    ecc_metadata_t metadata;
    metadata.k = 4;
#ifdef USE_OPT_ECC
    metadata.n = 4;
    metadata.a = param_ec_secp256r1.a;
    metadata.m = param_ec_secp256r1.p;
    metadata.m_inv = param_ec_secp256r1.p_m_inv;
    metadata.order_m = param_ec_secp256r1.order_m;
#else
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m_inv, MAX_ECC_BITS+1);
    sc_mpz_init2(&metadata.order_m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp256r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp256r1.p);
    sc_mpz_set_str(&metadata.m_inv, 16, param_ec_secp256r1.p_inv);
    sc_mpz_set_str(&metadata.order_m, 16, param_ec_secp256r1.order_m);
#endif

    // Set the point to the above test vector
    point_init(&p_a, 4);
#ifdef USE_OPT_ECC
    mpn_copy(p_a.x, tv_m_1_x, 4);
    mpn_copy(p_a.y, tv_m_1_y, 4);
#else
    sc_mpz_set_str(&p_a.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_a.y, 16, tv_m_1_y);
#endif

    // Double the point and overwrite p_a
    point_double(&metadata, &p_a);

    // Compare the result to the known result
#ifdef USE_OPT_ECC
    size_t i;
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(p_a.x[i], tv_m_2_x[i]);
        ck_assert_uint_eq(p_a.y[i], tv_m_2_y[i]);
    }
#else
    sc_mpz_out_str(stream, 16, &p_a.x);
    ck_assert_str_eq(result, tv_m_2_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &p_a.y);
    ck_assert_str_eq(result, tv_m_2_y);

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
    sc_mpz_clear(&metadata.m_inv);
    sc_mpz_clear(&metadata.order_m);
#endif
}
END_TEST

START_TEST(test_ecc_add_basic)
{
#ifdef USE_OPT_ECC
    const sc_ulimb_t tv_m_1_x[4] = {0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247};
    const sc_ulimb_t tv_m_1_y[4] = {0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b};
    const sc_ulimb_t tv_m_2_x[4] = {0xa60b48fc47669978, 0xc08969e277f21b35, 0x8a52380304b51ac3, 0x7cf27b188d034f7e};
    const sc_ulimb_t tv_m_2_y[4] = {0x9e04b79d227873d1, 0xba7dade63ce98229, 0x293d9ac69f7430db, 0x07775510db8ed040};
    const sc_ulimb_t tv_m_3_x[4] = {0xfb41661bc6e7fd6c, 0xe6c6b721efada985, 0xc8f7ef951d4bf165, 0x5ecbe4d1a6330a44};
    const sc_ulimb_t tv_m_3_y[4] = {0x9a79b127a27d5032, 0xd82ab036384fb83d, 0x374b06ce1a64a2ec, 0x8734640c4998ff7e};
#else
    const char *tv_m_1_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const char *tv_m_1_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const char *tv_m_2_x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const char *tv_m_2_y = "7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
    const char *tv_m_3_x = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c";
    const char *tv_m_3_y = "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032";
#endif

    ecc_point_t p_a, p_b;
    ecc_metadata_t metadata;

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);

#ifdef USE_OPT_ECC
    metadata.n = 4;
    metadata.a = param_ec_secp256r1.a;
    metadata.m = param_ec_secp256r1.p;
    metadata.m_inv = param_ec_secp256r1.p_inv;
    metadata.order_m = param_ec_secp256r1.order_m;
#else
    // Set the curve parameters a and prime (modulus)
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp256r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp256r1.p);
#endif

    // Set the two points to the above test vectors
    point_init(&p_a, 4);
    point_init(&p_b, 4);
#ifdef USE_OPT_ECC
    mpn_copy(p_a.x, tv_m_1_x, 4);
    mpn_copy(p_a.y, tv_m_1_y, 4);
    mpn_copy(p_b.x, tv_m_2_x, 4);
    mpn_copy(p_b.y, tv_m_2_y, 4);
#else
    sc_mpz_set_str(&p_a.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_a.y, 16, tv_m_1_y);
    sc_mpz_set_str(&p_b.x, 16, tv_m_2_x);
    sc_mpz_set_str(&p_b.y, 16, tv_m_2_y);
#endif

    // Add the two points and overwrite p_a
    point_add(&metadata, &p_a, &p_b);

    // Compare the result to the known result
#ifdef USE_OPT_ECC
    size_t i;
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(p_a.x[i], tv_m_3_x[i]);
        ck_assert_uint_eq(p_a.y[i], tv_m_3_y[i]);
    }
#else
    sc_mpz_out_str(stream, 16, &p_a.x);
    ck_assert_str_eq(result, tv_m_3_x);
    fflush(stream);
    sc_mpz_out_str(stream, 16, &p_a.y);
    ck_assert_str_eq(result, tv_m_3_y);

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
#endif
}
END_TEST

Suite *entropy_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ECC");

    /* Test cases */
    tc_core = tcase_create("CORE");
    //tcase_add_test(tc_core, test_ecc_zero_double);
    //tcase_add_test(tc_core, test_ecc_mul_basic);
    tcase_add_test(tc_core, test_ecc_double_basic);
    tcase_add_test(tc_core, test_ecc_add_basic);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = entropy_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


