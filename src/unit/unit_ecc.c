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
    sc_mpz_t a, p;
    ecc_point_t p_base;
    sc_mpz_init2(&a, MAX_ECC_BITS);
    sc_mpz_init2(&p, MAX_ECC_BITS);
    sc_mpz_set_str(&a, 16, param_ecdh_secp256r1.a);
    sc_mpz_set_str(&p, 16, param_ecdh_secp256r1.p);

    point_init(&p_base);

    point_double(&p, &a, &p_base);
    ck_assert_int_eq(1, point_is_zero(&p_base));
}
END_TEST

START_TEST(test_ecc_mul_basic)
{
    const char *tv_m_1_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const char *tv_m_1_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const char *tv_m_2_x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const char *tv_m_2_y = "7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";

    sc_mpz_t a, p;
    ecc_point_t point, p_base;
    sc_ulimb_t secret[MAX_ECC_LIMBS] = {0};
    sc_mpz_init2(&a, MAX_ECC_BITS);
    sc_mpz_init2(&p, MAX_ECC_BITS);
    sc_mpz_set_str(&a, 16, param_ecdh_secp256r1.a);
    sc_mpz_set_str(&p, 16, param_ecdh_secp256r1.p);

    point_init(&point);
    point_init(&p_base);
    sc_mpz_set_str(&p_base.x, 16, param_ecdh_secp256r1.g_x);
    sc_mpz_set_str(&p_base.y, 16, param_ecdh_secp256r1.g_y);

    secret[0] = 1;
    scalar_point_mult(param_ecdh_secp256r1.num_bits, &a, &p, &p_base, secret, &point);
    //ck_assert_str_eq(tv_m_1_x, );
    fprintf(stderr, "mul 1 x: "); sc_mpz_out_str(stderr, 16, &p_base.x); fprintf(stderr, "\n");
    fprintf(stderr, "      y: "); sc_mpz_out_str(stderr, 16, &p_base.y); fprintf(stderr, "\n");

    secret[0] = 2;
    scalar_point_mult(param_ecdh_secp256r1.num_bits, &a, &p, &p_base, secret, &point);
    //ck_assert_str_eq(tv_m_1_x, );
    fprintf(stderr, "mul 2 x: "); sc_mpz_out_str(stderr, 16, &p_base.x); fprintf(stderr, "\n");
    fprintf(stderr, "      y: "); sc_mpz_out_str(stderr, 16, &p_base.y); fprintf(stderr, "\n");
    fprintf(stderr, "res 2 x: "); sc_mpz_out_str(stderr, 16, &point.x); fprintf(stderr, "\n");
    fprintf(stderr, "      y: "); sc_mpz_out_str(stderr, 16, &point.y); fprintf(stderr, "\n");
}
END_TEST

START_TEST(test_ecc_double_basic)
{
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

    // Set the curve parameters a and prime (modulus)
    sc_mpz_t a, p;
    ecc_point_t p_a;
    sc_mpz_init2(&a, MAX_ECC_BITS);
    sc_mpz_init2(&p, MAX_ECC_BITS);
    sc_mpz_set_str(&a, 16, param_ecdh_secp256r1.a);
    sc_mpz_set_str(&p, 16, param_ecdh_secp256r1.p);

    // Set the point to the above test vector
    point_init(&p_a);
    sc_mpz_set_str(&p_a.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_a.y, 16, tv_m_1_y);

    // Double the point and overwrite p_a
    point_double(&p, &a, &p_a);

    // Compare the result to the known result
    sc_mpz_out_str(stream, 16, &p_a.x);
    ck_assert_str_eq(result, tv_m_2_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &p_a.y);
    ck_assert_str_eq(result, tv_m_2_y);
}
END_TEST

START_TEST(test_ecc_add_basic)
{
    const char *tv_m_1_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const char *tv_m_1_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const char *tv_m_2_x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const char *tv_m_2_y = "7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
    const char *tv_m_3_x = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c";
    const char *tv_m_3_y = "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032";

    sc_mpz_t a, p;
    ecc_point_t p_a, p_b;

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);

    // Set the curve parameters a and prime (modulus)
    sc_mpz_init2(&a, MAX_ECC_BITS);
    sc_mpz_init2(&p, MAX_ECC_BITS);
    sc_mpz_set_str(&a, 16, param_ecdh_secp256r1.a);
    sc_mpz_set_str(&p, 16, param_ecdh_secp256r1.p);

    // Set the two points to the above test vectors
    point_init(&p_a);
    sc_mpz_set_str(&p_a.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_a.y, 16, tv_m_1_y);
    point_init(&p_b);
    sc_mpz_set_str(&p_b.x, 16, tv_m_2_x);
    sc_mpz_set_str(&p_b.y, 16, tv_m_2_y);

    // Add the two points and overwrite p_a
    point_add(&p, &a, &p_a, &p_b);

    // Compare the result to the known result
    sc_mpz_out_str(stream, 16, &p_a.x);
    ck_assert_str_eq(result, tv_m_3_x);
    fflush(stream);
    sc_mpz_out_str(stream, 16, &p_a.y);
    ck_assert_str_eq(result, tv_m_3_y);
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


