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
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp256r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp256r1.p);

    point_init(&p_base, (256 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);

    point_double(&metadata, &p_base);
    ck_assert_int_eq(1, point_is_zero(&p_base));

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
}
END_TEST

START_TEST(test_ecc_double_basic_secp256r1)
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
    ecc_point_t p_a;
    ecc_metadata_t metadata;
    metadata.k = (256 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
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

    // Set the point to the above test vector
    point_init(&p_a, (256 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
    sc_mpz_set_str(&p_a.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_a.y, 16, tv_m_1_y);

    // Double the point and overwrite p_a
    point_double(&metadata, &p_a);

    // Compare the result to the known result
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
}
END_TEST

START_TEST(test_ecc_add_basic_secp256r1)
{
    const char *tv_m_1_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const char *tv_m_1_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const char *tv_m_2_x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const char *tv_m_2_y = "7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
    const char *tv_m_3_x = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c";
    const char *tv_m_3_y = "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032";

    ecc_point_t p_a, p_b;
    ecc_metadata_t metadata;

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);

    // Set the curve parameters a and prime (modulus)
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp256r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp256r1.p);

    // Set the two points to the above test vectors
    point_init(&p_a, (256 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
    point_init(&p_b, (256 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
    sc_mpz_set_str(&p_a.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_a.y, 16, tv_m_1_y);
    sc_mpz_set_str(&p_b.x, 16, tv_m_2_x);
    sc_mpz_set_str(&p_b.y, 16, tv_m_2_y);

    // Add the two points and overwrite p_a
    point_add(&metadata, &p_a, &p_b);

    // Compare the result to the known result
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
}
END_TEST

START_TEST(test_ecc_mul_basic_secp192r1)
{
    const char *tv_m_1_x = "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012";
    const char *tv_m_1_y = "7192b95ffc8da78631011ed6b24cdd573f977a11e794811";
    const char *tv_m_2_x = "dafebf5828783f2ad35534631588a3f629a70fb16982a888";
    const char *tv_m_2_y = "dd6bda0d993da0fa46b27bbc141b868f59331afa5c7e93ab";

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);

    ecc_metadata_t metadata;
    ecc_point_t point, p_base;
    sc_ulimb_t secret[MAX_ECC_LIMBS] = {0};
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp192r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp192r1.p);

    point_init(&point, (192+SC_LIMB_BITS-1) >> SC_LIMB_BITS_SHIFT);
    point_init(&p_base, (192+SC_LIMB_BITS-1) >> SC_LIMB_BITS_SHIFT);
    sc_mpz_set_str(&p_base.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_base.y, 16, tv_m_1_y);

    secret[0] = 1;
    scalar_point_mult(param_ec_secp192r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_1_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_1_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[0] = 2;
    scalar_point_mult(param_ec_secp192r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_2_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_2_y);

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
}
END_TEST

START_TEST(test_ecc_mul_basic_secp224r1)
{
    const char *tv_m_1_x = "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
    const char *tv_m_1_y = "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";
    const char *tv_m_2_x = "706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6";
    const char *tv_m_2_y = "1c2b76a7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb";

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);

    ecc_metadata_t metadata;
    ecc_point_t point, p_base;
    sc_ulimb_t secret[MAX_ECC_LIMBS] = {0};
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp224r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp224r1.p);

    point_init(&point, (224+SC_LIMB_BITS-1) >> SC_LIMB_BITS_SHIFT);
    point_init(&p_base, (224+SC_LIMB_BITS-1) >> SC_LIMB_BITS_SHIFT);
    sc_mpz_set_str(&p_base.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_base.y, 16, tv_m_1_y);

    secret[0] = 1;
    scalar_point_mult(param_ec_secp224r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_1_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_1_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[0] = 2;
    scalar_point_mult(param_ec_secp224r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_2_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_2_y);

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
}
END_TEST

START_TEST(test_ecc_mul_basic_secp256r1)
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

    ecc_metadata_t metadata;
    ecc_point_t point, p_base;
    sc_ulimb_t secret[MAX_ECC_LIMBS] = {0};
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp256r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp256r1.p);

    point_init(&point, (256 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
    point_init(&p_base, (256 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
    sc_mpz_set_str(&p_base.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_base.y, 16, tv_m_1_y);

    secret[0] = 1;
    scalar_point_mult(param_ec_secp256r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_1_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_1_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[0] = 2;
    scalar_point_mult(param_ec_secp256r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_2_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_2_y);

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
}
END_TEST

START_TEST(test_ecc_mul_basic_secp384r1)
{
    const char *tv_m_1_x = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
    const char *tv_m_1_y = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
    const char *tv_m_2_x = "8d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
    const char *tv_m_2_y = "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80";

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);

    ecc_metadata_t metadata;
    ecc_point_t point, p_base;
    sc_ulimb_t secret[MAX_ECC_LIMBS] = {0};
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp384r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp384r1.p);

    point_init(&point, (384 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
    point_init(&p_base, (384 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
    sc_mpz_set_str(&p_base.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_base.y, 16, tv_m_1_y);

    secret[0] = 1;
    scalar_point_mult(param_ec_secp384r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_1_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_1_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[0] = 2;
    scalar_point_mult(param_ec_secp384r1.num_bits, &metadata, &p_base, secret, &point);

    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_2_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_2_y);

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
}
END_TEST

START_TEST(test_ecc_mul_basic_secp521r1)
{
    const char *tv_m_1_x = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
    const char *tv_m_1_y = "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650";
    const char *tv_m_2_x = "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
    const char *tv_m_2_y = "f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02";
    const char *tv_m_3_x = "18bdd7f1b889598a4653deeae39cc6f8cc2bd767c2ab0d93fb12e968fbed342b51709506339cb1049cb11dd48b9bdb3cd5cad792e43b74e16d8e2603bfb11b0344f";
    const char *tv_m_3_y = "c5aadbe63f68ca5b6b6908296959bf0af89ee7f52b410b9444546c550952d311204da3bdddc6d4eae7edfaec1030da8ef837ccb22eee9cfc94dd3287fed0990f94";
    const char *tv_m_4_x = "17e1370d39c9c63925daeeac571e21caaf60bd169191baee8352e0f54674443b29786243564abb705f6fc0fe5fc5d3f98086b67ca0be7ac8a9dec421d9f1bc6b37f";
    const char *tv_m_4_y = "1cd559605ead19fbd99e83600a6a81a0489e6f20306ee0789ae00ce16a6efea2f42f7534186cf1c60df230bd9bcf8cb95e5028ad9820b2b1c0e15597ee54c4614a6";
    const char *tv_m_5_x = "b45cb84651c9d4f08858b867f82d816e84e94fe4cae3da5f65e420b08398d0c5bf019253a6c26d20671bdef0b8e6c1d348a4b0734687f73ac6a4cbb2e085c68b3f";
    const char *tv_m_5_y = "1c84942bbf538903062170a4ba8b3410d385719ba2037d29ca5248bfcbc8478220fec79244dcd45d31885a1764dee479ce20b12ceab62f9001c7aa4282ce4be7f56";
    const char *tv_m_6_x = "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
    const char *tv_m_6_y = "e7c6d6958765c43ffba375a04bd382e426670abbb6a864bb97e85042e8d8c199d368118d66a10bd9bf3aaf46fec052f89ecac38f795d8d3dbf77416b89602e99af";

    // Manipulate stdout to redirect to a char array for testing
    char result[8192];
    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stream, result);

    ecc_metadata_t metadata;
    ecc_point_t point, p_base;
    sc_ulimb_t secret[MAX_ECC_LIMBS] = {0};
    sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
    sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
    sc_mpz_set_str(&metadata.a, 16, param_ec_secp521r1.a);
    sc_mpz_set_str(&metadata.m, 16, param_ec_secp521r1.p);

    point_init(&point, 9);
    point_init(&p_base, 9);
    sc_mpz_set_str(&p_base.x, 16, tv_m_1_x);
    sc_mpz_set_str(&p_base.y, 16, tv_m_1_y);

    secret[0] = 1;
    scalar_point_mult(param_ec_secp521r1.num_bits, &metadata, &p_base, secret, &point);
    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_1_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_1_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[0] = 2;
    scalar_point_mult(param_ec_secp521r1.num_bits, &metadata, &p_base, secret, &point);
    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_2_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_2_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[0] = 20;
    scalar_point_mult(param_ec_secp521r1.num_bits, &metadata, &p_base, secret, &point);
    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_3_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_3_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[0] = 0x7246cdca43590e13;
    secret[1] = 0x00159d893d4cdd74;
    scalar_point_mult(param_ec_secp521r1.num_bits, &metadata, &p_base, secret, &point);
    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_4_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_4_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[8] = 0x83;
    secret[7] = 0xff83fffffc03fff8;
    secret[6] = 0x0007fffc000f8003;
    secret[5] = 0xffe00007ffe0fffc;
    secret[4] = 0x000f8000000007ff;
    secret[3] = 0xffff00ffff000fff;
    secret[2] = 0xfff001fffc000000;
    secret[1] = 0x001c000040000000;
    secret[0] = 0x3803ffffffcfffff;
    scalar_point_mult(param_ec_secp521r1.num_bits, &metadata, &p_base, secret, &point);
    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_5_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_5_y);
    fflush(stream);
    memset(result, 0, 8192);

    secret[8] = 0x1ff;
    secret[7] = 0xffffffffffffffff;
    secret[6] = 0xffffffffffffffff;
    secret[5] = 0xffffffffffffffff;
    secret[4] = 0xfffffffffffffffa;
    secret[3] = 0x51868783bf2f966b;
    secret[2] = 0x7fcc0148f709a5d0;
    secret[1] = 0x3bb5c9b8899c47ae;
    secret[0] = 0xbb6fb71e91386408;
    scalar_point_mult(param_ec_secp521r1.num_bits, &metadata, &p_base, secret, &point);
    sc_mpz_out_str(stream, 16, &point.x);
    ck_assert_str_eq(result, tv_m_6_x);
    fflush(stream);
    memset(result, 0, 8192);
    sc_mpz_out_str(stream, 16, &point.y);
    ck_assert_str_eq(result, tv_m_6_y);
    fflush(stream);
    memset(result, 0, 8192);

    sc_mpz_clear(&metadata.lambda);
    sc_mpz_clear(&metadata.x);
    sc_mpz_clear(&metadata.y);
    sc_mpz_clear(&metadata.temp);
    sc_mpz_clear(&metadata.a);
    sc_mpz_clear(&metadata.m);
}
END_TEST

Suite *entropy_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ECC");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_ecc_zero_double);
    tcase_add_test(tc_core, test_ecc_double_basic_secp256r1);
    tcase_add_test(tc_core, test_ecc_add_basic_secp256r1);
    tcase_add_test(tc_core, test_ecc_mul_basic_secp192r1);
    tcase_add_test(tc_core, test_ecc_mul_basic_secp224r1);
    tcase_add_test(tc_core, test_ecc_mul_basic_secp256r1);
    tcase_add_test(tc_core, test_ecc_mul_basic_secp384r1);
    tcase_add_test(tc_core, test_ecc_mul_basic_secp521r1);
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


