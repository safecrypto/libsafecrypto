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
#include "utils/entropy/packer.c"
#include "utils/entropy/entropy.c"

START_TEST(test_entropy_small_raw)
{
    size_t i, len;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    sc_packer_t *packer;
    entropy.type = SC_ENTROPY_NONE;
    entropy.entropy_coder = NULL;
    static const SINT32  p[4] = {-2, -1, 0, 1};
    SINT32 pt[4];

    packer = create(NULL, &entropy, 128, NULL, 0, NULL, 0);
    retcode = entropy_poly_encode_32(packer, 4, p, 3, SIGNED_COEFF, SC_ENTROPY_NONE, NULL);
    ck_assert_int_eq(retcode, SC_OK);
    retcode = get_buffer(packer, &buffer, &len);
    destroy(&packer);

    ck_assert_int_gt(len, 0);

    packer = create(NULL, &entropy, 128, buffer, len, NULL, 0);
    retcode = entropy_poly_decode_32(packer, 4, pt, 3, SIGNED_COEFF, SC_ENTROPY_NONE);
    ck_assert_int_eq(retcode, SC_OK);
    destroy(&packer);

    for (i=0; i<4; i++) {
        ck_assert_int_eq(p[i], pt[i]);
    }
}
END_TEST

START_TEST(test_entropy_small_huffman)
{
    size_t i, len;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    sc_packer_t *packer;
    entropy.type = SC_ENTROPY_NONE;
    entropy.entropy_coder = NULL;
    static const SINT32  p[4] = {-2, -1, 0, 1};
    SINT32 pt[4];

    packer = create(NULL, &entropy, 128, NULL, 0, NULL, 0);
    retcode = entropy_poly_encode_32(packer, 4, p, 3, SIGNED_COEFF, SC_ENTROPY_HUFFMAN_STATIC, NULL);
    ck_assert_int_eq(retcode, SC_OK);
    retcode = get_buffer(packer, &buffer, &len);
    destroy(&packer);

    ck_assert_int_gt(len, 0);

    packer = create(NULL, &entropy, 128, buffer, len, NULL, 0);
    retcode = entropy_poly_decode_32(packer, 4, pt, 3, SIGNED_COEFF, SC_ENTROPY_HUFFMAN_STATIC);
    ck_assert_int_eq(retcode, SC_OK);
    destroy(&packer);

    for (i=0; i<4; i++) {
        ck_assert_int_eq(p[i], pt[i]);
    }
}
END_TEST

START_TEST(test_entropy_large_huffman)
{
    size_t i, len;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    sc_packer_t *packer;
    entropy.type = SC_ENTROPY_NONE;
    entropy.entropy_coder = NULL;
    static const SINT32 p[32] = {102, -41, -239, 176, 146, 107, 55, 164, 61, 248, 249, 81, 79, 177, 43, 29,
        140, 134, 98, 169, -189, 10, 30, 189, -234, 0, -64, 138, -163, 202, 191, 118};
    SINT32 pt[32];

    packer = create(NULL, &entropy, 1024, NULL, 0, NULL, 0);
    retcode = entropy_poly_encode_32(packer, 32, p, 9, SIGNED_COEFF, SC_ENTROPY_HUFFMAN_STATIC, NULL);
    ck_assert_int_eq(retcode, SC_OK);
    retcode = get_buffer(packer, &buffer, &len);
    destroy(&packer);

    ck_assert_int_gt(len, 0);

    packer = create(NULL, &entropy, 1024, buffer, len, NULL, 0);
    retcode = entropy_poly_decode_32(packer, 32, pt, 9, SIGNED_COEFF, SC_ENTROPY_HUFFMAN_STATIC);
    ck_assert_int_eq(retcode, SC_OK);
    destroy(&packer);

    for (i=0; i<32; i++) {
        ck_assert_int_eq(p[i], pt[i]);
    }
}
END_TEST

Suite *entropy_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("entropy");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_entropy_small_raw);
    tcase_add_test(tc_core, test_entropy_small_huffman);
    tcase_add_test(tc_core, test_entropy_large_huffman);
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


