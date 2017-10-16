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
#include "utils/entropy/bac.c"
#include "schemes/sig/bliss_b/bliss_bac.c"

START_TEST(test_bac64_simple)
{
    size_t len;
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_BAC;
    entropy.entropy_coder = (void *) &bliss_bac_code_4;
    sc_packer_t *packer = create(NULL, &entropy, 1024, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    UINT64 dist[8];
    UINT64 freq[8] = {12, 42, 9, 30, 7, 1, 0, 0};
    bac_distfreq_64(dist, freq, 8);

    SINT32 iou[3] = { -1, 0, 1 };
    bac_encode_64_32(packer, iou, 3, dist, 3, 1<<2);

    UINT8 *buffer;
    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 1024, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 out_iou[3];
    bac_decode_64_32(packer, out_iou, 3, dist, 3, 1<<2);
    ck_assert_int_eq(out_iou[0], -1);
    ck_assert_int_eq(out_iou[1], 0);
    ck_assert_int_eq(out_iou[2], 1);

    free(buffer);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(packer, NULL);
}
END_TEST

START_TEST(test_bac64_long)
{
    size_t len;
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_BAC;
    entropy.entropy_coder = (void *) &bliss_bac_code_4;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    UINT64 dist[8];
    UINT64 freq[8] = {12, 42, 9, 30, 7, 1, 0, 0};
    bac_distfreq_64(dist, freq, 8);

    SINT32 iou[33] = { -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1,
                       -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1,
                       -1, 0, 1, -1, 0, 1, -1, 0, 1 };
    bac_encode_64_32(packer, iou, 33, dist, 3, 1<<2);

    UINT8 *buffer;
    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 0, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 out_iou[33];
    bac_decode_64_32(packer, out_iou, 33, dist, 3, 1<<2);
    ck_assert_int_eq(out_iou[0], -1);
    ck_assert_int_eq(out_iou[1], 0);
    ck_assert_int_eq(out_iou[2], 1);
    ck_assert_int_eq(out_iou[3], -1);
    ck_assert_int_eq(out_iou[4], 0);
    ck_assert_int_eq(out_iou[5], 1);
    ck_assert_int_eq(out_iou[6], -1);
    ck_assert_int_eq(out_iou[7], 0);
    ck_assert_int_eq(out_iou[8], 1);
    ck_assert_int_eq(out_iou[9], -1);
    ck_assert_int_eq(out_iou[10], 0);
    ck_assert_int_eq(out_iou[11], 1);
    ck_assert_int_eq(out_iou[12], -1);
    ck_assert_int_eq(out_iou[13], 0);
    ck_assert_int_eq(out_iou[14], 1);
    ck_assert_int_eq(out_iou[15], -1);
    ck_assert_int_eq(out_iou[16], 0);
    ck_assert_int_eq(out_iou[17], 1);
    ck_assert_int_eq(out_iou[18], -1);
    ck_assert_int_eq(out_iou[19], 0);
    ck_assert_int_eq(out_iou[20], 1);
    ck_assert_int_eq(out_iou[21], -1);
    ck_assert_int_eq(out_iou[22], 0);
    ck_assert_int_eq(out_iou[23], 1);
    ck_assert_int_eq(out_iou[24], -1);
    ck_assert_int_eq(out_iou[25], 0);
    ck_assert_int_eq(out_iou[26], 1);
    ck_assert_int_eq(out_iou[27], -1);
    ck_assert_int_eq(out_iou[28], 0);
    ck_assert_int_eq(out_iou[29], 1);
    ck_assert_int_eq(out_iou[30], -1);
    ck_assert_int_eq(out_iou[31], 0);
    ck_assert_int_eq(out_iou[32], 1);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(packer, NULL);

    free(buffer);
}
END_TEST

START_TEST(test_bac64_multi)
{
    size_t i;
    for (i=0; i<5; i++) {
        size_t len;
        SINT32 retcode;
        sc_entropy_t entropy;
        entropy.type = SC_ENTROPY_BAC;
        entropy.entropy_coder = (0 == i)? (void *) &bliss_bac_code_4 :
                                (1 == i)? (void *) &bliss_bac_code_3 :
                                (2 == i)? (void *) &bliss_bac_code_2 :
                                (3 == i)? (void *) &bliss_bac_code_1 :
                                                   &bliss_bac_code_0;
        sc_packer_t *packer = create(NULL, &entropy, 1024, NULL, 0, NULL, 0);
        ck_assert_ptr_ne(packer, NULL);

        UINT64 dist[8];
        UINT64 freq[8] = {12, 42, 9, 30, 7, 1, 0, 0};
        bac_distfreq_64(dist, freq, 8);

        SINT32 iou[3] = { -1, 0, 1 };
        bac_encode_64_32(packer, iou, 3, dist, 3, 1<<2);
        SINT32 iou2[3] = { -1, 0, 1 };
        bac_encode_64_32(packer, iou2, 3, dist, 3, 1<<2);

        UINT8 *buffer;
        retcode = get_buffer(packer, &buffer, &len);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

        retcode = destroy(&packer);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
        packer = create(NULL, &entropy, 1024, buffer, len, NULL, 0);
        ck_assert_ptr_ne(packer, NULL);

        SINT32 out_iou[3];
        bac_decode_64_32(packer, out_iou, 3, dist, 3, 1<<2);
        ck_assert_int_eq(out_iou[0], -1);
        ck_assert_int_eq(out_iou[1], 0);
        ck_assert_int_eq(out_iou[2], 1);

        SINT32 out_iou2[7];
        bac_decode_64_32(packer, out_iou2, 3, dist, 3, 1<<2);
        ck_assert_int_eq(out_iou2[0], -1);
        ck_assert_int_eq(out_iou2[1], 0);
        ck_assert_int_eq(out_iou2[2], 1);

        free(buffer);

        retcode = destroy(&packer);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
        ck_assert_ptr_eq(packer, NULL);
    }
}
END_TEST

Suite *bac_suite(void)
{
    Suite *s;
    TCase *tc_core_32, *tc_core_64;

    s = suite_create("bac");

    /* Test cases */
    tc_core_64 = tcase_create("CORE64");
    tcase_add_test(tc_core_64, test_bac64_simple);
    tcase_add_test(tc_core_64, test_bac64_long);
    tcase_add_test(tc_core_64, test_bac64_multi);
    suite_add_tcase(s, tc_core_64);
    
    tc_core_32 = tcase_create("CORE32");
    suite_add_tcase(s, tc_core_32);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = bac_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


