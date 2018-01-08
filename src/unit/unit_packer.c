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
#include "utils/sampling/sampling.h"
//#include "utils/entropy/strongswan_bliss_huffman.c"

START_TEST(test_packer_create)
{
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 128, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_ptr_eq(packer, NULL);
}
END_TEST

START_TEST(test_packer_bits)
{
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 4096);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_packer_bits_2)
{
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 31, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 32);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_packer_write_1)
{
    size_t i, len;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 1024, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 1024);

    for (i=0; i<256; i++) {
        retcode = write_bits(packer, i&1, 1);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    }
    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_eq(len, 32);
    for (i=0; i<32; i++) {
        ck_assert_int_eq(buffer[i], 0x55);
    }

    free(buffer);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_packer_write_2)
{
    size_t i, len;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 1024, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 1024);

    // Write a stream to the buffer
    for (i=0; i<256; i++) {
        retcode = write_bits(packer, i&3, 2);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    }
    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_eq(len, 64);
    for (i=0; i<64; i++) {
        ck_assert_int_eq(buffer[i], 0x1B);
    }
    free(buffer);

    // Write a second stream, the buffer should have been reset
    // after the call to get_buffer()
    for (i=0; i<256; i++) {
        retcode = write_bits(packer, i&1, 1);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    }
    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_int_eq(len, 32);
    for (i=0; i<32; i++) {
        ck_assert_int_eq(buffer[i], 0x55);
    }

    free(buffer);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_packer_read_1)
{
    size_t i;
    UINT8 buffer[128];
    UINT32 value;
    SINT32 retcode;

    for (i=0; i<128; i++) {
        buffer[i] = i;
    }

    // Create a packer initialised with the buffer contents
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 128*8, buffer, 128, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 128*8);

    // Read the packed data from the buffer
    for (i=0; i<128; i++) {
        retcode = read_bits(packer, &value, 8);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
        ck_assert_uint_eq(value, i);
    }

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_packer_read_2)
{
    size_t i, len;
    UINT8 *buffer;
    UINT32 value;
    SINT32 retcode;

    // Write the data into the buffer as 5-bit codes
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 128*5, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);
    for (i=0; i<128; i++) {
        retcode = write_bits(packer, i & 0x1F, 5);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    }
    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    // Create a packer initialised with the buffer contents
    packer = create(NULL, &entropy, 128*5, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    // Read the packed data from the buffer
    for (i=0; i<128; i++) {
        retcode = read_bits(packer, &value, 5);
        ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
        ck_assert_uint_eq(value, i & 0x1F);
    }

    free(buffer);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_ss_huff_range_1)
{
    /*SINT32 retcode;
    size_t i, j;
    SINT32 n_z1 = bliss_huffman_code_1.n_z1;
    SINT32 n_z2 = bliss_huffman_code_1.n_z2;

    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_STRONGSWAN_BLISS_B_I;

    sc_packer_t *packer = create(NULL, &entropy, 4 * n_z1 * n_z2 * 8 + 256, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    // All of the following input symbols should have a table entry
    for (i=-n_z1+1; i<n_z1; i++) {
        for (j=-(n_z2-1); j<n_z2; j++) {
            retcode = bliss_sig_encode_huff(packer, i << 8, n_z1, j, n_z2);
            ck_assert_int_eq(retcode, SC_OK);
        }
    }

    // The following input symbols should not have a table entry
    retcode = bliss_sig_encode_huff(packer, -(n_z1 << 8), n_z1, -(n_z2-1), n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, n_z1 << 8, n_z1, n_z2-1, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, -((n_z1-1) << 8), n_z1, n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, (n_z1-1) << 8, n_z1, n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, 0, n_z1, -n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);*/
}
END_TEST

START_TEST(test_ss_huff_range_3)
{
    /*SINT32 retcode;
    size_t i, j;
    SINT32 n_z1 = bliss_huffman_code_3.n_z1;
    SINT32 n_z2 = bliss_huffman_code_3.n_z2;

    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_STRONGSWAN_BLISS_B_III;

    sc_packer_t *packer = create(NULL, &entropy, 4 * n_z1 * n_z2 * 8 + 1024, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    // All of the following input symbols should have a table entry
    for (i=-n_z1+1; i<n_z1; i++) {
        for (j=-(n_z2-1); j<n_z2; j++) {
            retcode = bliss_sig_encode_huff(packer, i << 8, n_z1, j, n_z2);
            ck_assert_int_eq(retcode, SC_OK);
        }
    }

    // The following input symbols should not have a table entry
    retcode = bliss_sig_encode_huff(packer, -(n_z1 << 8), n_z1, -(n_z2-1), n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, n_z1 << 8, n_z1, n_z2-1, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, -((n_z1-1) << 8), n_z1, n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, (n_z1-1) << 8, n_z1, n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, 0, n_z1, -n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);*/
}
END_TEST

START_TEST(test_ss_huff_range_4)
{
    /*SINT32 retcode;
    size_t i, j;
    SINT32 n_z1 = bliss_huffman_code_4.n_z1;
    SINT32 n_z2 = bliss_huffman_code_4.n_z2;

    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_STRONGSWAN_BLISS_B_IV;

    sc_packer_t *packer = create(NULL, &entropy, 4 * n_z1 * n_z2 * 8 + 1024, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    // All of the following input symbols should have a table entry
    for (i=-n_z1+1; i<n_z1; i++) {
        for (j=-(n_z2-1); j<n_z2; j++) {
            retcode = bliss_sig_encode_huff(packer, i << 8, n_z1, j, n_z2);
            ck_assert_int_eq(retcode, SC_OK);
        }
    }

    // The following input symbols should not have a table entry
    retcode = bliss_sig_encode_huff(packer, -(n_z1 << 8), n_z1, -(n_z2-1), n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, n_z1 << 8, n_z1, n_z2-1, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, -((n_z1-1) << 8), n_z1, n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, (n_z1-1) << 8, n_z1, n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = bliss_sig_encode_huff(packer, 0, n_z1, -n_z2, n_z2);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);*/
}
END_TEST

Suite *packer_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_ss_huffman;

    s = suite_create("packer");

    /* Test cases */
    /*tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_packer_create);
    tcase_add_test(tc_core, test_packer_bits);
    tcase_add_test(tc_core, test_packer_bits_2);
    tcase_add_test(tc_core, test_packer_write_1);
    tcase_add_test(tc_core, test_packer_write_2);
    tcase_add_test(tc_core, test_packer_read_1);
    tcase_add_test(tc_core, test_packer_read_2);
    suite_add_tcase(s, tc_core);

    tc_ss_huffman = tcase_create("strongSwan Huffman");
    tcase_add_test(tc_ss_huffman, test_ss_huff_range_1);
    tcase_add_test(tc_ss_huffman, test_ss_huff_range_3);
    tcase_add_test(tc_ss_huffman, test_ss_huff_range_4);
    suite_add_tcase(s, tc_ss_huffman);*/

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = packer_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


