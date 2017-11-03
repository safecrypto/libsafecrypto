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
#include "utils/entropy/huffman.c"

START_TEST(test_huffman_static_bounds)
{
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 4096);

    retcode = encode_huffman(packer, NULL, 0);
    ck_assert_int_eq(retcode, SC_NULL_POINTER);
    retcode = encode_huffman(packer, huff_table_gaussian_3, 8);
    ck_assert_int_eq(retcode, SC_OUT_OF_BOUNDS);
    retcode = encode_huffman(packer, huff_table_gaussian_3, 7);
    ck_assert_int_eq(retcode, SC_OK);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_simple)
{
    size_t i, len;
    UINT32 value;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 4096);

    for (i=0; i<8; i++) {
        retcode = encode_huffman(packer, huff_table_gaussian_3, (UINT32) i);
        ck_assert_int_eq(retcode, SC_OK);
    }

    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 4096, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);
    free(buffer);

    for (i=0; i<8; i++) {
        retcode = decode_huffman(packer, huff_table_gaussian_3, &value);
        ck_assert_int_eq(retcode, SC_OK);
        ck_assert_uint_eq(value, (UINT32) i);
    }

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_complex)
{
    size_t i, len;
    UINT32 value;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 4096);

    for (i=0; i<4; i++) {
        retcode = encode_huffman(packer, huff_table_gaussian_2, (UINT32) i);
        ck_assert_int_eq(retcode, SC_OK);
    }
    for (i=0; i<8; i++) {
        retcode = encode_huffman(packer, huff_table_gaussian_3, (UINT32) i);
        ck_assert_int_eq(retcode, SC_OK);
    }
    for (i=0; i<16; i++) {
        retcode = encode_huffman(packer, huff_table_gaussian_4, (UINT32) i);
        ck_assert_int_eq(retcode, SC_OK);
    }

    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 0, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);
    free(buffer);

    for (i=0; i<4; i++) {
        retcode = decode_huffman(packer, huff_table_gaussian_2, &value);
        ck_assert_int_eq(retcode, SC_OK);
        ck_assert_uint_eq(value, (UINT32) i);
    }
    for (i=0; i<8; i++) {
        retcode = decode_huffman(packer, huff_table_gaussian_3, &value);
        ck_assert_int_eq(retcode, SC_OK);
        ck_assert_uint_eq(value, (UINT32) i);
    }
    for (i=0; i<16; i++) {
        retcode = decode_huffman(packer, huff_table_gaussian_4, &value);
        ck_assert_int_eq(retcode, SC_OK);
        ck_assert_uint_eq(value, (UINT32) i);
    }

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_compound)
{
    size_t i, j, len;
    UINT32 value;
    UINT8 *buffer;
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    SINT32 bits = get_bits(packer);
    ck_assert_int_eq(bits, 4096);

    for (i=0; i<8; i++) {
        for (j=0; j<4; j++) {
            retcode = encode_huffman(packer, huff_table_gaussian_5, (UINT32) i * j);
            ck_assert_int_eq(retcode, SC_OK);
        }
    }

    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 4096, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);
    free(buffer);

    for (i=0; i<8; i++) {
        for (j=0; j<4; j++) {
            retcode = decode_huffman(packer, huff_table_gaussian_5, &value);
            ck_assert_int_eq(retcode, SC_OK);
            ck_assert_uint_eq(value, (UINT32) i * j);
        }
    }

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_table_1)
{
    size_t i;
    SINT32 retcode;

    huffman_table_t *table = create_huffman_gaussian(3, 1.0f);
    ck_assert_ptr_ne(table, NULL);

    for (i=0; i<table->depth; i++) {
        ck_assert_int_eq(table->codes[i].code, (i == (table->depth-1))? 0 : 1);
        ck_assert_int_eq(table->codes[i].bits, (i == (table->depth-1))? i : i+1);
    }

    retcode = destroy_huffman(&table);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_table_2)
{
    size_t i, len;
    SINT32 retcode;
    UINT32 value;
    UINT8 *buffer;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    huffman_table_t *table = create_huffman_gaussian(3, 1.0f);
    ck_assert_ptr_ne(table, NULL);
    ck_assert_int_eq(table->depth, 8);

    for (i=0; i<table->depth; i++) {
        encode_huffman(packer, table, (int)i);
    }

    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 4096, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);
    free(buffer);

    for (i=0; i<table->depth; i++) {
        decode_huffman(packer, table, &value);
        ck_assert_uint_eq(value, (UINT32) i);
    }

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = destroy_huffman(&table);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_table_3)
{
    size_t i, len;
    SINT32 retcode;
    UINT32 value;
    UINT8 *buffer;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    huffman_table_t *table = create_huffman_gaussian(6, 12.0f);
    ck_assert_ptr_ne(table, NULL);
    ck_assert_int_eq(table->depth, 64);

    for (i=0; i<table->depth; i++) {
        encode_huffman(packer, table, (int)i);
    }

    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 4096, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);
    free(buffer);

    for (i=0; i<table->depth; i++) {
        decode_huffman(packer, table, &value);
        ck_assert_uint_eq(value, (UINT32) i);
    }

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = destroy_huffman(&table);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_table_4)
{
    SINT32 retcode;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 4096, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    // This Huffman table is too steep and requires more than 32 bits, therefore
    // create_huffman_gaussian() returns a NULL pointer
    huffman_table_t *table = create_huffman_gaussian(6, 1.0f);
    ck_assert_ptr_ne(table, NULL);
    ck_assert_ptr_ne(table->codes, NULL);
    ck_assert_ptr_eq(table->codes_64, NULL);

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_table_5)
{
    size_t i, len;
    SINT32 retcode;
    UINT32 value;
    UINT8 *buffer;
    sc_entropy_t entropy;
    entropy.type = SC_ENTROPY_NONE;
    sc_packer_t *packer = create(NULL, &entropy, 32768, NULL, 0, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);

    huffman_table_t *table = create_huffman_gaussian(10, 250.0f);
    ck_assert_ptr_ne(table, NULL);
    ck_assert_int_eq(table->depth, 1024);

    for (i=0; i<table->depth; i++) {
        encode_huffman(packer, table, (int)i);
    }

    retcode = get_buffer(packer, &buffer, &len);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    packer = create(NULL, &entropy, 32768, buffer, len, NULL, 0);
    ck_assert_ptr_ne(packer, NULL);
    free(buffer);

    for (i=0; i<table->depth; i++) {
        retcode = decode_huffman(packer, table, &value);
        ck_assert_int_eq(retcode, SC_OK);
        ck_assert_uint_eq(value, (UINT32) i);
    }

    retcode = destroy(&packer);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    retcode = destroy_huffman(&table);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_huffman_static_sampler_1)
{
    size_t i;
    SINT32 retcode;
    SINT32 value;

    huffman_table_t *table = create_huffman_gaussian_sampler(12, 250.0f);
    ck_assert_ptr_ne(table, NULL);
    ck_assert_int_eq(table->depth, 4096);

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 100);
    prng_init(prng_ctx, NULL, 0);

    for (i=0; i<16384; i++) {
        retcode = sample_huffman(prng_ctx, table, &value);
        ck_assert_int_eq(retcode, SC_OK);
    }

    retcode = destroy_huffman(&table);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

    prng_destroy(prng_ctx);
}
END_TEST

Suite *huffman_static_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_dynamic, *tc_sampler;

    s = suite_create("huffman_static");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_huffman_static_bounds);
    tcase_add_test(tc_core, test_huffman_static_simple);
    tcase_add_test(tc_core, test_huffman_static_complex);
    tcase_add_test(tc_core, test_huffman_static_compound);
    suite_add_tcase(s, tc_core);

    tc_dynamic = tcase_create("DYNAMIC");
    tcase_add_test(tc_dynamic, test_huffman_static_table_1);
    tcase_add_test(tc_dynamic, test_huffman_static_table_2);
    tcase_add_test(tc_dynamic, test_huffman_static_table_3);
    tcase_add_test(tc_dynamic, test_huffman_static_table_4);
    tcase_add_test(tc_dynamic, test_huffman_static_table_5);
    suite_add_tcase(s, tc_dynamic);

    tc_sampler = tcase_create("SAMPLER");
    tcase_add_test(tc_sampler, test_huffman_static_sampler_1);
    suite_add_tcase(s, tc_sampler);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = huffman_static_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


