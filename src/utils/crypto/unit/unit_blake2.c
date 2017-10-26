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
#include "prng_types.h"

#ifdef ENABLE_BLAKE2
#include "blake2/blake2_safecrypto.c"

static const UINT64 tv_blake2b_512_empty[] = {
    0x786a02f742015903, 0xc6c6fd852552d272, 0x912f4740e1584761, 0x8a86e217f71f5419,
    0xd25e1031afee5853, 0x13896444934eb04b, 0x903a685b1448b755, 0xd56f701afe9be2ce
};

static const UINT64 tv_sha3_512_nacl[] = {
    0xa8add4bdddfd93e4, 0x877d2746e62817b1, 0x16364a1fa7bc148d, 0x95090bc7333b3673,
    0xf82401cf7aa2e4cb, 0x1ecd90296e3f14cb, 0x5413f8ed77be7304, 0x5b13914cdcd6a918
};

START_TEST(test_blake2b_512_empty)
{
    size_t i;
    UINT8 md[64] = {0};
    blake2b_state c;
    sc_blake2b_init(&c, 64);
    sc_blake2b_final(&c, &md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_blake2b_512_empty[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_blake2b_512_nacl)
{
    size_t i;
    UINT8 md[64] = {0};
    blake2b_state c;
    UINT8 data[43] = {0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20,
                      0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74,
                      0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67};
    sc_blake2b_init(&c, 64);
    sc_blake2b_update(&c, data, 43);
    sc_blake2b_final(&c, &md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_512_nacl[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

Suite *blake2b_suite(void)
{
    Suite *s;
    TCase *tc_core_512;

    s = suite_create("BLAKE2B");

    /* Test cases */
    tc_core_512 = tcase_create("CORE_512");
    tcase_add_test(tc_core_512, test_blake2b_512_empty);
    tcase_add_test(tc_core_512, test_blake2b_512_nacl);
    suite_add_tcase(s, tc_core_512);

    return s;
}

#endif

int main(void)
{
#ifdef ENABLE_BLAKE2
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = blake2b_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
#else
    return EXIT_SUCCESS;
#endif
}


