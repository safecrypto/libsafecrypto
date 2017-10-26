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
#include "whirlpool/whirlpool.c"

#ifdef ENABLE_WHIRLPOOL

static const UINT64 tv_whirlpool_512_empty[] = {
    0x19FA61D75522A466, 0x9B44E39C1D2E1726, 0xC530232130D407F8, 0x9AFEE0964997F7A7,
    0x3E83BE698B288FEB, 0xCF88E3E03C4F0757, 0xEA8964E59B63D937, 0x08B138CC42A66EB3
};

static const UINT64 tv_whirlpool_512_abc[] = {
    0x4E2448A4C6F486BB, 0x16B6562C73B4020B, 0xF3043E3A731BCE72, 0x1AE1B303D97E6D4C,
    0x7181EEBDB6C57E27, 0x7D0E34957114CBD6, 0xC797FC9D95D8B582, 0xD225292076D4EEF5
};



START_TEST(test_whirlpool_512_empty)
{
    size_t i;
    unsigned char md[64] = {0};
    whirlpool_ctx c;
    whirlpool_init(&c, 64);
    whirlpool_final(&c, md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_whirlpool_512_empty[i>>3] >> (56 - (i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_whirlpool_512_abc)
{
    size_t i;
    unsigned char md[64] = {0};
    UINT8 data[3] = "abc";
    whirlpool_ctx c;
    whirlpool_init(&c, 64);
    whirlpool_update(&c, data, 3);
    whirlpool_final(&c, md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_whirlpool_512_abc[i>>3] >> (56 - (i&7)*8)) & 0xff);
    }
}
END_TEST

Suite *whirlpool_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("WHIRLPOOL");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_whirlpool_512_empty);
    tcase_add_test(tc_core, test_whirlpool_512_abc);
    suite_add_tcase(s, tc_core);

    return s;
}

#endif

int main(void)
{
#ifdef ENABLE_WHIRLPOOL
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = whirlpool_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
#else
    return EXIT_SUCCESS;
#endif
}


