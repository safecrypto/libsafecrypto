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


#ifdef ENABLE_SHA3

#include "sha3/tinysha3.c"


#define SHA3_CTX   sha3_ctx_t

static const UINT64 tv_sha3_256_empty[] = {
    0xa7ffc6f8bf1ed766, 0x51c14756a061d662, 0xf580ff4de43b49fa, 0x82d80a4b80f8434a
};

static const UINT64 tv_sha3_256_abc[] = {
    0x3a985da74fe225b2, 0x045c172d6bd390bd, 0x855f086e3e9d525b, 0x46bfe24511431532
};

static const UINT64 tv_sha3_256_448[] = {
    0x41c0dba2a9d62408, 0x49100376a8235e2c, 0x82e1b9998a999e21, 0xdb32dd97496d3376
};

static const UINT64 tv_sha3_256_896[] = {
    0x916f6061fe879741, 0xca6469b43971dfdb, 0x28b1a32dc36cb325, 0x4e812be27aad1d18
};

static const UINT64 tv_sha3_256_million[] = {
    0x5c8875ae474a3634, 0xba4fd55ec85bffd6, 0x61f32aca75c6d699, 0xd0cdcb6c115891c1
};

static const UINT64 tv_sha3_384_empty[] = {
    0x0c63a75b845e4f7d, 0x01107d852e4c2485, 0xc51a50aaaa94fc61, 0x995e71bbee983a2a,
    0xc3713831264adb47, 0xfb6bd1e058d5f004
};

static const UINT64 tv_sha3_384_abc[] = {
    0xec01498288516fc9, 0x26459f58e2c6ad8d, 0xf9b473cb0fc08c25, 0x96da7cf0e49be4b2,
    0x98d88cea927ac7f5, 0x39f1edf228376d25
};

static const UINT64 tv_sha3_384_448[] = {
    0x991c665755eb3a4b, 0x6bbdfb75c78a492e, 0x8c56a22c5c4d7e42, 0x9bfdbc32b9d4ad5a,
    0xa04a1f076e62fea1, 0x9eef51acd0657c22
};

static const UINT64 tv_sha3_384_896[] = {
    0x79407d3b5916b59c, 0x3e30b09822974791, 0xc313fb9ecc849e40, 0x6f23592d04f625dc,
    0x8c709b98b43b3852, 0xb337216179aa7fc7
};

static const UINT64 tv_sha3_384_million[] = {
    0xeee9e24d78c18553, 0x37983451df97c8ad, 0x9eedf256c6334f8e, 0x948d252d5e0e7684,
    0x7aa0774ddb90a842, 0x190d2c558b4b8340
};

static const UINT64 tv_sha3_512_empty[] = {
    0xa69f73cca23a9ac5, 0xc8b567dc185a756e, 0x97c982164fe25859, 0xe0d1dcc1475c80a6,
    0x15b2123af1f5f94c, 0x11e3e9402c3ac558, 0xf500199d95b6d3e3, 0x01758586281dcd26
};

static const UINT64 tv_sha3_512_abc[] = {
    0xb751850b1a57168a, 0x5693cd924b6b096e, 0x08f621827444f70d, 0x884f5d0240d2712e,
    0x10e116e9192af3c9, 0x1a7ec57647e39340, 0x57340b4cf408d5a5, 0x6592f8274eec53f0
};

static const UINT64 tv_sha3_512_448[] = {
    0x04a371e84ecfb5b8, 0xb77cb48610fca818, 0x2dd457ce6f326a0f, 0xd3d7ec2f1e91636d,
    0xee691fbe0c985302, 0xba1b0d8dc78c0863, 0x46b533b49c030d99, 0xa27daf1139d6e75e
};

static const UINT64 tv_sha3_512_896[] = {
    0xafebb2ef542e6579, 0xc50cad06d2e578f9, 0xf8dd6881d7dc824d, 0x26360feebf18a4fa,
    0x73e3261122948efc, 0xfd492e74e82e2189, 0xed0fb440d187f382, 0x270cb455f21dd185
};

static const UINT64 tv_sha3_512_million[] = {
    0x3c3a876da14034ab, 0x60627c077bb98f7e, 0x120a2a5370212dff, 0xb3385a18d4f38859,
    0xed311d0a9d5141ce, 0x9cc5c66ee689b266, 0xa8aa18ace8282a0e, 0x0db596c90b0a7b87
};

static const UINT64 tv_sha3_512_long[] = {
    0x235ffd53504ef836, 0xa1342b488f483b39, 0x6eabbfe642cf78ee, 0x0d31feec788b23d0,
    0xd18d5c339550dd59, 0x58a500d4b95363da, 0x1b5fa18affc1bab2, 0x292dc63b7d85097c
};

START_TEST(test_sha3_256_empty)
{
    size_t i;
    UINT8 md[32] = {0};
    SHA3_CTX c;
    tinysha3_init(&c, 32);
    tinysha3_final(&c, &md);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_256_empty[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_256_abc)
{
    size_t i;
    UINT8 md[32] = {0};
    SHA3_CTX c;
    UINT8 data[3] = "abc";
    tinysha3_init(&c, 32);
    tinysha3_update(&c, data, 3);
    tinysha3_final(&c, &md);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_256_abc[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_256_448)
{
    size_t i;
    UINT8 md[32] = {0};
    SHA3_CTX c;
    UINT8 data[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    tinysha3_init(&c, 32);
    tinysha3_update(&c, data, 56);
    tinysha3_final(&c, &md);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_256_448[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_256_896)
{
    size_t i;
    UINT8 md[32] = {0};
    SHA3_CTX c;
    UINT8 data[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklm\
nhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    tinysha3_init(&c, 32);
    tinysha3_update(&c, data, 112);
    tinysha3_final(&c, &md);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_256_896[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_256_million)
{
    size_t i;
    UINT8 md[32] = {0};
    SHA3_CTX c;
    UINT8 data[50] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    tinysha3_init(&c, 32);
    for (i=0; i<1000000/50; i++) {
        tinysha3_update(&c, data, 50);
    }
    tinysha3_final(&c, &md);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_256_million[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_384_empty)
{
    size_t i;
    UINT8 md[48] = {0};
    SHA3_CTX c;
    tinysha3_init(&c, 48);
    tinysha3_final(&c, &md);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_384_empty[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_384_abc)
{
    size_t i;
    UINT8 md[48] = {0};
    SHA3_CTX c;
    UINT8 data[3] = "abc";
    tinysha3_init(&c, 48);
    tinysha3_update(&c, data, 3);
    tinysha3_final(&c, &md);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_384_abc[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_384_448)
{
    size_t i;
    UINT8 md[48] = {0};
    SHA3_CTX c;
    UINT8 data[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    tinysha3_init(&c, 48);
    tinysha3_update(&c, data, 56);
    tinysha3_final(&c, &md);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_384_448[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_384_896)
{
    size_t i;
    UINT8 md[48] = {0};
    SHA3_CTX c;
    UINT8 data[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklm\
nhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    tinysha3_init(&c, 48);
    tinysha3_update(&c, data, 112);
    tinysha3_final(&c, &md);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_384_896[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_384_million)
{
    size_t i;
    UINT8 md[48] = {0};
    SHA3_CTX c;
    UINT8 data[50] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    tinysha3_init(&c, 48);
    for (i=0; i<1000000/50; i++) {
        tinysha3_update(&c, data, 50);
    }
    tinysha3_final(&c, &md);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_384_million[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_512_empty)
{
    size_t i;
    UINT8 md[64] = {0};
    SHA3_CTX c;
    tinysha3_init(&c, 64);
    tinysha3_final(&c, &md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_512_empty[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_512_abc)
{
    size_t i;
    UINT8 md[64] = {0};
    SHA3_CTX c;
    UINT8 data[3] = "abc";
    tinysha3_init(&c, 64);
    tinysha3_update(&c, data, 3);
    tinysha3_final(&c, &md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_512_abc[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_512_448)
{
    size_t i;
    UINT8 md[64] = {0};
    SHA3_CTX c;
    UINT8 data[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    tinysha3_init(&c, 64);
    tinysha3_update(&c, data, 56);
    tinysha3_final(&c, &md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_512_448[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_512_896)
{
    size_t i;
    UINT8 md[64] = {0};
    SHA3_CTX c;
    UINT8 data[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklm\
nhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    tinysha3_init(&c, 64);
    tinysha3_update(&c, data, 112);
    tinysha3_final(&c, &md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_512_896[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha3_512_million)
{
    size_t i;
    UINT8 md[64] = {0};
    SHA3_CTX c;
    UINT8 data[50] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    tinysha3_init(&c, 64);
    for (i=0; i<1000000/50; i++) {
        tinysha3_update(&c, data, 50);
    }
    tinysha3_final(&c, &md);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha3_512_million[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

Suite *sha3_suite(void)
{
    Suite *s;
    TCase *tc_core_512, *tc_core_384, *tc_core_256;

    s = suite_create("SHA3");

    /* Test cases */
    tc_core_256 = tcase_create("CORE_256");
    tcase_add_test(tc_core_256, test_sha3_256_empty);
    tcase_add_test(tc_core_256, test_sha3_256_abc);
    tcase_add_test(tc_core_256, test_sha3_256_448);
    tcase_add_test(tc_core_256, test_sha3_256_896);
    tcase_add_test(tc_core_256, test_sha3_256_million);
    suite_add_tcase(s, tc_core_256);

    tc_core_384 = tcase_create("CORE_384");
    tcase_add_test(tc_core_384, test_sha3_384_empty);
    tcase_add_test(tc_core_384, test_sha3_384_abc);
    tcase_add_test(tc_core_384, test_sha3_384_448);
    tcase_add_test(tc_core_384, test_sha3_384_896);
    tcase_add_test(tc_core_384, test_sha3_384_million);
    suite_add_tcase(s, tc_core_384);

    tc_core_512 = tcase_create("CORE_512");
    tcase_add_test(tc_core_512, test_sha3_512_empty);
    tcase_add_test(tc_core_512, test_sha3_512_abc);
    tcase_add_test(tc_core_512, test_sha3_512_448);
    tcase_add_test(tc_core_512, test_sha3_512_896);
    tcase_add_test(tc_core_512, test_sha3_512_million);
    suite_add_tcase(s, tc_core_512);

    return s;
}

#endif

int main(void)
{
#ifdef ENABLE_SHA3
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = sha3_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
#else
    return EXIT_SUCCESS;
#endif
}


