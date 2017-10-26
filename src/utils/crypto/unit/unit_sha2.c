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

#ifdef ENABLE_SHA2
#include "sha2/sha2_safecrypto.c"


static const UINT32 tv_sha2_224_empty[] = {
    0xd14a028c, 0x2a3a2bc9, 0x476102bb, 0x288234c4, 0x15a2b01f, 0x828ea62a, 0xc5b3e42f
};

static const UINT32 tv_sha2_224_abc[] = {
    0x23097d22, 0x3405d822, 0x8642a477, 0xbda255b3, 0x2aadbce4, 0xbda0b3f7, 0xe36c9da7
};

static const UINT32 tv_sha2_224_448[] = {
    0x75388b16, 0x512776cc, 0x5dba5da1, 0xfd890150, 0xb0c6455c, 0xb4f58b19, 0x52522525
};

static const UINT32 tv_sha2_224_896[] = {
    0xc97ca9a5, 0x59850ce9, 0x7a04a96d, 0xef6d99a9, 0xe0e0e2ab, 0x14e6b8df, 0x265fc0b3
};

static const UINT32 tv_sha2_224_million[] = {
    0x20794655, 0x980c91d8, 0xbbb4c1ea, 0x97618a4b, 0xf03f4258, 0x1948b2ee, 0x4ee7ad67
};

static const UINT32 tv_sha2_256_empty[] = {
    0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855
};

static const UINT32 tv_sha2_256_abc[] = {
    0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad
};

static const UINT32 tv_sha2_256_448[] = {
    0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039, 0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1
};

static const UINT32 tv_sha2_256_896[] = {
    0xcf5b16a7, 0x78af8380, 0x036ce59e, 0x7b049237, 0x0b249b11, 0xe8f07a51, 0xafac4503, 0x7afee9d1
};

static const UINT32 tv_sha2_256_million[] = {
    0xcdc76e5c, 0x9914fb92, 0x81a1c7e2, 0x84d73e67, 0xf1809a48, 0xa497200e, 0x046d39cc, 0xc7112cd0
};

static const UINT64 tv_sha2_384_empty[] = {
    0x38b060a751ac9638, 0x4cd9327eb1b1e36a, 0x21fdb71114be0743,
    0x4c0cc7bf63f6e1da, 0x274edebfe76f65fb, 0xd51ad2f14898b95b
};

static const UINT64 tv_sha2_384_abc[] = {
    0xcb00753f45a35e8b, 0xb5a03d699ac65007, 0x272c32ab0eded163,
    0x1a8b605a43ff5bed, 0x8086072ba1e7cc23, 0x58baeca134c825a7
};

static const UINT64 tv_sha2_384_448[] = {
    0x3391fdddfc8dc739, 0x3707a65b1b470939, 0x7cf8b1d162af05ab,
    0xfe8f450de5f36bc6, 0xb0455a8520bc4e6f, 0x5fe95b1fe3c8452b
};

static const UINT64 tv_sha2_384_896[] = {
    0x09330c33f71147e8, 0x3d192fc782cd1b47, 0x53111b173b3b05d2,
    0x2fa08086e3b0f712, 0xfcc7c71a557e2db9, 0x66c3e9fa91746039
};

static const UINT64 tv_sha2_384_million[] = {
    0x9d0e1809716474cb, 0x086e834e310a4a1c, 0xed149e9c00f24852,
    0x7972cec5704c2a5b, 0x07b8b3dc38ecc4eb, 0xae97ddd87f3d8985
};

static const UINT64 tv_sha2_512_empty[] = {
    0xcf83e1357eefb8bd, 0xf1542850d66d8007, 0xd620e4050b5715dc, 0x83f4a921d36ce9ce,
    0x47d0d13c5d85f2b0, 0xff8318d2877eec2f, 0x63b931bd47417a81, 0xa538327af927da3e
};

static const UINT64 tv_sha2_512_abc[] = {
    0xddaf35a193617aba, 0xcc417349ae204131, 0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
    0x2192992a274fc1a8, 0x36ba3c23a3feebbd, 0x454d4423643ce80e, 0x2a9ac94fa54ca49f
};

static const UINT64 tv_sha2_512_448[] = {
    0x204a8fc6dda82f0a, 0x0ced7beb8e08a416, 0x57c16ef468b228a8, 0x279be331a703c335,
    0x96fd15c13b1b07f9, 0xaa1d3bea57789ca0, 0x31ad85c7a71dd703, 0x54ec631238ca3445
};

static const UINT64 tv_sha2_512_896[] = {
    0x8e959b75dae313da, 0x8cf4f72814fc143f, 0x8f7779c6eb9f7fa1, 0x7299aeadb6889018,
    0x501d289e4900f7e4, 0x331b99dec4b5433a, 0xc7d329eeb6dd2654, 0x5e96e55b874be909
};

static const UINT64 tv_sha2_512_million[] = {
    0xe718483d0ce76964, 0x4e2e42c7bc15b463, 0x8e1f98b13b204428, 0x5632a803afa973eb,
    0xde0ff244877ea60a, 0x4cb0432ce577c31b, 0xeb009c5c2c49aa2e, 0x4eadb217ad8cc09b
};


START_TEST(test_sha2_224_empty)
{
    size_t i;
    unsigned char md[28] = {0};
    sha2_ctx c;
    sha2_begin(28, &c);
    sha2_end(md, &c);

    for (i=0; i<28; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_224_empty[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_224_abc)
{
    size_t i;
    unsigned char md[28] = {0};
    sha2_ctx c;
    unsigned char data[3] = "abc";
    sha2_begin(28, &c);
    sha2_hash(data, 3, &c);
    sha2_end(md, &c);

    for (i=0; i<28; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_224_abc[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_224_448)
{
    size_t i;
    unsigned char md[28] = {0};
    sha2_ctx c;
    unsigned char data[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha2_begin(28, &c);
    sha2_hash(data, 56, &c);
    sha2_end(md, &c);

    for (i=0; i<28; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_224_448[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_224_896)
{
    size_t i;
    unsigned char md[28] = {0};
    sha2_ctx c;
    unsigned char data[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklm\
nhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    sha2_begin(28, &c);
    sha2_hash(data, 112, &c);
    sha2_end(md, &c);

    for (i=0; i<28; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_224_896[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_224_million)
{
    size_t i;
    unsigned char md[28] = {0};
    sha2_ctx c;
    unsigned char data[50] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    sha2_begin(28, &c);
    for (i=0; i<1000000/50; i++) {
        sha2_hash(data, 50, &c);
    }
    sha2_end(md, &c);

    for (i=0; i<28; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_224_million[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST


START_TEST(test_sha2_256_empty)
{
    size_t i;
    unsigned char md[32] = {0};
    sha2_ctx c;
    sha2_begin(32, &c);
    sha2_end(md, &c);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_256_empty[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_256_abc)
{
    size_t i;
    unsigned char md[32] = {0};
    sha2_ctx c;
    unsigned char data[3] = "abc";
    sha2_begin(32, &c);
    sha2_hash(data, 3, &c);
    sha2_end(md, &c);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_256_abc[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_256_448)
{
    size_t i;
    unsigned char md[32] = {0};
    sha2_ctx c;
    unsigned char data[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha2_begin(32, &c);
    sha2_hash(data, 56, &c);
    sha2_end(md, &c);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_256_448[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_256_896)
{
    size_t i;
    unsigned char md[32] = {0};
    sha2_ctx c;
    unsigned char data[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklm\
nhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    sha2_begin(32, &c);
    sha2_hash(data, 112, &c);
    sha2_end(md, &c);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_256_896[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_256_million)
{
    size_t i;
    unsigned char md[32] = {0};
    sha2_ctx c;
    unsigned char data[50] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    sha2_begin(32, &c);
    for (i=0; i<1000000/50; i++) {
        sha2_hash(data, 50, &c);
    }
    sha2_end(md, &c);

    for (i=0; i<32; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_256_million[i>>2] >> (24-(i&3)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_384_empty)
{
    size_t i;
    UINT8 md[48] = {0};
    sha2_ctx c;
    sha2_begin(48, &c);
    sha2_end(md, &c);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_384_empty[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_384_abc)
{
    size_t i;
    UINT8 md[48] = {0};
    sha2_ctx c;
    UINT8 data[3] = "abc";
    sha2_begin(48, &c);
    sha2_hash(data, 3, &c);
    sha2_end(md, &c);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_384_abc[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_384_448)
{
    size_t i;
    UINT8 md[48] = {0};
    sha2_ctx c;
    UINT8 data[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha2_begin(48, &c);
    sha2_hash(data, 56, &c);
    sha2_end(md, &c);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_384_448[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_384_896)
{
    size_t i;
    UINT8 md[48] = {0};
    sha2_ctx c;
    UINT8 data[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklm\
nhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    sha2_begin(48, &c);
    sha2_hash(data, 112, &c);
    sha2_end(md, &c);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_384_896[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_384_million)
{
    size_t i;
    UINT8 md[48] = {0};
    sha2_ctx c;
    UINT8 data[50] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    sha2_begin(48, &c);
    for (i=0; i<1000000/50; i++) {
        sha2_hash(data, 50, &c);
    }
    sha2_end(md, &c);

    for (i=0; i<48; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_384_million[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_512_empty)
{
    size_t i;
    UINT8 md[64] = {0};
    sha2_ctx c;
    sha2_begin(64, &c);
    sha2_end(md, &c);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_512_empty[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_512_abc)
{
    size_t i;
    UINT8 md[64] = {0};
    sha2_ctx c;
    UINT8 data[3] = "abc";
    sha2_begin(64, &c);
    sha2_hash(data, 3, &c);
    sha2_end(md, &c);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_512_abc[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_512_448)
{
    size_t i;
    UINT8 md[64] = {0};
    sha2_ctx c;
    UINT8 data[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha2_begin(64, &c);
    sha2_hash(data, 56, &c);
    sha2_end(md, &c);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_512_448[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_512_896)
{
    size_t i;
    UINT8 md[64] = {0};
    sha2_ctx c;
    UINT8 data[112] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklm\
nhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    sha2_begin(64, &c);
    sha2_hash(data, 112, &c);
    sha2_end(md, &c);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_512_896[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

START_TEST(test_sha2_512_million)
{
    size_t i;
    UINT8 md[64] = {0};
    sha2_ctx c;
    UINT8 data[50] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    sha2_begin(64, &c);
    for (i=0; i<1000000/50; i++) {
        sha2_hash(data, 50, &c);
    }
    sha2_end(md, &c);

    for (i=0; i<64; i++) {
        ck_assert_uint_eq(md[i], (tv_sha2_512_million[i>>3] >> (56-(i&7)*8)) & 0xff);
    }
}
END_TEST

Suite *sha2_suite(void)
{
    Suite *s;
    TCase *tc_core_512, *tc_core_384, *tc_core_256, *tc_core_224;

    s = suite_create("SHA2");

    /* Test cases */
    tc_core_224 = tcase_create("CORE_224");
    tcase_add_test(tc_core_224, test_sha2_224_empty);
    tcase_add_test(tc_core_224, test_sha2_224_abc);
    tcase_add_test(tc_core_224, test_sha2_224_448);
    tcase_add_test(tc_core_224, test_sha2_224_896);
    tcase_add_test(tc_core_224, test_sha2_224_million);
    suite_add_tcase(s, tc_core_224);

    tc_core_256 = tcase_create("CORE_256");
    tcase_add_test(tc_core_256, test_sha2_256_empty);
    tcase_add_test(tc_core_256, test_sha2_256_abc);
    tcase_add_test(tc_core_256, test_sha2_256_448);
    tcase_add_test(tc_core_256, test_sha2_256_896);
    tcase_add_test(tc_core_256, test_sha2_256_million);
    suite_add_tcase(s, tc_core_256);

    tc_core_384 = tcase_create("CORE_384");
    tcase_add_test(tc_core_384, test_sha2_384_empty);
    tcase_add_test(tc_core_384, test_sha2_384_abc);
    tcase_add_test(tc_core_384, test_sha2_384_448);
    tcase_add_test(tc_core_384, test_sha2_384_896);
    tcase_add_test(tc_core_384, test_sha2_384_million);
    suite_add_tcase(s, tc_core_384);

    tc_core_512 = tcase_create("CORE_512");
    tcase_add_test(tc_core_512, test_sha2_512_empty);
    tcase_add_test(tc_core_512, test_sha2_512_abc);
    tcase_add_test(tc_core_512, test_sha2_512_448);
    tcase_add_test(tc_core_512, test_sha2_512_896);
    tcase_add_test(tc_core_512, test_sha2_512_million);
    suite_add_tcase(s, tc_core_512);

    return s;
}

#endif

int main(void)
{
#ifdef ENABLE_SHA2
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = sha2_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
#else
    return EXIT_SUCCESS;
#endif
}


