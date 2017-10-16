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
#include "utils/arith/sc_math.c"
#include <math.h>


START_TEST(test_parity_8)
{
    UINT32 parity;
    parity = sc_bit_parity_8(0xFF);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_8(0x00);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_8(0x80);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_8(0xA4);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_8(0x9E);
    ck_assert_uint_eq(parity, 1);
}
END_TEST

START_TEST(test_parity_16)
{
    UINT32 parity;
    parity = sc_bit_parity_16(0xFFFF);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_16(0x0000);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_16(0x8000);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_16(0xA43C);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_16(0x9E06);
    ck_assert_uint_eq(parity, 1);
}
END_TEST

START_TEST(test_parity_32)
{
    UINT32 parity;
    parity = sc_bit_parity_32(0xFFFFFFFF);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_32(0x00000000);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_32(0x80000000);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_32(0xA43C176C);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_32(0x9E281C31);
    ck_assert_uint_eq(parity, 1);
}
END_TEST

START_TEST(test_parity_64)
{
#ifdef HAVE_64BIT
    UINT32 parity;
    parity = sc_bit_parity_64(0xFFFFFFFFFFFFFFFFULL);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_64(0x0000000000000000ULL);
    ck_assert_uint_eq(parity, 0);
    parity = sc_bit_parity_64(0x8000000000000000ULL);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_64(0xA43C176CA43C1762ULL);
    ck_assert_uint_eq(parity, 1);
    parity = sc_bit_parity_64(0x9E281C319E281C33ULL);
    ck_assert_uint_eq(parity, 1);
#endif
}
END_TEST

START_TEST(test_parity_128)
{
#ifdef HAVE_128BIT
    UINT128 data;
    UINT32 parity;
    data = 0xFFFFFFFFFFFFFFFFULL; data <<= 64; data |= 0xFFFFFFFFFFFFFFFFULL;
    parity = sc_bit_parity_128(data);
    ck_assert_uint_eq(parity, 0);
    data = 0;
    parity = sc_bit_parity_128(data);
    ck_assert_uint_eq(parity, 0);
    data = 0x8000000000000000ULL; data <<= 64;
    parity = sc_bit_parity_128(data);
    ck_assert_uint_eq(parity, 1);
    data = 0xA43C176CA43C1762ULL; data <<= 64; data |= 0xA43C176CA43C1763ULL;
    parity = sc_bit_parity_128(data);
    ck_assert_uint_eq(parity, 1);
    data = 0x9E281C319E281C33ULL; data <<= 64; data |= 0x9E281C319E281C31ULL;
    parity = sc_bit_parity_128(data);
    ck_assert_uint_eq(parity, 1);
#endif
}
END_TEST

START_TEST(test_hamming_8)
{
    UINT8 hamming;
    hamming = sc_hamming_8(0xFF);
    ck_assert_uint_eq(hamming, 8);
    hamming = sc_hamming_8(0x00);
    ck_assert_uint_eq(hamming, 0);
    hamming = sc_hamming_8(0x80);
    ck_assert_uint_eq(hamming, 1);
    hamming = sc_hamming_8(0xA4);
    ck_assert_uint_eq(hamming, 3);
    hamming = sc_hamming_8(0x9E);
    ck_assert_uint_eq(hamming, 5);
}
END_TEST

START_TEST(test_hamming_16)
{
    UINT16 hamming;
    hamming = sc_hamming_16(0xFFFF);
    ck_assert_uint_eq(hamming, 16);
    hamming = sc_hamming_16(0x0000);
    ck_assert_uint_eq(hamming, 0);
    hamming = sc_hamming_16(0x8000);
    ck_assert_uint_eq(hamming, 1);
    hamming = sc_hamming_16(0xA43C);
    ck_assert_uint_eq(hamming, 7);
    hamming = sc_hamming_16(0x9E06);
    ck_assert_uint_eq(hamming, 7);
}
END_TEST

START_TEST(test_hamming_32)
{
    UINT32 hamming;
    hamming = sc_hamming_32(0xFFFFFFFF);
    ck_assert_uint_eq(hamming, 32);
    hamming = sc_hamming_32(0x00000000);
    ck_assert_uint_eq(hamming, 0);
    hamming = sc_hamming_32(0x80000000);
    ck_assert_uint_eq(hamming, 1);
    hamming = sc_hamming_32(0xA43C176C);
    ck_assert_uint_eq(hamming, 15);
    hamming = sc_hamming_32(0x9E281C31);
    ck_assert_uint_eq(hamming, 13);
}
END_TEST

START_TEST(test_hamming_64)
{
#ifdef HAVE_64BIT
    UINT64 hamming;
    hamming = sc_hamming_64(0xFFFFFFFFFFFFFFFFULL);
    ck_assert_uint_eq(hamming, 64);
    hamming = sc_hamming_64(0x0000000000000000ULL);
    ck_assert_uint_eq(hamming, 0);
    hamming = sc_hamming_64(0x8000000000000000ULL);
    ck_assert_uint_eq(hamming, 1);
    hamming = sc_hamming_64(0xA43C176CA43C1762ULL);
    ck_assert_uint_eq(hamming, 29);
    hamming = sc_hamming_64(0x9E281C319E281C33ULL);
    ck_assert_uint_eq(hamming, 27);
#endif
}
END_TEST

START_TEST(test_ctz_8)
{
    UINT32 ctz = sc_ctz_8(0xFF);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_8(0x00);
    ck_assert_uint_eq(ctz, 8);
    ctz = sc_ctz_8(0x55);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_8(0xAA);
    ck_assert_uint_eq(ctz, 1);
    ctz = sc_ctz_8(0xE4);
    ck_assert_uint_eq(ctz, 2);
}
END_TEST

START_TEST(test_ctz_16)
{
    UINT32 ctz = sc_ctz_16(0xFFFF);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_16(0x0000);
    ck_assert_uint_eq(ctz, 16);
    ctz = sc_ctz_16(0x5555);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_16(0xAAAA);
    ck_assert_uint_eq(ctz, 1);
    ctz = sc_ctz_16(0xE4C0);
    ck_assert_uint_eq(ctz, 6);
}
END_TEST

START_TEST(test_ctz_32)
{
    UINT32 ctz = sc_ctz_32(0xFFFFFFFF);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_32(0x00000000);
    ck_assert_uint_eq(ctz, 32);
    ctz = sc_ctz_32(0x55555555);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_32(0xAAAAAAAA);
    ck_assert_uint_eq(ctz, 1);
    ctz = sc_ctz_32(0xE4C00000);
    ck_assert_uint_eq(ctz, 22);
}
END_TEST

START_TEST(test_ctz_64)
{
#ifdef HAVE_64BIT
    UINT32 ctz = sc_ctz_64(0xFFFFFFFFFFFFFFFFULL);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_64(0x0000000000000000ULL);
    ck_assert_uint_eq(ctz, 64);
    ctz = sc_ctz_64(0x5555555555555555ULL);
    ck_assert_uint_eq(ctz, 0);
    ctz = sc_ctz_64(0xAAAAAAAAAAAAAAAAULL);
    ck_assert_uint_eq(ctz, 1);
    ctz = sc_ctz_64(0xE4C0000000000000ULL);
    ck_assert_uint_eq(ctz, 54);
#endif
}
END_TEST

START_TEST(test_clz_8)
{
    UINT32 clz = sc_clz_8(0xFF);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_8(0x00);
    ck_assert_uint_eq(clz, 8);
    clz = sc_clz_8(0x55);
    ck_assert_uint_eq(clz, 1);
    clz = sc_clz_8(0xAA);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_8(0x39);
    ck_assert_uint_eq(clz, 2);
}
END_TEST

START_TEST(test_clz_16)
{
    UINT32 clz = sc_clz_16(0xFFFF);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_16(0x0000);
    ck_assert_uint_eq(clz, 16);
    clz = sc_clz_16(0x5555);
    ck_assert_uint_eq(clz, 1);
    clz = sc_clz_16(0xAAAA);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_16(0xE4C);
    ck_assert_uint_eq(clz, 4);
}
END_TEST

START_TEST(test_clz_32)
{
    UINT32 clz = sc_clz_32(0xFFFFFFFF);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_32(0x00000000);
    ck_assert_uint_eq(clz, 32);
    clz = sc_clz_32(0x55555555);
    ck_assert_uint_eq(clz, 1);
    clz = sc_clz_32(0xAAAAAAAA);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_32(0x00000E4C);
    ck_assert_uint_eq(clz, 20);
}
END_TEST

START_TEST(test_clz_64)
{
#ifdef HAVE_64BIT
    UINT32 clz = sc_clz_64(0xFFFFFFFFFFFFFFFFULL);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_64(0x0000000000000000ULL);
    ck_assert_uint_eq(clz, 64);
    clz = sc_clz_64(0x5555555555555555ULL);
    ck_assert_uint_eq(clz, 1);
    clz = sc_clz_64(0xAAAAAAAAAAAAAAAAULL);
    ck_assert_uint_eq(clz, 0);
    clz = sc_clz_64(0x0000000000000E4CULL);
    ck_assert_uint_eq(clz, 52);
    clz = sc_clz_64(0x0000000000000036ULL);
    ck_assert_uint_eq(clz, 58);
#endif
}
END_TEST

START_TEST(test_log2_128)
{
#ifdef HAVE_128BIT
    UINT128 data;
    data = 0xFFFFFFFFFFFFFFFFULL; data <<= 64; data |= 0xFFFFFFFFFFFFFFFFULL;
    UINT32 log2 = sc_log2_128(data);
    ck_assert_uint_eq(log2, 127);
    log2 = sc_log2_128(0);
    ck_assert_uint_eq(log2, 0);
    data = 0x0000000000000001ULL; data <<= 64;
    log2 = sc_log2_128(data);
    ck_assert_uint_eq(log2, 64);
    data = 0xFFFFFFFFFFFFFFFFULL;;
    log2 = sc_log2_128(data);
    ck_assert_uint_eq(log2, 63);
    log2 = sc_log2_128(7);
    ck_assert_uint_eq(log2, 2);
#endif
}
END_TEST

START_TEST(test_log2_64)
{
#ifdef HAVE_64BIT
    UINT32 log2 = sc_log2_64(0xFFFFFFFFFFFFFFFFULL);
    ck_assert_uint_eq(log2, 63);
    log2 = sc_log2_64(0x0000000000000000ULL);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_log2_64(0x0000000100000000ULL);
    ck_assert_uint_eq(log2, 32);
    log2 = sc_log2_64(0x00000000FFFFFFFFULL);
    ck_assert_uint_eq(log2, 31);
    log2 = sc_log2_64(0x0000000000000007ULL);
    ck_assert_uint_eq(log2, 2);
#endif
}
END_TEST

START_TEST(test_log2_32)
{
    UINT32 log2 = sc_log2_32(0xFFFFFFFF);
    ck_assert_uint_eq(log2, 31);
    log2 = sc_log2_32(0x00000000);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_log2_32(0x00010000);
    ck_assert_uint_eq(log2, 16);
    log2 = sc_log2_32(0x0000FFFF);
    ck_assert_uint_eq(log2, 15);
    log2 = sc_log2_32(0x7);
    ck_assert_uint_eq(log2, 2);
}
END_TEST

START_TEST(test_log2_16)
{
    UINT32 log2 = sc_log2_16(0xFFFF);
    ck_assert_uint_eq(log2, 15);
    log2 = sc_log2_16(0x0000);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_log2_16(0x0100);
    ck_assert_uint_eq(log2, 8);
    log2 = sc_log2_16(0x00FF);
    ck_assert_uint_eq(log2, 7);
    log2 = sc_log2_16(0x0007);
    ck_assert_uint_eq(log2, 2);
}
END_TEST

START_TEST(test_log2_8)
{
    UINT32 log2 = sc_log2_8(0xFF);
    ck_assert_uint_eq(log2, 7);
    log2 = sc_log2_8(0x00);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_log2_8(0x10);
    ck_assert_uint_eq(log2, 4);
    log2 = sc_log2_8(0x0F);
    ck_assert_uint_eq(log2, 3);
    log2 = sc_log2_8(0x07);
    ck_assert_uint_eq(log2, 2);
}
END_TEST

START_TEST(test_ceil_log2_128)
{
#ifdef HAVE_128BIT
    UINT128 data;
    data = 0xFFFFFFFFFFFFFFFFULL; data <<= 64; data |= 0xFFFFFFFFFFFFFFFFULL;
    UINT32 log2 = sc_ceil_log2_128(data);
    ck_assert_uint_eq(log2, 128);
    log2 = sc_ceil_log2_128(0);
    ck_assert_uint_eq(log2, 0);
    data = 0x0000000000000001ULL; data <<= 64;
    log2 = sc_ceil_log2_128(data);
    ck_assert_uint_eq(log2, 64);
    data = 0xFFFFFFFFFFFFFFFFULL;;
    log2 = sc_ceil_log2_128(data);
    ck_assert_uint_eq(log2, 64);
    log2 = sc_ceil_log2_128(7);
    ck_assert_uint_eq(log2, 3);
#endif
}
END_TEST

START_TEST(test_ceil_log2_64)
{
#ifdef HAVE_64BIT
    UINT32 log2 = sc_ceil_log2_64(0xFFFFFFFFFFFFFFFFULL);
    ck_assert_uint_eq(log2, 64);
    log2 = sc_ceil_log2_64(0x0000000000000000ULL);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_ceil_log2_64(0x0000000100000000ULL);
    ck_assert_uint_eq(log2, 32);
    log2 = sc_ceil_log2_64(0x00000000FFFFFFFFULL);
    ck_assert_uint_eq(log2, 32);
    log2 = sc_ceil_log2_64(0x0000000000000007ULL);
    ck_assert_uint_eq(log2, 3);
#endif
}
END_TEST

START_TEST(test_ceil_log2_32)
{
    UINT32 log2 = sc_ceil_log2_32(0xFFFFFFFF);
    ck_assert_uint_eq(log2, 32);
    log2 = sc_ceil_log2_32(0x00000000);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_ceil_log2_32(0x00010000);
    ck_assert_uint_eq(log2, 16);
    log2 = sc_ceil_log2_32(0x0000FFFF);
    ck_assert_uint_eq(log2, 16);
    log2 = sc_ceil_log2_32(0x7);
    ck_assert_uint_eq(log2, 3);
}
END_TEST

START_TEST(test_ceil_log2_16)
{
    UINT32 log2 = sc_ceil_log2_16(0xFFFF);
    ck_assert_uint_eq(log2, 16);
    log2 = sc_ceil_log2_16(0x0000);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_ceil_log2_16(0x0100);
    ck_assert_uint_eq(log2, 8);
    log2 = sc_ceil_log2_16(0x00FF);
    ck_assert_uint_eq(log2, 8);
    log2 = sc_ceil_log2_16(0x0007);
    ck_assert_uint_eq(log2, 3);
}
END_TEST

START_TEST(test_ceil_log2_8)
{
    UINT32 log2 = sc_ceil_log2_8(0xFF);
    ck_assert_uint_eq(log2, 8);
    log2 = sc_ceil_log2_8(0x00);
    ck_assert_uint_eq(log2, 0);
    log2 = sc_ceil_log2_8(0x10);
    ck_assert_uint_eq(log2, 4);
    log2 = sc_ceil_log2_8(0x0F);
    ck_assert_uint_eq(log2, 4);
    log2 = sc_ceil_log2_8(0x07);
    ck_assert_uint_eq(log2, 3);
}
END_TEST

START_TEST(test_reverse_8)
{
    UINT8 reverse = sc_bit_reverse_8(0xFF);
    ck_assert_uint_eq(reverse, 0xFF);
    reverse = sc_bit_reverse_8(0x00);
    ck_assert_uint_eq(reverse, 0x00);
    reverse = sc_bit_reverse_8(0x55);
    ck_assert_uint_eq(reverse, 0xAA);
    reverse = sc_bit_reverse_8(0xAA);
    ck_assert_uint_eq(reverse, 0x55);
    reverse = sc_bit_reverse_8(0xE4);
    ck_assert_uint_eq(reverse, 0x27);
}
END_TEST

START_TEST(test_reverse_16)
{
    UINT16 reverse = sc_bit_reverse_16(0xFFFF);
    ck_assert_uint_eq(reverse, 0xFFFF);
    reverse = sc_bit_reverse_16(0x0000);
    ck_assert_uint_eq(reverse, 0x0000);
    reverse = sc_bit_reverse_16(0x5555);
    ck_assert_uint_eq(reverse, 0xAAAA);
    reverse = sc_bit_reverse_16(0xAAAA);
    ck_assert_uint_eq(reverse, 0x5555);
    reverse = sc_bit_reverse_16(0x3210);
    ck_assert_uint_eq(reverse, 0x084C);
}
END_TEST

START_TEST(test_reverse_32)
{
    UINT32 reverse = sc_bit_reverse_32(0xFFFFFFFF);
    ck_assert_uint_eq(reverse, 0xFFFFFFFF);
    reverse = sc_bit_reverse_32(0x00000000);
    ck_assert_uint_eq(reverse, 0x00000000);
    reverse = sc_bit_reverse_32(0x55555555);
    ck_assert_uint_eq(reverse, 0xAAAAAAAA);
    reverse = sc_bit_reverse_32(0xAAAAAAAA);
    ck_assert_uint_eq(reverse, 0x55555555);
    reverse = sc_bit_reverse_32(0x76543210);
    ck_assert_uint_eq(reverse, 0x084C2A6E);
}
END_TEST

START_TEST(test_reverse_64)
{
#ifdef HAVE_64_BIT
    UINT64 reverse = sc_bit_reverse_64(0xFFFFFFFFFFFFFFFF);
    ck_assert_uint_eq(reverse, 0xFFFFFFFFFFFFFFFF);
    reverse = sc_bit_reverse_64(0x0000000000000000);
    ck_assert_uint_eq(reverse, 0x000000000000000);
    reverse = sc_bit_reverse_64(0x5555555555555555);
    ck_assert_uint_eq(reverse, 0xAAAAAAAAAAAAAAAA);
    reverse = sc_bit_reverse_64(0xAAAAAAAAAAAAAAAA);
    ck_assert_uint_eq(reverse, 0x5555555555555555);
    reverse = sc_bit_reverse_64(0xFEDCBA9876543210);
    ck_assert_uint_eq(reverse, 0x084C2A6E195D3B7F);
#endif
}
END_TEST

START_TEST(test_reverse_128)
{
#ifdef HAVE_128_BIT
    UINT128 data;
    data = 0xFFFFFFFFFFFFFFFF; data <<= 64; data |= 0xFFFFFFFFFFFFFFFF;
    UINT128 reverse = sc_bit_reverse_128(data);
    ck_assert_uint_eq(reverse >> 64, 0xFFFFFFFFFFFFFFFF);
    ck_assert_uint_eq((UINT64)reverse, 0xFFFFFFFFFFFFFFFF);
    data = 0;
    reverse = sc_bit_reverse_64(data);
    ck_assert_uint_eq(reverse >> 64, 0x000000000000000);
    ck_assert_uint_eq((UINT64)reverse, 0x000000000000000);
    data = 0x5555555555555555; data <<= 64; data |= 0x5555555555555555;
    reverse = sc_bit_reverse_64(data);
    ck_assert_uint_eq(reverse >> 64, 0xAAAAAAAAAAAAAAAA);
    ck_assert_uint_eq((UINT64)reverse, 0xAAAAAAAAAAAAAAAA);
    data = 0xAAAAAAAAAAAAAAAA; data <<= 64; data |= 0xAAAAAAAAAAAAAAAA;
    reverse = sc_bit_reverse_64(data);
    ck_assert_uint_eq(reverse >> 64, 0x5555555555555555);
    ck_assert_uint_eq((UINT64)reverse, 0x5555555555555555);
    data = 0xFEDCBA9876543210; data <<= 64; data |= 0xF7E6D5C4B3A29180;
    reverse = sc_bit_reverse_64(data);
    ck_assert_uint_eq(reverse >> 64, 0x018945CD23AB67EF);
    ck_assert_uint_eq((UINT64)reverse, 0x084C2A6E195D3B7F);
#endif
}
END_TEST

START_TEST(test_rotate_8)
{
    UINT8 rotate = sc_rotl_8(0x81, 1);
    ck_assert_uint_eq(rotate, 0x03);
    rotate = sc_rotl_8(0x81, 0);
    ck_assert_uint_eq(rotate, 0x81);
    rotate = sc_rotl_8(0x81, -1);
    ck_assert_uint_eq(rotate, 0xC0);
    rotate = sc_rotl_8(0x81, 8);
    ck_assert_uint_eq(rotate, 0x81);
    rotate = sc_rotl_8(0x81, 9);
    ck_assert_uint_eq(rotate, 0x03);
    rotate = sc_rotl_8(0x81, 256);
    ck_assert_uint_eq(rotate, 0x81);
    rotate = sc_rotl_8(0x81, -256);
    ck_assert_uint_eq(rotate, 0x81);
    rotate = sc_rotl_8(0x81, -255);
    ck_assert_uint_eq(rotate, 0x03);
}
END_TEST

START_TEST(test_rotate_16)
{
    UINT16 rotate = sc_rotl_16(0x8001, 1);
    ck_assert_uint_eq(rotate, 0x0003);
    rotate = sc_rotl_16(0x8001, 0);
    ck_assert_uint_eq(rotate, 0x8001);
    rotate = sc_rotl_16(0x8001, -1);
    ck_assert_uint_eq(rotate, 0xC000);
    rotate = sc_rotl_16(0x8001, 16);
    ck_assert_uint_eq(rotate, 0x8001);
    rotate = sc_rotl_16(0x8001, 17);
    ck_assert_uint_eq(rotate, 0x0003);
    rotate = sc_rotl_16(0x8001, 256);
    ck_assert_uint_eq(rotate, 0x8001);
    rotate = sc_rotl_16(0x8001, -256);
    ck_assert_uint_eq(rotate, 0x8001);
    rotate = sc_rotl_16(0x8001, -255);
    ck_assert_uint_eq(rotate, 0x0003);
}
END_TEST

START_TEST(test_rotate_32)
{
    UINT32 rotate = sc_rotl_32(0x80000001, 1);
    ck_assert_uint_eq(rotate, 0x00000003);
    rotate = sc_rotl_32(0x80000001, 0);
    ck_assert_uint_eq(rotate, 0x80000001);
    rotate = sc_rotl_32(0x80000001, -1);
    ck_assert_uint_eq(rotate, 0xC0000000);
    rotate = sc_rotl_32(0x80000001, 32);
    ck_assert_uint_eq(rotate, 0x80000001);
    rotate = sc_rotl_32(0x80000001, 33);
    ck_assert_uint_eq(rotate, 0x00000003);
    rotate = sc_rotl_32(0x80000001, 256);
    ck_assert_uint_eq(rotate, 0x80000001);
    rotate = sc_rotl_32(0x80000001, -256);
    ck_assert_uint_eq(rotate, 0x80000001);
    rotate = sc_rotl_32(0x80000001, -255);
    ck_assert_uint_eq(rotate, 0x00000003);
}
END_TEST

START_TEST(test_rotate_64)
{
#ifdef HAVE_64BIT
    UINT64 rotate = sc_rotl_64(0x8000000000000001, 1);
    ck_assert_uint_eq(rotate, 0x0000000000000003);
    rotate = sc_rotl_64(0x8000000000000001, 0);
    ck_assert_uint_eq(rotate, 0x8000000000000001);
    rotate = sc_rotl_64(0x8000000000000001, -1);
    ck_assert_uint_eq(rotate, 0xC000000000000000);
    rotate = sc_rotl_64(0x8000000000000001, 64);
    ck_assert_uint_eq(rotate, 0x8000000000000001);
    rotate = sc_rotl_64(0x8000000000000001, 65);
    ck_assert_uint_eq(rotate, 0x0000000000000003);
    rotate = sc_rotl_64(0x8000000000000001, 256);
    ck_assert_uint_eq(rotate, 0x8000000000000001);
    rotate = sc_rotl_64(0x8000000000000001, -256);
    ck_assert_uint_eq(rotate, 0x8000000000000001);
    rotate = sc_rotl_64(0x8000000000000001, -255);
    ck_assert_uint_eq(rotate, 0x0000000000000003);
#endif
}
END_TEST

START_TEST(test_rotate_128)
{
#ifdef HAVE_128BIT
    UINT128 a = 0x8000000000000000;
    a <<= 64; a |= 0x0000000000000001;
    UINT128 b = 0xC000000000000000;
    b <<= 64; b |= 0x0000000000000000;
    UINT128 c = 0x0000000000000000;
    c <<= 64; c |= 0x0000000000000003;
    UINT128 rotate = sc_rotl_128(a, 1);
    ck_assert_uint_eq(rotate, c);
    rotate = sc_rotl_128(a, 0);
    ck_assert_uint_eq(rotate, a);
    rotate = sc_rotl_128(a, -1);
    ck_assert_uint_eq(rotate, b);
    rotate = sc_rotl_128(a, 128);
    ck_assert_uint_eq(rotate, a);
    rotate = sc_rotl_128(a, 129);
    ck_assert_uint_eq(rotate, c);
    rotate = sc_rotl_128(a, 256);
    ck_assert_uint_eq(rotate, a);
    rotate = sc_rotl_128(a, -256);
    ck_assert_uint_eq(rotate, a);
    rotate = sc_rotl_128(a, -255);
    ck_assert_uint_eq(rotate, c);
#endif
}
END_TEST

START_TEST(test_endianness_32)
{
    UINT32 val;

    val = SC_BIG_ENDIAN_32(0x00010203);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(val, 0x00010203);
#else
    ck_assert_uint_eq(val, 0x03020100);
#endif

    UINT32 be_from[4] = {0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F};
    UINT32 be_to[4];
    SC_BIG_ENDIAN_32_COPY(be_to, 0, be_from, 4 * sizeof(UINT32));
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(be_to[0], 0x00010203);
    ck_assert_uint_eq(be_to[1], 0x04050607);
    ck_assert_uint_eq(be_to[2], 0x08090A0B);
    ck_assert_uint_eq(be_to[3], 0x0C0D0E0F);
#else
    ck_assert_uint_eq(be_to[0], 0x03020100);
    ck_assert_uint_eq(be_to[1], 0x07060504);
    ck_assert_uint_eq(be_to[2], 0x0B0A0908);
    ck_assert_uint_eq(be_to[3], 0x0F0E0D0C);
#endif

    val = SC_LITTLE_ENDIAN_32(0x00010203);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(val, 0x03020100);
#else
    ck_assert_uint_eq(val, 0x00010203);
#endif

    UINT32 le_from[4] = {0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F};
    UINT32 le_to[4];
    SC_LITTLE_ENDIAN_32_COPY(le_to, 0, le_from, 4 * sizeof(UINT32));
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(le_to[0], 0x03020100);
    ck_assert_uint_eq(le_to[1], 0x07060504);
    ck_assert_uint_eq(le_to[2], 0x0B0A0908);
    ck_assert_uint_eq(le_to[3], 0x0F0E0D0C);
#else
    ck_assert_uint_eq(le_to[0], 0x00010203);
    ck_assert_uint_eq(le_to[1], 0x04050607);
    ck_assert_uint_eq(le_to[2], 0x08090A0B);
    ck_assert_uint_eq(le_to[3], 0x0C0D0E0F);
#endif
}
END_TEST

START_TEST(test_endianness_64)
{
#ifdef HAVE_64BIT
    UINT64 val;

    val = SC_BIG_ENDIAN_64(0x0001020304050607);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(val, 0x0001020304050607);
#else
    ck_assert_uint_eq(val, 0x0706050403020100);
#endif

    UINT64 be_from[4] = {0x0001020304050607, 0x08090A0B0C0D0E0F, 0x1011121314151617, 0x18191A1B1C1D1E1F};
    UINT64 be_to[4];
    SC_BIG_ENDIAN_64_COPY(be_to, 0, be_from, 4 * sizeof(UINT64));
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(be_to[0], 0x0001020304050607);
    ck_assert_uint_eq(be_to[1], 0x08090A0B0C0D0E0F);
    ck_assert_uint_eq(be_to[2], 0x1011121314151617);
    ck_assert_uint_eq(be_to[3], 0x18191A1B1C1D1E1F);
#else
    ck_assert_uint_eq(be_to[0], 0x0706050403020100);
    ck_assert_uint_eq(be_to[1], 0x0F0E0D0C0B0A0908);
    ck_assert_uint_eq(be_to[2], 0x1716151413121110);
    ck_assert_uint_eq(be_to[3], 0x1F1E1D1C1B1A1918);
#endif

    val = SC_LITTLE_ENDIAN_32(0x0001020304050607);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(val, 0x0706050403020100);
#else
    ck_assert_uint_eq(val, 0x0001020304050607);
#endif

    UINT64 le_from[4] = {0x0001020304050607, 0x08090A0B0C0D0E0F, 0x1011121314151617, 0x18191A1B1C1D1E1F};
    UINT64 le_to[4];
    SC_LITTLE_ENDIAN_32_COPY(le_to, 0, le_from, 4 * sizeof(UINT64));
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ck_assert_uint_eq(le_to[0], 0x0706050403020100);
    ck_assert_uint_eq(le_to[1], 0x0F0E0D0C0B0A0908);
    ck_assert_uint_eq(le_to[2], 0x1716151413121110);
    ck_assert_uint_eq(le_to[3], 0x1F1E1D1C1B1A1918);
#else
    ck_assert_uint_eq(le_to[0], 0x0001020304050607);
    ck_assert_uint_eq(le_to[1], 0x08090A0B0C0D0E0F);
    ck_assert_uint_eq(le_to[2], 0x1011121314151617);
    ck_assert_uint_eq(le_to[3], 0x18191A1B1C1D1E1F);
#endif
#endif
}
END_TEST

START_TEST(test_rotate_array_32)
{
    SINT32 retcode;
    UINT32 d[4] = {0xE0000000, 0x00000000, 0x00000000, 0x1FFFFFFF};
    retcode = sc_arr_rotl_32(d, 4, 3);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_uint_eq(d[0], 0x00000000);
    ck_assert_uint_eq(d[1], 0x00000000);
    ck_assert_uint_eq(d[2], 0x00000000);
    ck_assert_uint_eq(d[3], 0xFFFFFFFF);
    retcode = sc_arr_rotl_32(d, 4, -31);
    ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
    ck_assert_uint_eq(d[0], 0xFFFFFFFE);
    ck_assert_uint_eq(d[1], 0x00000000);
    ck_assert_uint_eq(d[2], 0x00000000);
    ck_assert_uint_eq(d[3], 0x00000001);
    retcode = sc_arr_rotl_32(d, 4, -32);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
    retcode = sc_arr_rotl_32(d, 4, 32);
    ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
}
END_TEST

Suite *sc_math_suite(void)
{
    Suite *s;
    TCase *tc_parity, *tc_hamming, *tc_ctz, *tc_clz, *tc_rev, *tc_log2,
          *tc_ceil_log2, *tc_rot, *tc_endianness;

    s = suite_create("SC_MATH");

    /* Test cases */
    tc_parity = tcase_create("PARITY");
    tcase_add_test(tc_parity, test_parity_8);
    tcase_add_test(tc_parity, test_parity_16);
    tcase_add_test(tc_parity, test_parity_32);
    tcase_add_test(tc_parity, test_parity_64);
    tcase_add_test(tc_parity, test_parity_128);
    suite_add_tcase(s, tc_parity);

    tc_hamming = tcase_create("HAMMING");
    tcase_add_test(tc_hamming, test_hamming_8);
    tcase_add_test(tc_hamming, test_hamming_16);
    tcase_add_test(tc_hamming, test_hamming_32);
    tcase_add_test(tc_hamming, test_hamming_64);
    suite_add_tcase(s, tc_hamming);

    tc_ctz = tcase_create("CTZ");
    tcase_add_test(tc_ctz, test_ctz_8);
    tcase_add_test(tc_ctz, test_ctz_16);
    tcase_add_test(tc_ctz, test_ctz_32);
    tcase_add_test(tc_ctz, test_ctz_64);
    suite_add_tcase(s, tc_ctz);

    tc_clz = tcase_create("CLZ");
    tcase_add_test(tc_clz, test_clz_8);
    tcase_add_test(tc_clz, test_clz_16);
    tcase_add_test(tc_clz, test_clz_32);
    tcase_add_test(tc_clz, test_clz_64);
    suite_add_tcase(s, tc_clz);

    tc_log2 = tcase_create("LOG2");
    tcase_add_test(tc_log2, test_log2_128);
    tcase_add_test(tc_log2, test_log2_64);
    tcase_add_test(tc_log2, test_log2_32);
    tcase_add_test(tc_log2, test_log2_16);
    tcase_add_test(tc_log2, test_log2_8);
    suite_add_tcase(s, tc_log2);

    tc_ceil_log2 = tcase_create("CEIL_LOG2");
    tcase_add_test(tc_ceil_log2, test_ceil_log2_128);
    tcase_add_test(tc_ceil_log2, test_ceil_log2_64);
    tcase_add_test(tc_ceil_log2, test_ceil_log2_32);
    tcase_add_test(tc_ceil_log2, test_ceil_log2_16);
    tcase_add_test(tc_ceil_log2, test_ceil_log2_8);
    suite_add_tcase(s, tc_ceil_log2);

    tc_rev = tcase_create("REVERSE");
    tcase_add_test(tc_rev, test_reverse_8);
    tcase_add_test(tc_rev, test_reverse_16);
    tcase_add_test(tc_rev, test_reverse_32);
    tcase_add_test(tc_rev, test_reverse_64);
    tcase_add_test(tc_rev, test_reverse_128);
    suite_add_tcase(s, tc_rev);

    tc_rot = tcase_create("ROTATE");
    tcase_add_test(tc_rot, test_rotate_8);
    tcase_add_test(tc_rot, test_rotate_16);
    tcase_add_test(tc_rot, test_rotate_32);
    tcase_add_test(tc_rot, test_rotate_64);
    tcase_add_test(tc_rot, test_rotate_128);
    tcase_add_test(tc_rot, test_rotate_array_32);
    suite_add_tcase(s, tc_rot);

    tc_endianness = tcase_create("ENDIANNESS");
    tcase_add_test(tc_endianness, test_endianness_32);
    tcase_add_test(tc_endianness, test_endianness_64);
    suite_add_tcase(s, tc_endianness);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = sc_math_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}



