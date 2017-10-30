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
#include "utils/arith/sc_mpn.c"


START_TEST(test_mpn_cmp)
{
    SINT32 result;
    sc_ulimb_t a[4] = {1, 2, 3, 4};
    sc_ulimb_t b[4] = {1, 2, 3, 4};
    result = mpn_cmp(a, b, 4);
    ck_assert_int_eq(result, 0);
    b[3] = 3;
    result = mpn_cmp(a, b, 4);
    ck_assert_int_eq(result, 1);
    b[3] = 5;
    result = mpn_cmp(a, b, 4);
    ck_assert_int_eq(result, -1);
}
END_TEST

#ifdef USE_SAFECRYPTO_INTEGER_MP

START_TEST(test_mpn_copy)
{
    size_t i;
    sc_ulimb_t a[4];
    sc_ulimb_t b[4] = {1, 2, 3, 4};
    mpn_copy(a, b, 1);
    for (i=0; i<1; i++) {
        ck_assert_uint_eq(a[i], b[i]);
    }
    mpn_copy(a, b, 2);
    for (i=0; i<2; i++) {
        ck_assert_uint_eq(a[i], b[i]);
    }
    mpn_copy(a, b, 3);
    for (i=0; i<3; i++) {
        ck_assert_uint_eq(a[i], b[i]);
    }
    mpn_copy(a, b, 4);
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(a[i], b[i]);
    }
}
END_TEST

#endif

START_TEST(test_mpn_zero)
{
    size_t i;
    sc_ulimb_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    mpn_zero(a, 8);
    for (i=0; i<8; i++) {
        ck_assert_uint_eq(a[i], 0);
    }
}
END_TEST

START_TEST(test_mpn_zero_p)
{
    SINT32 retval;
    size_t i;
    sc_ulimb_t a[8] = {0, 0, 0, 0, 1, 0, 0, 0};
    sc_ulimb_t b[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    sc_ulimb_t c[8] = {0, 0, 0, 0, 0, 0, 0, SC_LIMB_UMAX};
    sc_ulimb_t d[8] = {SC_LIMB_UMAX, 0, 0, 0, 0, 0, 0, 0};
    sc_ulimb_t e[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    retval = mpn_zero_p(a, 8);
    ck_assert_uint_eq(retval, 0);
    retval = mpn_zero_p(b, 8);
    ck_assert_uint_eq(retval, 0);
    retval = mpn_zero_p(c, 8);
    ck_assert_uint_eq(retval, 0);
    retval = mpn_zero_p(d, 8);
    ck_assert_uint_eq(retval, 0);
    retval = mpn_zero_p(e, 8);
    ck_assert_uint_eq(retval, 1);
}
END_TEST

START_TEST(test_mpn_com)
{
    size_t i;
    sc_ulimb_t a[4] = {1, 2, 3, 4}, b[4];
    mpn_com(b, a, 4);
    for (i=0; i<4; i++) {
        ck_assert_uint_eq(b[i], ~a[i]);
    }
}
END_TEST

#ifdef USE_SAFECRYPTO_INTEGER_MP    

START_TEST(test_mpn_normalized_size)
{
    size_t retval;
    sc_ulimb_t a[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    retval = mpn_normalized_size(a, 8);
    ck_assert_uint_eq(retval, 8);
    a[7] = 0;
    retval = mpn_normalized_size(a, 8);
    ck_assert_uint_eq(retval, 7);
    a[6] = 0;
    retval = mpn_normalized_size(a, 7);
    ck_assert_uint_eq(retval, 6);
    a[5] = 0;
    retval = mpn_normalized_size(a, 6);
    ck_assert_uint_eq(retval, 5);
    a[4] = 0;
    retval = mpn_normalized_size(a, 5);
    ck_assert_uint_eq(retval, 4);
    a[3] = 0;
    retval = mpn_normalized_size(a, 4);
    ck_assert_uint_eq(retval, 3);
    a[2] = 0;
    retval = mpn_normalized_size(a, 3);
    ck_assert_uint_eq(retval, 2);
    a[1] = 0;
    retval = mpn_normalized_size(a, 2);
    ck_assert_uint_eq(retval, 1);
    a[0] = 0;
    retval = mpn_normalized_size(a, 1);
    ck_assert_uint_eq(retval, 0);
}
END_TEST

#endif

START_TEST(test_mpn_lshift)
{
    sc_ulimb_t out[4];
    sc_ulimb_t in[4] = {1, 2, 3, 4};
    mpn_lshift(out, in, 4, 1);
    ck_assert_uint_eq(out[0], 2);
    ck_assert_uint_eq(out[1], 4);
    ck_assert_uint_eq(out[2], 6);
    ck_assert_uint_eq(out[3], 8);
}
END_TEST

START_TEST(test_mpn_rshift)
{
    sc_ulimb_t out[4];
    sc_ulimb_t in[4] = {0x00000001, 0x00000002, 0x00000003, 0x00000004};
    mpn_rshift(out, in, 4, 1);
    ck_assert_uint_eq(out[0], 0);
    ck_assert_uint_eq(out[1], SC_LIMB_HIGHBIT | 1);
    ck_assert_uint_eq(out[2], 1);
    ck_assert_uint_eq(out[3], 2);
}
END_TEST

START_TEST(test_mpn_add_1)
{
    sc_ulimb_t out[4], in[4] = {1, 2, 3, 4};
    mpn_add_1(out, in, 4, 1);
    ck_assert_uint_eq(out[0], 2);
    ck_assert_uint_eq(out[1], 2);
    ck_assert_uint_eq(out[2], 3);
    ck_assert_uint_eq(out[3], 4);
    mpn_add_1(out, in, 4, SC_LIMB_WORD(~0));
    ck_assert_uint_eq(out[0], 0);
    ck_assert_uint_eq(out[1], 3);
    ck_assert_uint_eq(out[2], 3);
    ck_assert_uint_eq(out[3], 4);
}
END_TEST

START_TEST(test_mpn_add_n)
{
    sc_ulimb_t out[4], in1[4] = {1, 2, 3, 4}, in2[4] = {SC_LIMB_WORD(~0), 0, 1, 2};
    mpn_add_n(out, in1, in2, 4);
    ck_assert_uint_eq(out[0], 0);
    ck_assert_uint_eq(out[1], 3);
    ck_assert_uint_eq(out[2], 4);
    ck_assert_uint_eq(out[3], 6);
}
END_TEST

START_TEST(test_mpn_add)
{
    {
        sc_ulimb_t out[4], in1[4] = {1, 2, 3, 4}, in2[3] = {SC_LIMB_WORD(~0), 0, 1};
        mpn_add(out, in1, 4, in2, 3);
        ck_assert_uint_eq(out[0], 0);
        ck_assert_uint_eq(out[1], 3);
        ck_assert_uint_eq(out[2], 4);
        ck_assert_uint_eq(out[3], 4);
    }

    {
        sc_ulimb_t out[4], in1[3] = {SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), SC_LIMB_WORD(-1)},
            in2[2] = {SC_LIMB_WORD(-1), SC_LIMB_WORD(-1)};
        out[3] = mpn_add(out, in1, 3, in2, 2);
        ck_assert_uint_eq(out[0], SC_LIMB_WORD(-2));
        ck_assert_uint_eq(out[1], SC_LIMB_WORD(-1));
        ck_assert_uint_eq(out[2], SC_LIMB_WORD(0));
        ck_assert_uint_eq(out[3], SC_LIMB_WORD(1));
    }
}
END_TEST

START_TEST(test_mpn_sub_1)
{
    sc_ulimb_t out[4], in[4] = {1, 2, 3, 4};
    mpn_sub_1(out, in, 4, 1);
    ck_assert_uint_eq(out[0], 0);
    ck_assert_uint_eq(out[1], 2);
    ck_assert_uint_eq(out[2], 3);
    ck_assert_uint_eq(out[3], 4);
    mpn_sub_1(out, in, 4, SC_LIMB_WORD(~0));
    ck_assert_uint_eq(out[0], in[0] - SC_LIMB_WORD(~0));
    ck_assert_uint_eq(out[1], 1);
    ck_assert_uint_eq(out[2], 3);
    ck_assert_uint_eq(out[3], 4);
}
END_TEST

START_TEST(test_mpn_sub_n)
{
    sc_ulimb_t out[4], in1[4] = {1, 2, 3, 4}, in2[4] = {SC_LIMB_WORD(~0), 0, 1, 2};
    mpn_sub_n(out, in1, in2, 4);
    ck_assert_uint_eq(out[0], 2);
    ck_assert_uint_eq(out[1], 1);
    ck_assert_uint_eq(out[2], 2);
    ck_assert_uint_eq(out[3], 2);
}
END_TEST

START_TEST(test_mpn_sub)
{
    sc_ulimb_t out[4], in1[4] = {1, 2, 3, 4}, in2[3] = {SC_LIMB_WORD(~0), 0, 1};
    mpn_sub(out, in1, 4, in2, 3);
    ck_assert_uint_eq(out[0], 2);
    ck_assert_uint_eq(out[1], 1);
    ck_assert_uint_eq(out[2], 2);
    ck_assert_uint_eq(out[3], 4);
}
END_TEST

START_TEST(test_mpn_addmul_1)
{
    sc_ulimb_t out[4] = {3, 5, 7, 9}, in1[4] = {1, 2, 3, 4};
    mpn_addmul_1(out, in1, 4, 2);
    ck_assert_uint_eq(out[0], 5);
    ck_assert_uint_eq(out[1], 9);
    ck_assert_uint_eq(out[2], 13);
    ck_assert_uint_eq(out[3], 17);
}
END_TEST

START_TEST(test_mpn_submul_1)
{
    sc_ulimb_t out[4] = {3, 5, 7, 9}, in1[4] = {1, 2, 3, 4};
    mpn_submul_1(out, in1, 4, 2);
    ck_assert_uint_eq(out[0], 1);
    ck_assert_uint_eq(out[1], 1);
    ck_assert_uint_eq(out[2], 1);
    ck_assert_uint_eq(out[3], 1);
}
END_TEST

START_TEST(test_mpn_mul_1)
{
    sc_ulimb_t out[4], in1[4] = {1, 2, 3, 4};
    mpn_mul_1(out, in1, 4, 2);
    ck_assert_uint_eq(out[0], 2);
    ck_assert_uint_eq(out[1], 4);
    ck_assert_uint_eq(out[2], 6);
    ck_assert_uint_eq(out[3], 8);
}
END_TEST

START_TEST(test_mpn_mul_n)
{
    sc_ulimb_t out[8], in1[4] = {1, 2, 3, 4}, in2[4] = {5, 6, 7, 8};
    mpn_mul_n(out, in1, in2, 4);
    ck_assert_uint_eq(out[0], 0x00000005);
    ck_assert_uint_eq(out[1], 0x00000010);
    ck_assert_uint_eq(out[2], 0x00000022);
    ck_assert_uint_eq(out[3], 0x0000003C);
    ck_assert_uint_eq(out[4], 0x0000003D);
    ck_assert_uint_eq(out[5], 0x00000034);
    ck_assert_uint_eq(out[6], 0x00000020);
    ck_assert_uint_eq(out[7], 0x00000000);
}
END_TEST

#ifdef USE_SAFECRYPTO_INTEGER_MP    

START_TEST(test_mpn_mul_karatsuba)
{
    sc_ulimb_t out[8], in1[4] = {1, 2, 3, 4}, in2[4] = {5, 6, 7, 8};
    mpn_mul_karatsuba(out, in1, 4, in2, 4);
    ck_assert_uint_eq(out[0], 0x00000005);
    ck_assert_uint_eq(out[1], 0x00000010);
    ck_assert_uint_eq(out[2], 0x00000022);
    ck_assert_uint_eq(out[3], 0x0000003C);
    ck_assert_uint_eq(out[4], 0x0000003D);
    ck_assert_uint_eq(out[5], 0x00000034);
    ck_assert_uint_eq(out[6], 0x00000020);
    ck_assert_uint_eq(out[7], 0x00000000);
}
END_TEST

START_TEST(test_mpn_mul_karatsuba_2)
{
    sc_ulimb_t out[8], in1[4] = {SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), SC_LIMB_WORD(-1)},
        in2[4] = {SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), SC_LIMB_WORD(-1), SC_LIMB_WORD(-1)};
    mpn_mul_karatsuba(out, in1, 4, in2, 4);
    ck_assert_uint_eq(out[0], 1);
    ck_assert_uint_eq(out[1], 0);
    ck_assert_uint_eq(out[2], 0);
    ck_assert_uint_eq(out[3], 0);
    ck_assert_uint_eq(out[4], SC_LIMB_WORD(-2));
    ck_assert_uint_eq(out[5], SC_LIMB_WORD(-1));
    ck_assert_uint_eq(out[6], SC_LIMB_WORD(-1));
    ck_assert_uint_eq(out[7], SC_LIMB_WORD(-1));
}
END_TEST

START_TEST(test_mpn_mul_karatsuba_3)
{
#define KARAT_3_N    256
    size_t i;
    sc_ulimb_t out[2*KARAT_3_N], in1[KARAT_3_N], in2[KARAT_3_N];
    for (i=0; i<KARAT_3_N; i++) {
        in1[i] = SC_LIMB_WORD(-1);
        in2[i] = SC_LIMB_WORD(-1);
    }
    mpn_mul(out, in1, KARAT_3_N, in2, KARAT_3_N);
    ck_assert_uint_eq(out[0], 1);
    for (i=1; i<KARAT_3_N; i++) {
        ck_assert_uint_eq(out[i], 0);
    }
    ck_assert_uint_eq(out[KARAT_3_N], SC_LIMB_WORD(-2));
    for (i=KARAT_3_N+1; i<2*KARAT_3_N; i++) {
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(-1));
    }
}
END_TEST

START_TEST(test_mpn_mul_karatsuba_4)
{
#define KARAT_3_N_A    256
#define KARAT_3_N_B    37
    size_t i;
    sc_ulimb_t out[KARAT_3_N_A+KARAT_3_N_B], in1[KARAT_3_N_A], in2[KARAT_3_N_B];
    for (i=0; i<KARAT_3_N_A; i++) {
        in1[i] = SC_LIMB_WORD(-1);
    }
    for (i=0; i<KARAT_3_N_B; i++) {
        in2[i] = SC_LIMB_WORD(-1);
    }
    mpn_mul_karatsuba(out, in1, KARAT_3_N_A, in2, KARAT_3_N_B);
    for (i=0; i<KARAT_3_N_A+KARAT_3_N_B; i++) {
        fprintf(stderr, "%016lX ", out[i]);
    }
    fprintf(stderr, "\n");
    ck_assert_uint_eq(out[0], 1);
    for (i=1; i<KARAT_3_N_B; i++) {
        ck_assert_uint_eq(out[i], 0);
    }
    ck_assert_uint_eq(out[KARAT_3_N_A], SC_LIMB_WORD(-2));
    for (i=KARAT_3_N_B+1; i<KARAT_3_N_A+KARAT_3_N_B; i++) {
        if (i == KARAT_3_N_A) {
            continue;
        }
        ck_assert_uint_eq(out[i], SC_LIMB_WORD(-1));
    }
}
END_TEST

#endif

START_TEST(test_mpn_mul)
{
    {
        sc_ulimb_t out[8], in1[4] = {1, 2, 3, 4}, in2[4] = {5, 6, 7, 8};
        mpn_mul(out, in1, 4, in2, 4);
        ck_assert_uint_eq(out[0], 0x00000005);
        ck_assert_uint_eq(out[1], 0x00000010);
        ck_assert_uint_eq(out[2], 0x00000022);
        ck_assert_uint_eq(out[3], 0x0000003C);
        ck_assert_uint_eq(out[4], 0x0000003D);
        ck_assert_uint_eq(out[5], 0x00000034);
        ck_assert_uint_eq(out[6], 0x00000020);
        ck_assert_uint_eq(out[7], 0x00000000);
    }
    {
        sc_ulimb_t out[6], in1[4] = {1, 2, 3, 4}, in2[2] = {1, 7};
        mpn_mul(out, in1, 4, in2, 2);
        ck_assert_uint_eq(out[0], 0x00000001);
        ck_assert_uint_eq(out[1], 0x00000009);
        ck_assert_uint_eq(out[2], 0x00000011);
        ck_assert_uint_eq(out[3], 0x00000019);
        ck_assert_uint_eq(out[4], 0x0000001C);
        ck_assert_uint_eq(out[5], 0x00000000);
    }
}
END_TEST

START_TEST(test_mpn_divrem_1)
{
    {
        sc_ulimb_t q[6], r, n[4] = {8, 16, 32, 64};

        r = mpn_divrem_1(q, 3, n, 4, SC_LIMB_HIGHBIT);
        ck_assert_uint_eq(q[3+0], 32);
        ck_assert_uint_eq(q[3+1], 64);
        ck_assert_uint_eq(q[3+2], 128);
        ck_assert_uint_eq(q[0], 0);
        ck_assert_uint_eq(q[1], 0);
        ck_assert_uint_eq(q[2], 16);
        ck_assert_uint_eq(r, 0);
    }
    {
        sc_ulimb_t q[6], r, n[4] = {8, 16, 32, SC_LIMB_HIGHBIT};

        r = mpn_divrem_1(q, 3, n, 4, SC_LIMB_HIGHBIT);
        ck_assert_uint_eq(q[3+0], 32);
        ck_assert_uint_eq(q[3+1], 64);
        ck_assert_uint_eq(q[3+2], 0);
        ck_assert_uint_eq(q[0], 0);
        ck_assert_uint_eq(q[1], 0);
        ck_assert_uint_eq(q[2], 16);
        ck_assert_uint_eq(r, 0);
    }
    {
        sc_ulimb_t q[6], r, n[4] = {8, 16, 32, SC_LIMB_HIGHBIT+1};

        r = mpn_divrem_1(q, 3, n, 4, SC_LIMB_HIGHBIT);
        ck_assert_uint_eq(q[3+0], 32);
        ck_assert_uint_eq(q[3+1], 64);
        ck_assert_uint_eq(q[3+2], 2);
        ck_assert_uint_eq(q[0], 0);
        ck_assert_uint_eq(q[1], 0);
        ck_assert_uint_eq(q[2], 16);
        ck_assert_uint_eq(r, 0);
    }
    {
        sc_ulimb_t q[6], r, n[4] = {8, 16, 32, 64};

        r = mpn_divrem_1(q, 3, n, 4, SC_LIMB_HIGHBIT+1);
        ck_assert_uint_eq(q[3+0], 0x019F);
        ck_assert_uint_eq(q[3+1], SC_LIMB_WORD(-1) - 192 + 1);
        ck_assert_uint_eq(q[3+2], 0x7F);
        ck_assert_uint_eq(q[0], SC_LIMB_UMAX - 3264 + 1);
        ck_assert_uint_eq(q[1], 1631);
        ck_assert_uint_eq(q[2], SC_LIMB_UMAX - 816 + 1);
        ck_assert_uint_eq(r, 3264);
    }
    {
        sc_ulimb_t q[6], r, n[4] = {8, 16, 32, SC_LIMB_HIGHBIT};

        r = mpn_divrem_1(q, 3, n, 4, SC_LIMB_HIGHBIT+1);
        ck_assert_uint_eq(q[3+0], SC_LIMB_WORD(-1) - 103);
        ck_assert_uint_eq(q[3+1], 0x43);
        ck_assert_uint_eq(q[3+2], SC_LIMB_WORD(-2));
        ck_assert_uint_eq(q[0], 895);
        ck_assert_uint_eq(q[1], SC_LIMB_WORD(-1) - 447);
        ck_assert_uint_eq(q[2], 223);
        ck_assert_uint_eq(r, SC_LIMB_SMAX - 894);
    }
}
END_TEST

START_TEST(test_mpn_div_qr_1)
{
    {
        sc_ulimb_t q[4], qh, r, n[4] = {8, 16, 32, 64};

        r = mpn_div_qr_1(q, &qh, n, 4, SC_LIMB_HIGHBIT);
        ck_assert_uint_eq(q[0], 32);
        ck_assert_uint_eq(q[1], 64);
        ck_assert_uint_eq(q[2], 128);
        ck_assert_uint_eq(qh, 0);
        ck_assert_uint_eq(r, 8);
    }
    {
        sc_ulimb_t q[4], qh, r, n[4] = {8, 16, 32, SC_LIMB_HIGHBIT};

        r = mpn_div_qr_1(q, &qh, n, 4, SC_LIMB_HIGHBIT);
        ck_assert_uint_eq(q[0], 32);
        ck_assert_uint_eq(q[1], 64);
        ck_assert_uint_eq(q[2], 0);
        ck_assert_uint_eq(qh, 1);
        ck_assert_uint_eq(r, 8);
    }
    {
        sc_ulimb_t q[4], qh, r, n[4] = {8, 16, 32, SC_LIMB_HIGHBIT+1};

        r = mpn_div_qr_1(q, &qh, n, 4, SC_LIMB_HIGHBIT);
        ck_assert_uint_eq(q[0], 32);
        ck_assert_uint_eq(q[1], 64);
        ck_assert_uint_eq(q[2], 2);
        ck_assert_uint_eq(qh, 1);
        ck_assert_uint_eq(r, 8);
    }
    {
        sc_ulimb_t q[4], qh, r, n[4] = {8, 16, 32, 64};

        r = mpn_div_qr_1(q, &qh, n, 4, SC_LIMB_HIGHBIT+1);
        ck_assert_uint_eq(q[0], 0x019F);
        ck_assert_uint_eq(q[1], SC_LIMB_WORD(-1) - 192 + 1);
        ck_assert_uint_eq(q[2], 0x7F);
        ck_assert_uint_eq(qh, 0);
        ck_assert_uint_eq(r, SC_LIMB_SMAX - 0x196);
    }
    {
        sc_ulimb_t q[4], qh, r, n[4] = {8, 16, 32, SC_LIMB_HIGHBIT};

        r = mpn_div_qr_1(q, &qh, n, 4, SC_LIMB_HIGHBIT+1);
        ck_assert_uint_eq(q[0], SC_LIMB_WORD(-1) - 103);
        ck_assert_uint_eq(q[1], 0x43);
        ck_assert_uint_eq(q[2], SC_LIMB_WORD(-2));
        ck_assert_uint_eq(qh, 0);
        ck_assert_uint_eq(r, 112);
    }
}
END_TEST

#ifdef USE_SAFECRYPTO_INTEGER_MP    

START_TEST(test_mpn_div_qr)
{
    sc_ulimb_t q[8], n[8], d[8];
    n[0] = 2;
    d[0] = 1;
    mpn_div_qr(q, n, 1, d, 1);
    ck_assert_uint_eq(q[0], 2);
    n[0] = SC_LIMB_HIGHBIT;
    d[0] = 8;
    mpn_div_qr(q, n, 1, d, 1);
    ck_assert_uint_eq(q[0], SC_LIMB_HIGHBIT >> 3);
    n[1] = SC_LIMB_HIGHBIT;
    n[0] = 8;
    d[0] = 8;
    mpn_div_qr(q, n, 2, d, 1);
    ck_assert_uint_eq(q[1], SC_LIMB_HIGHBIT >> 3);
    ck_assert_uint_eq(q[0], 1);
    n[1] = SC_LIMB_HIGHBIT;
    n[0] = 0;
    d[1] = 2;
    d[0] = 0;
    mpn_div_qr(q, n, 2, d, 2);
    ck_assert_uint_eq(q[0], SC_LIMB_HIGHBIT >> 1);
    n[2] = 0x3333;
    n[1] = 0;
    n[0] = 0;
    d[1] = 3;
    d[0] = 0;
    mpn_div_qr(q, n, 3, d, 2);
    ck_assert_uint_eq(q[1], 0x1111);
    ck_assert_uint_eq(q[0], 0);
}
END_TEST

#endif


Suite *sc_mp_suite(void)
{
    Suite *s;
    TCase *tc_mpn;

    s = suite_create("SC_MP");

    /* Test cases */
    tc_mpn = tcase_create("mpn");
#ifdef USE_SAFECRYPTO_INTEGER_MP    
    tcase_add_test(tc_mpn, test_mpn_normalized_size);
    tcase_add_test(tc_mpn, test_mpn_copy);
#endif
    tcase_add_test(tc_mpn, test_mpn_cmp);
    tcase_add_test(tc_mpn, test_mpn_zero);
    tcase_add_test(tc_mpn, test_mpn_zero_p);
    tcase_add_test(tc_mpn, test_mpn_com);
    tcase_add_test(tc_mpn, test_mpn_lshift);
    tcase_add_test(tc_mpn, test_mpn_rshift);
    tcase_add_test(tc_mpn, test_mpn_add_1);
    tcase_add_test(tc_mpn, test_mpn_add_n);
    tcase_add_test(tc_mpn, test_mpn_add);
    tcase_add_test(tc_mpn, test_mpn_sub_1);
    tcase_add_test(tc_mpn, test_mpn_sub_n);
    tcase_add_test(tc_mpn, test_mpn_sub);
    tcase_add_test(tc_mpn, test_mpn_addmul_1);
    tcase_add_test(tc_mpn, test_mpn_submul_1);
    tcase_add_test(tc_mpn, test_mpn_mul_1);
    tcase_add_test(tc_mpn, test_mpn_mul_n);
    tcase_add_test(tc_mpn, test_mpn_mul);
    tcase_add_test(tc_mpn, test_mpn_divrem_1);
    tcase_add_test(tc_mpn, test_mpn_div_qr_1);
#ifdef USE_SAFECRYPTO_INTEGER_MP    
    tcase_add_test(tc_mpn, test_mpn_div_qr);
    tcase_add_test(tc_mpn, test_mpn_mul_karatsuba);
    tcase_add_test(tc_mpn, test_mpn_mul_karatsuba_2);
    tcase_add_test(tc_mpn, test_mpn_mul_karatsuba_3);
    tcase_add_test(tc_mpn, test_mpn_mul_karatsuba_4);
#endif
    suite_add_tcase(s, tc_mpn);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = sc_mp_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}



