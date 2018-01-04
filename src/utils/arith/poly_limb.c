/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#include "utils/arith/poly_limb.h"
#include "utils/arith/ntt.h"
#include "utils/arith/sc_math.h"
#include "utils/arith/sc_mp.h"
#include "utils/arith/sc_mpn.h"
#include "safecrypto_types.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"
//#include "utils/third_party/libtommath-develop/tommath.h"

#include <math.h>
#include <assert.h>


#define POLY_LIMB_DIVCONQUER_THRESH                256
#define POLY_LIMB_HALFGCD_THRESHOLD                128
#define POLY_LIMB_SMALL_GCD_THRESH                 192
#define POLY_LIMB_LARGE_GCD_THRESH                 384
#define POLY_LIMB_MUL_GRADESCHOOL_THRESH           6
#define POLY_LIMB_MUL_GRADESCHOOL_SMALL_B_THRESH   2
#define POLY_LIMB_MUL_KARATSUBA_THRESH             16
#define POLY_LIMB_MUL_KS4_THRESH                   320
#define POLY_LIMB_DIVREM_DIVCONQUER_THRESH         16
#define POLY_2X2_MATRIX_STRASSEN_THRESH            20


typedef struct sc_halfgcd_resultant
{
    sc_ulimb_t res;
    sc_ulimb_t lc;
    size_t     l0;
    size_t     l1;
    size_t     off;
} sc_halfgcd_resultant_t;



sc_ulimb_t limb_mp_lshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t len, size_t shift)
{
    return mpn_lshift(out, in, len, shift);
}

sc_ulimb_t limb_mp_rshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t len, size_t shift)
{
    return mpn_rshift(out, in, len, shift);
}

SINT32 limb_mp_cmp(const sc_ulimb_t *a, const sc_ulimb_t *b, size_t len)
{
    return mpn_cmp(a, b, len);
}

sc_ulimb_t limb_mp_add_1(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t b)
{
    return mpn_add_1(out, a, len_a, b);
}

sc_ulimb_t limb_mp_add_n(sc_ulimb_t *out, const sc_ulimb_t *a, const sc_ulimb_t *b, size_t len)
{
    return mpn_add_n(out, a, b, len);
}

sc_ulimb_t limb_mp_sub_1(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t b)
{
    return mpn_sub_1(out, a, len_a, b);
}

sc_ulimb_t limb_mp_sub_n(sc_ulimb_t *out, const sc_ulimb_t *a, const sc_ulimb_t *b, size_t len)
{
    return mpn_sub_n(out, a, b, len);
}

sc_ulimb_t limb_mp_mul(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b)
{
    return mpn_mul(out, a, len_a, b, len_b);
}

sc_ulimb_t limb_mp_mul_1(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b)
{
    return mpn_mul_1(out, a, len_a, b);
}

sc_ulimb_t limb_mp_addmul_1(sc_ulimb_t *inout, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b)
{
    return mpn_addmul_1(inout, a, len_a, b);
}

void limb_mp_mul_n(sc_ulimb_t *out, const sc_ulimb_t *a,
    const sc_ulimb_t *b, size_t len)
{
    return mpn_mul_n(out, a, b, len);
}


static SINT32 poly_limb_divrem_mod_limbcount(SINT32 len1, SINT32 len2, sc_ulimb_t norm)
{
    const size_t bits = 
        2 * (SC_LIMB_BITS - norm) + SC_LIMB_BITS - limb_clz(len1 - len2 + 1);
    
    if (bits <= SC_LIMB_BITS) {
        return len1;
    }
    else if (bits <= 2 * SC_LIMB_BITS) {
        return 2*(len1 + len2 - 1);
    }
    else {
        return 3*(len1 + len2 - 1);
    }
}

static SINT32 poly_limb_divrem_mod_divconquer_limbcount(SINT32 len, sc_ulimb_t norm)
{
    size_t i = 0;
    while (len > POLY_LIMB_DIVCONQUER_THRESH + i) {
        len = (len + 1) >> 1;
        i++;
    }
    if (len > POLY_LIMB_DIVCONQUER_THRESH) {
        len = POLY_LIMB_DIVCONQUER_THRESH;
    }

    return poly_limb_divrem_mod_limbcount(2*len - 1, len, norm) + 2*len - 1;
}

// Swap the contents of polynomial in to polynomial out
SINT32 poly_limb_copy(sc_ulimb_t *SC_RESTRICT out, size_t n, const sc_ulimb_t *SC_RESTRICT in)
{
    if (NULL == in || NULL == out) {
        return SC_FUNC_FAILURE;
    }
    if (out == in) {
        return SC_FUNC_SUCCESS;
    }

    size_t i;
    for (i=n; i--;) {
        out[i] = in[i];
    }
    return SC_FUNC_SUCCESS;
}

// Swap the contents of polynomial a with polynomial b
SINT32 poly_limb_swap(sc_ulimb_t *SC_RESTRICT a, size_t *len_a,
    sc_ulimb_t *SC_RESTRICT b, size_t *len_b)
{
    if (NULL == a || NULL == b) {
        return SC_FUNC_FAILURE;
    }
    if (a == b && *len_a == *len_b) {
        return SC_FUNC_SUCCESS;
    }

    sc_ulimb_t t;
    size_t i, min = SC_MIN(*len_a, *len_b);
    for (i=0; i<min; i++) {
        t    = a[i];
        a[i] = b[i];
        b[i] = t;
    }

    *len_a ^= *len_b;
    *len_b ^= *len_a;
    *len_a ^= *len_b;

    return SC_FUNC_SUCCESS;
}

// Swap the pointers and lengths of polynomials a and b
static void poly_limb_swap_pointers(sc_ulimb_t **a, size_t *len_a, sc_ulimb_t **b, size_t *len_b)
{
    sc_ulimb_t *t;
    t  = *a;
    *a = *b;
    *b = t;
    *len_b ^= *len_a;
    *len_a ^= *len_b;
    *len_b ^= *len_a;
}

SINT32 poly_limb_degree(const sc_ulimb_t *h, size_t n)
{
    SINT32 deg = -1;
    if (NULL != h && n > 0) {
        size_t j = n - 1;
        while (0 == h[j]) {
            if (0 == j) {
                break;
            }
            j--;
        }
        deg = j;
    }
    return deg;
}

SINT32 poly_limb_is_zero(const sc_ulimb_t *h, size_t n)
{
    SINT32 degree = poly_limb_degree(h, n);
    if (0 == degree && 0 == h[0]) {
        return 0;
    }
    return 1;
}

void poly_limb_reset(sc_ulimb_t *inout, size_t n)
{
    size_t i;
    for (i=0; i<n; i++) {
        inout[i] = SC_LIMB_WORD(0);
    }
}

void poly_limb_negate_mod(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n, const sc_mod_t *mod)
{
    size_t i;
    const sc_ulimb_t m     = mod->m;

    for (i=0; i<n; i++) {
        out[i] = limb_negate_mod(in[i], m);
    }
}

void poly_limb_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_mod_t *mod)
{
    size_t i;
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    for (i=0; i<len_a; i++) {
        out[i] = limb_mod_l(a[i], m, m_inv, norm);
    }
}

void poly_limb_add_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    size_t i;
    const size_t min_len = SC_MIN(len_a, len_b);
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t norm  = mod->norm;

    if (norm) {
        for (i=min_len; i--;) {
            out[i] = limb_add_mod_norm(a[i], b[i], m);
        }
    }
    else {
        for (i=min_len; i--;) {
            out[i] = limb_add_mod(a[i], b[i], m);
        }
    }

    if (len_a < len_b) {
        for (i=min_len; i<len_b; i++) {
           out[i] = b[i];
        }
    }
    else {
        for (i=min_len; i<len_a; i++) {
           out[i] = a[i];
        }
    }
}

void poly_limb_sub_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    size_t i;
    const size_t min_len = (len_a < len_b)? len_a : len_b;
    const sc_ulimb_t m = mod->m;

    if (mod->norm) {
        for (i=min_len; i--;) {
            out[i] = limb_sub_mod_norm(a[i], b[i], m);
        }
    }
    else {
        for (i=min_len; i--;) {
            out[i] = limb_sub_mod(a[i], b[i], m);
        }
    }
    if (a != out) {
        for (i=min_len; i<len_a; i++) {
           out[i] = a[i];
        }
    }
    for (i=min_len; i<len_b; i++) {
       out[i] = limb_negate_mod(b[i], m);
    }
}

static void poly_limb_mul_mod_simple(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    size_t i;
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    // Set res[i] = a[i]*b[0]
    limb_mp_mul_1(out, a, len_a, b[0]);

    if (1 != len_b)
    {
        // Set out[i+len_a-1] = in1[len_a-1]*in2[i]
        limb_mp_mul_1(out + len_a, b + 1, len_b - 1, a[len_a - 1]);

        // out[i+j] += in1[i]*in2[j]
        for (i=len_a - 1; i--;) {
            limb_mp_addmul_1(out + i + 1, b + 1, len_b - 1, a[i]);
        }
    }

    if (norm) {
        for (i=len_a + len_b - 1; i--;) {
            out[i] = limb_mod_reduction_norm(0, out[i], m, m_inv, norm);
        }
    }
    else {
        for (i=len_a + len_b - 1; i--;) {
            out[i] = limb_mod_reduction(0, out[i], m, m_inv);
        }
    }
}

static void poly_limb_mul_mod_gradeschool(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    size_t i, j;
    sc_ulimb_t hi, lo;
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    const SINT32     log_len = SC_LIMB_BITS - limb_clz(len_b);
    const sc_ulimb_t bits    = mod->b_norm;

    if ((2*bits + log_len) <= SC_LIMB_BITS) {
        poly_limb_mul_mod_simple(out, a, len_a, b, len_b, mod);
        return;
    }

#if 1
    if (len_a == 0 || len_b == 0) {
        for (i=len_a+len_b-1; i--;) {
            out[i] = 0;
        }
        return;
    }

    if (norm) {
        for (j=len_a; j--;) {
            limb_mul_hi_lo(&hi, &lo, a[j], b[0]);
            out[j] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
        }

        if (1 == len_b) {
            return;
        }

        for (j=len_b-1; j--;) {
            limb_mul_hi_lo(&hi, &lo, b[j+1], a[len_a-1]);
            out[j+len_a] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
        }

        for (i=len_a-1; i--;) {
            for (j=len_b-1; j--;) {
                limb_mul_hi_lo(&hi, &lo, b[j+1], a[i]);
                limb_add_hi_lo(&hi, &lo, hi, lo, SC_LIMB_WORD(0), out[1+j+i]);
                out[1+j+i] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
            }
        }
    }
    else {
        if (b[0]) {
            for (j=len_a; j--;) {
                limb_mul_hi_lo(&hi, &lo, a[j], b[0]);
                out[j] = limb_mod_reduction(hi, lo, m, m_inv);
            }
        }

        if (1 == len_b) {
            return;
        }

        for (j=len_b-1; j--;) {
            limb_mul_hi_lo(&hi, &lo, b[j+1], a[len_a-1]);
            out[j+len_a] = limb_mod_reduction(hi, lo, m, m_inv);
        }

        for (i=len_a-1; i--;) {
            for (j=len_b-1; j--;) {
                limb_mul_hi_lo(&hi, &lo, b[j+1], a[i]);
                limb_add_hi_lo(&hi, &lo, hi, lo, SC_LIMB_WORD(0), out[j+1+i]);
                out[j+1+i] = limb_mod_reduction(hi, lo, m, m_inv);
            }
        }
    }
#else
    for (i=len_a+len_b-1; i--;) {
        out[i] = 0;
    }

    if (len_a == 0 || len_b == 0) {
        return;
    }

    for (i=0; i<len_a; i++) {
        for (j=0; j<len_b; j++) {
            limb_mul_hi_lo(&hi, &lo, a[i], b[j]);
            limb_add_hi_lo(&hi, &lo, hi, lo, SC_LIMB_WORD(0), out[i+j]);
            out[i+j] = limb_mod_reduction(hi, lo, mod->m, mod->m_inv);
        }
    }
#endif
}

static void poly_limb_mul_mod_gradeschool_trunc(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, size_t n, const sc_mod_t *mod)
{
    size_t i, j;
    sc_ulimb_t hi, lo;
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

#if 1
    if (len_a == 0 || len_b == 0) {
        for (i=SC_MIN(len_a+len_b-1,n); i--;) {
            out[i] = 0;
        }
        return;
    }

    for (j=SC_MIN(len_a,n); j--;) {
        limb_mul_hi_lo(&hi, &lo, a[j], b[0]);
        out[j] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
    }
    if (1 == len_b) {
        return;
    }

    if (n > len_a) {
        for (j=SC_MIN(len_b,n)-1; j--;) {
            limb_mul_hi_lo(&hi, &lo, b[j+1], a[len_a-1]);
            out[j+len_a] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
        }
    }
    
    for (i=SC_MIN(len_a,n)-1; i--;) {
        for (j=SC_MIN(len_b,n-i)-1; j--;) {
            limb_mul_hi_lo(&hi, &lo, b[j+1], a[i]);
            limb_add_hi_lo(&hi, &lo, hi, lo, SC_LIMB_WORD(0), out[j+i+1]);
            out[j+i+1] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
        }
    }
#else
    for (i=len_a+len_b-1; i--;) {
        out[i] = 0;
    }

    if (len_a == 0 || len_b == 0) {
        return;
    }

    for (i=0; i<len_a; i++) {
        for (j=0; j<len_b; j++) {
            limb_mul_hi_lo(&hi, &lo, a[i], b[j]);
            limb_add_hi_lo(&hi, &lo, hi, lo, SC_LIMB_WORD(0), out[i+j]);
            out[i+j] = limb_mod_reduction(hi, lo, mod->m, mod->m_inv);
        }
    }
#endif
}

static size_t poly_limb_max_bits(const sc_ulimb_t *vec, size_t len)
{
    size_t i, bits = 0;
#if 1
    sc_ulimb_t mask = 0;

    // This can be vectorised ...
    for (i=0; i<len; i++) {
        mask |= vec[i];
    }
    bits = SC_LIMB_BITS - limb_clz(mask);
#else
    sc_ulimb_t mask = ~(sc_ulimb_t) 0;
    
    for (i=0; i<len; i++) {
        if (vec[i] & mask) {
            bits = SC_LIMB_BITS - limb_clz(vec[i]);
            if (bits == SC_LIMB_BITS) {
                break;
            }
            else {
                mask = ~SC_LIMB_WORD(0) - ((SC_LIMB_WORD(1) << bits) - SC_LIMB_WORD(1));
            }
        }
    }
#endif
    
    return bits;
}

static void poly_limb_ks_bit_pack(sc_ulimb_t *res, const sc_ulimb_t *poly, size_t len, size_t bits)
{
    size_t i;
    size_t current_bit = 0, current_limb = 0;
    size_t total_limbs = ((len * bits - 1) / SC_LIMB_BITS) + 1;
    sc_ulimb_t temp_lower, temp_upper;

    res[0] = SC_LIMB_WORD(0);

    if (bits < SC_LIMB_BITS) {
        // When packing the coefficients are smaller than a limb
        const size_t limit_bit = SC_LIMB_BITS - bits;

        for (i=0; i<len; i++) {
            if (current_bit > limit_bit) {
                // The coefficient will be added accross a limb boundary
                temp_lower = (poly[i] << current_bit);
                temp_upper = (poly[i] >> (SC_LIMB_BITS - current_bit));

                res[current_limb] |= temp_lower;

                current_limb++;
                res[current_limb] = temp_upper;

                current_bit += bits - SC_LIMB_BITS;
            }
            else {
                // The coefficient will fit in the current limb
                temp_lower = poly[i] << current_bit;
                res[current_limb] |= temp_lower;

                current_bit += bits;

                if (current_bit == SC_LIMB_BITS) {
                    current_limb++;
                    if (current_limb < total_limbs)
                        res[current_limb] = SC_LIMB_WORD(0);
                    current_bit = 0;
                }
            }
        }
    }
    else if (bits == SC_LIMB_BITS) {
        // If bits are equivalent to a limb word in size
        // we can quickly copy
        for (i=len; i--;) {
            res[i] = poly[i];
        }
    }
    else if (bits == 2 * SC_LIMB_BITS) {
        // If bits are equivalent to two limb words in size
        // we can quickly copy
        for (i = 0; i < len; i++) {
            res[current_limb++] = poly[i];
            res[current_limb++] = SC_LIMB_WORD(0);
        }
    }
    else if (bits < 2 * SC_LIMB_BITS) {
        for (i = 0; i < len; i++) {
            // As bits is less than two limbs in lengths the coefficient lies
            // across a limb boundary
            temp_lower = poly[i] << current_bit;
            temp_upper = SC_LIMB_RSHIFT(poly[i], SC_LIMB_BITS - current_bit);

            res[current_limb++] |= temp_lower;
            res[current_limb] = temp_upper;

            current_bit += bits - SC_LIMB_BITS;

            if (current_bit >= SC_LIMB_BITS) {
                current_bit -= SC_LIMB_BITS;
                current_limb++;
                if (current_limb < total_limbs) {
                    res[current_limb] = SC_LIMB_WORD(0);
                }
            }
        }
    }
    else {
        // 2*SC_LIMB_BITS < bits < 3*SC_LIMB_BITS
        for (i = 0; i < len; i++) {
            temp_lower = poly[i] << current_bit;
            temp_upper = SC_LIMB_RSHIFT(poly[i], SC_LIMB_BITS - current_bit);

            res[current_limb++] |= temp_lower;
            res[current_limb++] = temp_upper;

            if (current_limb < total_limbs) {
                res[current_limb] = SC_LIMB_WORD(0);
            }
            current_bit += bits - 2 * SC_LIMB_BITS;

            if (current_bit >= SC_LIMB_BITS) {
                current_bit -= SC_LIMB_BITS;
                current_limb++;
                if (current_limb < total_limbs) {
                    res[current_limb] = SC_LIMB_WORD(0);
                }
            }
        }
    }
}

static void poly_limb_ks_bit_unpack(sc_ulimb_t *res, size_t len, const sc_ulimb_t *poly,
    size_t bits, const sc_mod_t *mod)
{
    size_t i;
    size_t current_bit = 0, current_limb = 0;
    sc_ulimb_t temp_lower, temp_upper, temp_upper2;
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    if (bits < SC_LIMB_BITS) {
        const size_t limit_bit = SC_LIMB_BITS - bits;
        const sc_ulimb_t mask = (SC_LIMB_WORD(1) << bits) - SC_LIMB_WORD(1);

        for (i = 0; i < len; i++) {
            if (current_bit > limit_bit) {
                temp_lower = poly[current_limb++] >> current_bit;
                temp_upper = poly[current_limb] << (SC_LIMB_BITS - current_bit);

                temp_upper |= temp_lower;
                temp_upper &= mask;

                res[i] = limb_mod_l(temp_upper, m, m_inv, norm);

                current_bit += bits - SC_LIMB_BITS;
            }
            else {
                // The coefficient will fit in the current limb
                temp_upper = (poly[current_limb] >> current_bit) & mask;

                res[i] = limb_mod_l(temp_upper, m, m_inv, norm);

                current_bit += bits;

                if (current_bit == SC_LIMB_BITS) {
                    current_bit = 0;
                    current_limb++;
                }
            }
        }
    }
    else if (bits == SC_LIMB_BITS) {
        // Directly and efficiently transfer the reduced coefficients to the output
        for (i=len; i--;) {
            res[i] = limb_mod_reduction_norm(0, poly[i], m, m_inv, norm);
        }
    }
    else if (bits == 2 * SC_LIMB_BITS) {
        // Directly and efficiently transfer the reduced coefficients to the output
        for (i=0; i<len; i++) {
            res[i] = limb_mod_ll(poly[current_limb + 1], poly[current_limb], m, m_inv, norm);
            current_limb += 2;
        }
    }
    else if (bits < 2 * SC_LIMB_BITS) {
        // SC_LIMB_BITS < bits < 2*SC_LIMB_BITS
        const size_t double_limit_bit = 2 * SC_LIMB_BITS - bits;
        const sc_ulimb_t mask = (SC_LIMB_WORD(1) << (bits - SC_LIMB_BITS)) - SC_LIMB_WORD(1);

        for (i=0; i<len; i++) {
            if (current_bit == 0) {
                temp_lower = poly[current_limb++];
                temp_upper = poly[current_limb] & mask;

                res[i] = limb_mod_ll(temp_upper, temp_lower, m, m_inv, norm);

                current_bit = bits - SC_LIMB_BITS;
            }
            else if (current_bit > double_limit_bit) {
                // The coefficient will be across two limb boundaries
                temp_lower  = poly[current_limb++] >> current_bit;
                temp_lower |= (poly[current_limb] << (SC_LIMB_BITS - current_bit));

                temp_upper  = poly[current_limb++] >> current_bit;
                temp_upper |= (poly[current_limb] << (SC_LIMB_BITS - current_bit));
                temp_upper &= mask;

                res[i] = limb_mod_ll(temp_upper, temp_lower, m, m_inv, norm);

                current_bit += bits - 2 * SC_LIMB_BITS;
            }
            else {
                // The coefficient will be across one limb boundary
                temp_lower = (poly[current_limb] >> current_bit) | (poly[current_limb + 1]
                                                          << (SC_LIMB_BITS -
                                                              current_bit));
                current_limb++;

                temp_upper = poly[current_limb] >> current_bit;
                temp_upper &= mask;

                res[i] = limb_mod_ll(temp_upper, temp_lower, m, m_inv, norm);

                current_bit += bits - SC_LIMB_BITS;
                if (current_bit == SC_LIMB_BITS) {
                    current_bit = 0;
                    current_limb++;
                }
            }
        }
    }
    else {
        // 2*SC_LIMB_BITS < bits < 3*SC_LIMB_BITS
        const size_t double_limit_bit = 3 * SC_LIMB_BITS - bits;
        const sc_ulimb_t mask = (SC_LIMB_WORD(1) << (bits - 2 * SC_LIMB_BITS)) - SC_LIMB_WORD(1);

        for (i = 0; i < len; i++) {
            if (current_bit == 0) {
                temp_lower = poly[current_limb++];
                temp_upper = poly[current_limb++];
                temp_upper2 = poly[current_limb] & mask;

                res[i] = limb_mod_lll(temp_upper2, temp_upper, temp_lower, m, m_inv, norm);

                current_bit = bits - 2 * SC_LIMB_BITS;
            }
            else if (current_bit <= double_limit_bit) {
                // the coeff will be across two limb boundaries
                temp_lower  = poly[current_limb++] >> current_bit;
                temp_lower |= (poly[current_limb] << (SC_LIMB_BITS - current_bit));

                temp_upper  = poly[current_limb++] >> current_bit;
                temp_upper |= (poly[current_limb] << (SC_LIMB_BITS - current_bit));

                temp_upper2 = poly[current_limb] >> current_bit;
                temp_upper2 &= mask;

                res[i] = limb_mod_lll(temp_upper2, temp_upper, temp_lower, m, m_inv, norm);

                current_bit += bits - 2 * SC_LIMB_BITS;
                if (current_bit == SC_LIMB_BITS) {
                    current_bit = 0;
                    current_limb++;
                }
            }
            else {
                // the coeff will be across three limb boundaries
                temp_lower  = poly[current_limb++] >> current_bit;
                temp_lower |= (poly[current_limb] << (SC_LIMB_BITS - current_bit));

                temp_upper  = poly[current_limb++] >> current_bit;
                temp_upper |= (poly[current_limb] << (SC_LIMB_BITS - current_bit));

                temp_upper2  = poly[current_limb++] >> current_bit;
                temp_upper2 |= (poly[current_limb] << (SC_LIMB_BITS - current_bit));

                temp_upper2 &= mask;

                res[i] = limb_mod_lll(temp_upper2, temp_upper, temp_lower, m, m_inv, norm);

                current_bit += bits - 3 * SC_LIMB_BITS;
            }
        }
    }
}

static void poly_limb_mul_mod_kronecker(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    const size_t len_out = len_a + len_b - 1;
    const size_t bits1   = poly_limb_max_bits(a, len_a);
    const size_t bits2   = (a == b)? bits1 : poly_limb_max_bits(b, len_b);
    const size_t log_len = SC_LIMB_BITS - limb_clz(len_b);
    const size_t bits    = bits1 + bits2 + log_len;

    // Determine the total number of limbs in each input (rounded up)
    const size_t limbs1 = ((len_a * bits - 1) / SC_LIMB_BITS) + 1;
    const size_t limbs2 = ((len_b * bits - 1) / SC_LIMB_BITS) + 1;

    // Calculate the depth of memory needed to store the packed variables
    const size_t depth = (a == b)? (2*limbs1 + limbs2) : (2 * (limbs1 + limbs2));

    // Allocate and assign memory
    sc_ulimb_t *mp0, *mp1, *res;
    res  = (sc_ulimb_t*) SC_MALLOC(sizeof(sc_ulimb_t) * depth);
    mp0 = res + limbs1 + limbs2;
    mp1 = (a == b)? mp0 : mp0 + limbs1;

    // Pack the polynomial coefficients into a multiple-precision variable
    poly_limb_ks_bit_pack(mp0, a, len_a, bits);
    if (a != b) {
        poly_limb_ks_bit_pack(mp1, b, len_b, bits);
    }

    // Use the GMP multiple-precision multiply
    if (limbs1 == limbs2) {
        limb_mp_mul_n(res, mp0, mp1, limbs1);
    }
    else {
        limb_mp_mul(res, mp0, limbs1, mp1, limbs2);
    }

    // Unpack back into polynomial coefficients
    poly_limb_ks_bit_unpack(out, len_out, res, bits, mod);

    // Free memory resources     
    SC_FREE(res, sizeof(sc_ulimb_t) * depth);
}

static void poly_limb_ks2_bit_pack(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n,
    const size_t s, size_t k, const size_t r, const size_t w)
{
    sc_ulimb_t *dest, buf;
    size_t bits;

    // Initialisation
    dest = out;
    buf  = 0;
    bits = k;

    // Output k words of zero-padding
    while (k >= SC_LIMB_BITS) {
        *dest++  = 0;
        k       -= SC_LIMB_BITS;
    }

    while (n--) {
        const size_t prev_bits  = bits;
        buf       += *in << bits;
        bits      += w;
        if (bits >= SC_LIMB_BITS) {
            // Flush the buffer but keep remaining bits
            *dest++  = buf;
            bits    -= SC_LIMB_BITS;
            buf      = (prev_bits)? (*in >> (SC_LIMB_BITS - prev_bits)) : 0;

            // Output zero padding
            if (w > SC_LIMB_BITS) {
                if (bits >= SC_LIMB_BITS) {
                    *dest++  = buf;
                    buf      = 0;
                    bits    -= SC_LIMB_BITS;
                    if (bits >= SC_LIMB_BITS) {
                        *dest++  = 0;
                        bits    -= SC_LIMB_BITS;
                    }
                }
            }
        }

        in += s;
    }

    // Flush any remaining data from the buffer
    if (bits) {
        *dest++ = buf;
    }

    // Add any requested zero padding
    if (r) {
        size_t written = dest - out; 
        while (written++ < r) {
            *dest++ = 0;
        }
   }
}

static void poly_limb_ks2_bit_unpack(sc_ulimb_t *out, const sc_ulimb_t *in,
    size_t n, size_t w, size_t k)
{
    sc_ulimb_t temp, buf;
    size_t mask, bits;
    const size_t w_gt_1 = w > SC_LIMB_BITS;
    const size_t w_gt_2 = w > 2*SC_LIMB_BITS;

    buf  = 0;
    bits = 0;

    // Deal with the zero padding
    while (k >= SC_LIMB_BITS) {
        k -= SC_LIMB_BITS;
        in++;
    }

    // Initialisation of the buffer if k is non-zero
    if (k) {
        buf   = *in++;
        buf >>= k;
        bits  = SC_LIMB_BITS - k;
    }

    if (w == SC_LIMB_BITS) {
        if (bits) {
            for (; n--;) {
                temp   = buf;
                buf    = *in++;
                *out++ = temp + (buf << bits);
                buf  >>= (SC_LIMB_BITS - bits);
            }
        }
        else {
            for (; n--;) {
                *out++ = *in++;
            }
        }
    }
    else if (w == 2 * SC_LIMB_BITS)
    {
        n <<= 1;
      
        if (bits) {
            for (; n--;) {
                temp   = buf;
                buf    = *in++;
                *out++ = temp + (buf << bits);
                buf  >>= (SC_LIMB_BITS - bits);
            }
        }
        else {
            for (; n--;) {
                *out++ = *in++;
            }
        }
    }
    else {
        if (w_gt_2) {
            w -= 2 * SC_LIMB_BITS;
        }
        else if (w_gt_1) {
            w -= SC_LIMB_BITS;
        }
        mask = (SC_LIMB_WORD(1) << w) - 1;

        for (; n--;) {
            // Deal with whole limbs that must be output
            if (w_gt_1) {
                if (bits) {
                    temp   = buf;
                    buf    = *in++;
                    *out++ = temp + (buf << bits);
                    buf  >>= (SC_LIMB_BITS - bits);

                    if (w_gt_2) {
                        temp   = buf;
                        buf    = *in++;
                        *out++ = temp + (buf << bits);
                        buf  >>= (SC_LIMB_BITS - bits);
                    }
                }
                else {
                    *out++ = *in++;
                    if (w_gt_2) {
                        *out++ = *in++;
                    }
                }
            }
       
            // Now deal with the remainder of packed data
            if (w <= bits) {
                *out++ = buf & mask;
                buf  >>= w;
                bits  -= w;
            }
            else {
                temp   = buf;
                buf    = *in++;
                *out++ = temp + ((buf << bits) & mask);
                buf  >>= (w - bits);
                bits   = SC_LIMB_BITS - (w - bits);
            }
        }
    }
}

static void poly_limb_ks2_combine(sc_ulimb_t *res, size_t s, const sc_ulimb_t *a,
    const sc_ulimb_t *b, const size_t w, size_t n, const sc_mod_t *mod)
{
    sc_ulimb_t a0_hi, a0_lo, a1_hi, a1_lo;
    sc_ulimb_t b0_hi, b0_lo, b1_hi, b1_lo;

    // Initialisation of constant parameters
    const sc_ulimb_t mask  = (SC_LIMB_WORD(1) << (w - SC_LIMB_BITS)) - 1;
    const size_t lshift    = w - SC_LIMB_BITS;
    const size_t rshift    = 2 * SC_LIMB_BITS - w;
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    // Obtain data for the first iteration
    a0_lo = *a++;
    a0_hi = *a++;
    
    // The second input will be accessed in descending order
    b    += 2*n + 1;
    b1_hi = *b--;
    b1_lo = *b--;

    // Initialisation of carry
    sc_ulimb_t carry = 0;

    // Iterate over the given number of coefficients
    while (n--) {
        b0_hi = *b--;
        b0_lo = *b--;
        a1_lo = *a++;
        a1_hi = *a++;
        if ((b0_hi < a0_hi) || (b0_hi == a0_hi && b0_lo < a0_lo)) {
            b1_hi -= (b1_lo == 0);
            b1_lo--;
        }

        // Combine and reduce
        const sc_ulimb_t hi = (b1_hi << lshift) + (b1_lo >> rshift);
        const sc_ulimb_t me = (b1_lo << lshift) + a0_hi;
#if 1
        *res = limb_mod_lll(hi, me, a0_lo, m, m_inv, norm);
#else
        *res = limb_mod_reduction_norm(hi, me, m, m_inv, norm);
        *res = limb_mod_reduction_norm(*res, a0_lo, m, m_inv, norm);
#endif
        res += s;

        // Propagate any carried bits
        if (carry) {
            b1_lo++;
            b1_hi += (b1_lo == 0);
        }
        carry = (a1_hi < b1_hi) || (a1_hi == b1_hi && a1_lo < b1_lo);
        limb_sub_hi_lo(&a1_hi, &a1_lo, a1_hi, a1_lo, b1_hi, b1_lo);
        limb_sub_hi_lo(&b1_hi, &b1_lo, b0_hi, b0_lo, a0_hi, a0_lo);
        b1_hi &= mask;

        // Obtain data for the next iteration
        a0_lo = a1_lo;
        a0_hi = a1_hi & mask;
    }
}

static void poly_limb_mul_mod_kronecker_ks4(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    sc_ulimb_t *scratch;
    sc_ulimb_t *aon, *aen, *apn, *amn, *bon, *ben, *bpn, *bmn, *on, *en, *pn, *mn;
    sc_ulimb_t *aor, *aer, *apr, *amr, *bor, *ber, *bpr, *bmr, *or, *er, *pr, *mr;
    sc_ulimb_t *cn, *cr;
    SINT32 sign, neg;

    if (1 == len_b) {
        poly_limb_mul_mod_scalar(out, a, len_a, b[0], mod);
        return;
    }

    // Set a flag to indicate if the squaring is to be performed
    const SINT32 sqr_flag = (len_a == len_b) && (a == b);

    // h1(x) = h1e(x^2) + x * h1o(x^2)
    // h2(x) = h2e(x^2) + x * h2o(x^2)
    // h(x)  =  he(x^2) + x *  ho(x^2)
    const size_t nao = len_a >> 1;
    const size_t nae = len_a - nao;
    const size_t nbo = len_b >> 1;
    const size_t nbe = len_b - nbo;
    const size_t n   = len_a + len_b - 1;
    const size_t no  = n >> 1;
    const size_t ne  = n - no;

    // Bits to be packed for each coefficient
    const size_t bits = 2 * mod->b_norm + sc_ceil_log2(len_b);

    // KS4 evaulates at B, -B, 1/B and -1/B where B = 2^w and w = ceil(bits/4)
    const size_t w = (bits + 3) >> 2;

    // Number of limbs in each B^2 digit
    const size_t num_limbs = (2*w-1)/SC_LIMB_BITS + 1;

    // Length of intermediate products
    const size_t ka = ((len_a + 1) * w)/SC_LIMB_BITS + 1;
    const size_t kb = ((len_b + 1) * w)/SC_LIMB_BITS + 1;
    const size_t k  = ka + kb;

    // Index offsets used to correct for even length polynomials swapping
    // even and odd coefficients when reversed.
    const size_t r1 = (len_a & 1)? 0 : w;
    const size_t r2 = (len_b & 1)? 0 : w;
    const size_t r3 = (n & 1)? 0 : w;

    // Allocate and assign memory
    scratch = (sc_ulimb_t*) SC_MALLOC(sizeof(sc_ulimb_t) * (5 * k + 2*num_limbs*(ne + 1)));
    aen     = scratch;
    aon     = scratch +   k;
    apn     = scratch + 2*k;
    amn     = scratch;
    ben     = scratch       + ka;
    bon     = scratch +   k + ka;
    bpn     = scratch + 2*k + ka;
    bmn     = scratch       + ka;
    pn      = scratch +   k;
    mn      = scratch + 2*k;
    en      = scratch;
    on      = scratch +   k;
    aer     = scratch + 2*k;
    aor     = scratch + 3*k;
    apr     = scratch + 4*k;
    amr     = scratch + 2*k;
    ber     = scratch + 2*k + ka;
    bor     = scratch + 3*k + ka;
    bpr     = scratch + 4*k + ka;
    bmr     = scratch + 2*k + ka;
    pr      = scratch + 3*k;
    mr      = scratch + 4*k;
    er      = scratch + 2*k;
    or      = scratch + 3*k;
    cn      = scratch + 5*k;
    cr      = cn   + num_limbs*(ne + 1);

    // h1e(B^2) and B * h1o(B^2)
    poly_limb_ks2_bit_pack(aen, a,     nae, 2, 0, ka, 2*w);
    poly_limb_ks2_bit_pack(aon, a + 1, nao, 2, w, ka, 2*w);

    // h1(B) = h1e(B^2) + B * h1o(B^2)
    limb_mp_add_n(apn, aen, aon, ka);

    // |h1(-B)| = |h1e(B^2) - B * h1o(B^2)|
    sign = (limb_mp_cmp(aen, aon, ka) >= 0)? 0 : 1;
    if (sign) {
        limb_mp_sub_n(amn, aon, aen, ka);
    }
    else {
        limb_mp_sub_n(amn, aen, aon, ka);
    }

    if (!sqr_flag) {
        // h1e(B^2) and B * h1o(B^2)
        poly_limb_ks2_bit_pack(ben, b,     nbe, 2, 0, kb, 2*w);
        poly_limb_ks2_bit_pack(bon, b + 1, nbo, 2, w, kb, 2*w);

        // h1(B) = h1e(B^2) + B * h1o(B^2)
        limb_mp_add_n(bpn, ben, bon, kb);

        // |h1(-B)| = |h1e(B^2) - B * h1o(B^2)|
        neg = (limb_mp_cmp(ben, bon, kb) >= 0)? 0 : 1;
        if (neg) {
            limb_mp_sub_n(bmn, bon, ben, kb);
        }
        else {
            limb_mp_sub_n(bmn, ben, bon, kb);
        }

        // h(B) = h1(B) * h2(B), |h(-B)| = |h1(-B)| * |h2(-B)|
        limb_mp_mul(pn, apn, ka, bpn, kb);
        limb_mp_mul(mn, amn, ka, bmn, kb);

        sign ^= neg;
    }
    else {
        // h(B) = h1(B)^2, |h(-B)| = |h1(-B)|^2
        limb_mp_mul(pn, apn, ka, apn, ka);
        limb_mp_mul(mn, amn, ka, amn, ka);

        sign = 0;
    }

    //     2 * he(B^2) = h(B) + h(-B)
    // B * 2 * ho(B^2) = h(B) - h(-B)
    if (sign) {
        limb_mp_sub_n(en, pn, mn, k);
        limb_mp_add_n(on, pn, mn, k);
    }
    else {
        limb_mp_add_n(en, pn, mn, k);
        limb_mp_sub_n(on, pn, mn, k);
    }

    // B^(len_a-1) * h1e(1/B^2) and B^(len_a-2) * h1o(1/B^2)
    poly_limb_ks2_bit_pack(aer, a     + 2*(nae - 1), nae, -2, r1,   ka, 2*w);
    poly_limb_ks2_bit_pack(aor, a + 1 + 2*(nao - 1), nao, -2, w-r1, ka, 2*w);

    // B^(len_a-1) * h1(1/B) = B^(len_a-1) * h1e(1/B^2) + B^(len_a-2) * h1o(1/B^2)
    limb_mp_add_n(apr, aer, aor, ka);

    // B^(len_a-1) * |h1(-B)| = B^(len_a-1) * |h1e(B^2) - B^(len_a-2) * h1o(B^2)|
    sign = (limb_mp_cmp(aer, aor, ka) >= 0)? 0 : 1;
    if (sign) {
        limb_mp_sub_n(amr, aor, aer, ka);
    }
    else {
        limb_mp_sub_n(amr, aer, aor, ka);
    }

    if (!sqr_flag) {
        // B^(len_b-1) * h1e(B^2) and B^(len_b-2) * h1o(B^2)
        poly_limb_ks2_bit_pack(ber, b     + 2*(nbe - 1), nbe, -2, r2,   kb, 2*w);
        poly_limb_ks2_bit_pack(bor, b + 1 + 2*(nbo - 1), nbo, -2, w-r2, kb, 2*w);

        // B^(len_b-1) * h1(B) = B^(len_b-1) * h1e(B^2) + B^(len_b-2) * h1o(B^2)
        limb_mp_add_n(bpr, ber, bor, kb);

        // B^(len_b-1) * |h1(-B)| = |B^(len_b-1) * h1e(B^2)|
        //                        - |B^(len_b-2) * h1o(B^2)|
        neg = (limb_mp_cmp(ber, bor, kb) >= 0)? 0 : 1;
        if (neg) {
            limb_mp_sub_n(bmr, bor, ber, kb);
        }
        else {
            limb_mp_sub_n(bmr, ber, bor, kb);
        }

        // B^(n-1) * h(B) = B^(len_a-1) * h1(B) * B^(len_b-1) * h2(B)
        // B^(n-1) * |h(-B)| = |B^(len_a-1) * h1(-B)| * |B^(len_b-1) * h2(-B)|
        limb_mp_mul(pr, apr, ka, bpr, kb);
        limb_mp_mul(mr, amr, ka, bmr, kb);

        sign ^= neg;
    }
    else {
        // B^(n-1) * h(B) = (B^(len_a-1) * h1(B))^2
        // B^(n-1) * |h(-B)| = |B^(len_a-1) * h1(-B)|^2
        limb_mp_mul(pr, apr, ka, apr, ka);
        limb_mp_mul(mr, amr, ka, amr, ka);

        sign = 0;
    }

    //     2 * he(B^2) = h(B) + h(-B)
    // B * 2 * ho(B^2) = h(B) - h(-B)
    if (sign) {
        limb_mp_sub_n(er, pr, mr, k);
        limb_mp_add_n(or, pr, mr, k);
    }
    else {
        limb_mp_add_n(er, pr, mr, k);
        limb_mp_sub_n(or, pr, mr, k);
    }

    // Unpack he(B^2) and B^(2*(ne-1)) * he(1/B^2) into base-B^2 digits
    // and combine to form the even coefficients
    poly_limb_ks2_bit_unpack(cn, en, ne + 1, 2*w, 1);
    poly_limb_ks2_bit_unpack(cr, er, ne + 1, 2*w, r3 + 1);
    poly_limb_ks2_combine(out,     2, cn, cr, 2*w, ne, mod);

    // Unpack ho(B^2) and B^(2*(no-1)) * ho(1/B^2) into base-B^2 digits
    // and combine to form the odd coefficients
    poly_limb_ks2_bit_unpack(cn, on, no + 1, 2*w, w + 1);
    poly_limb_ks2_bit_unpack(cr, or, no + 1, 2*w, w - r3 + 1);
    poly_limb_ks2_combine(out + 1, 2, cn, cr, 2*w, no, mod);

    // Free memory resources
    SC_FREE(scratch, sizeof(sc_ulimb_t) * (5*k + 2*num_limbs*(ne + 1)));
}

static void poly_limb_mul_mod_kronecker_trunc(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, size_t n, const sc_mod_t *mod)
{
    const size_t bits1   = poly_limb_max_bits(a, len_a);
    const size_t bits2   = (a == b)? bits1 : poly_limb_max_bits(b, len_b);
    const size_t log_len = SC_LIMB_BITS - limb_clz(len_b);
    const size_t bits    = bits1 + bits2 + log_len;

    // Determine the total number of limbs in each input (rounded up)
    const size_t limbs1  = ((len_a * bits - 1)/SC_LIMB_BITS) + 1;
    const size_t limbs2  = ((len_b * bits - 1)/SC_LIMB_BITS) + 1;

    // Calculate the depth of memory needed to store the packed variables
    const size_t depth   = (a == b)? (2*limbs1 + limbs2) : (2 * (limbs1 + limbs2));

    // Allocate and assign memory
    sc_ulimb_t *mpn1, *mpn2, *res;
    res  = (sc_ulimb_t*) SC_MALLOC(sizeof(sc_ulimb_t) * depth);
    mpn1 = res + limbs1 + limbs2;
    mpn2 = (a == b)? mpn1 : mpn1 + limbs1;

    // Pack the polynomial coefficients into a multiple-precision variable
    poly_limb_ks_bit_pack(mpn1, a, len_a, bits);
    if (a != b) {
        poly_limb_ks_bit_pack(mpn2, b, len_b, bits);
    }

    // Use the GMP multiple-precision multiply
    limb_mp_mul(res, mpn1, limbs1, mpn2, limbs2);

    // Unpack back into polynomial coefficients
    poly_limb_ks_bit_unpack(out, n, res, bits, mod);

    // Free memory resources     
    SC_FREE(res, sizeof(sc_ulimb_t) * depth);
}

static void poly_limb_mul_mod_karatsuba(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    // a * b => a1b1 * B**2n + ((a1 + a0)(b1 + b0) - (a0b0 + a1b1)) * B + a0b0

    const size_t B     = len_b >> 1;
    const size_t depth = 8*len_a - B;
    sc_ulimb_t *a0b0, *a1b1, *t0, *t1;

    if (B <= POLY_LIMB_MUL_KARATSUBA_THRESH) {
        poly_limb_mul_mod_gradeschool(out, a, len_a, b, len_b, mod);
        //out[len_a+len_b-1] = 0;
        return;
    }

    a0b0 = SC_MALLOC(sizeof(sc_ulimb_t) * depth);
    a1b1 = a0b0 + 2*len_a - B;
    t0   = a1b1 + 2*len_a - B;
    t1   = t0   + 2*len_a - B;

    // z0 = a0 * b0
    poly_limb_mul_mod_karatsuba(a0b0, a, B, b, B, mod);

    // z1 = (a0 + a1)(b0 + b1)
    poly_limb_add_mod(a1b1, a + B, len_a - B, a, B, mod);
    poly_limb_add_mod(t1, b + B, len_b - B, b, B, mod);
    poly_limb_mul_mod_karatsuba(t0, a1b1, len_a - B, t1, len_b - B, mod);

    // z2 = a1 * b1
    poly_limb_mul_mod_karatsuba(a1b1, a + B, len_a - B, b + B, len_b - B, mod);

    // t1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1
    poly_limb_add_mod(t1, a0b0, 2*B, a1b1, len_a+len_b-2*B, mod);
    poly_limb_sub_mod(t1, t0, len_a+len_b-2*B, t1, len_a+len_b-2*B, mod);

    poly_limb_copy(out, B, a0b0);

    // t1 = x0y0 + t1
    poly_limb_add_mod(out + B, t1, B, a0b0 + B, B, mod);

    // out = a0*b0 + t1 + x1y1
    poly_limb_add_mod(out + 2*B, t1 + B, len_a+len_b-3*B, a1b1, len_a+len_b-2*B - 1, mod);

    SC_FREE(a0b0, sizeof(sc_ulimb_t) * depth);
}

void poly_limb_mul_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod)
{
    if (len_a < len_b) {
        poly_limb_mul_mod(out, b, len_b, a, len_a, mod);
        return;
    }
    else {
        const sc_ulimb_t bits    = mod->b_norm;

        if ((len_b <= POLY_LIMB_MUL_GRADESCHOOL_THRESH) ||
                 (len_b <= POLY_LIMB_MUL_GRADESCHOOL_SMALL_B_THRESH)) {
            poly_limb_mul_mod_gradeschool(out, a, len_a, b, len_b, mod);
        }
        else if (len_b <= POLY_LIMB_MUL_KARATSUBA_THRESH) {
            poly_limb_mul_mod_karatsuba(out, a, len_a, b, len_b, mod);
        }
        else if (bits * len_b <= POLY_LIMB_MUL_KS4_THRESH*SC_LIMB_BITS) {
            poly_limb_mul_mod_kronecker_ks4(out, a, len_a, b, len_b, mod);
        }
        else {
            poly_limb_mul_mod_kronecker(out, a, len_a, b, len_b, mod);
        }
    }
}

void poly_limb_mul_mod_trunc(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, size_t n, const sc_mod_t *mod)
{
    const size_t min_len_a = SC_MIN(len_a, n);
    const size_t min_len_b = SC_MIN(len_b, n);

    if ((min_len_a + min_len_b <= POLY_LIMB_MUL_GRADESCHOOL_THRESH) ||
        (n <= POLY_LIMB_MUL_GRADESCHOOL_THRESH)) {
        poly_limb_mul_mod_gradeschool_trunc(out, a, min_len_a, b, min_len_b, n, mod);
    }
    else {
        poly_limb_mul_mod_kronecker_trunc(out, a, min_len_a, b, min_len_b, n, mod);
    }
}

void poly_limb_addmul_mod_scalar(sc_ulimb_t *inout, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b, const sc_mod_t *mod)
{
    if (0 == b) {
        return;
    }

    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    size_t i;
    for (i=len_a; i--;) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, a[i], b);
        limb_add_hi_lo(&hi, &lo, SC_LIMB_WORD(0), inout[i], hi, lo);
        inout[i] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
    }
}

void poly_limb_submul_mod_scalar(sc_ulimb_t *inout, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b, const sc_mod_t *mod)
{
    size_t i;
    if (0 == b) {
        return;
    }

    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    for (i=len_a; i--;) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, a[i], b);
        if (hi || (!hi && lo > inout[i])) {
            limb_sub_hi_lo(&hi, &lo, hi, lo, SC_LIMB_WORD(0), inout[i]);
        }
        else {
            limb_sub_hi_lo(&hi, &lo, SC_LIMB_WORD(0), inout[i], hi, lo);
        }
        inout[i] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
    }
}

void poly_limb_mul_mod_scalar(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n,
    sc_ulimb_t scalar, const sc_mod_t *mod)
{
#if 1
    poly_limb_mul_mod(out, in, n, &scalar, 1, mod);
#else
    size_t i;
    if (0 == scalar) {
        for (i=n; i--;) {
            out[i] = 0;
        }
        return;
    }

    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    if (mod->norm >= (SC_LIMB_BITS/2)) {
        limb_mp_mul_1(out, in, n, scalar);
        for (i=n; i--;) {
            out[i] = limb_mod_l(out[i], m, m_inv, norm);
        }
    }
    else {
        for (i=n; i--;) {
            sc_ulimb_t hi, lo;
            limb_mul_hi_lo(&hi, &lo, in[i], scalar);
            out[i] = limb_mod_reduction_norm(hi, lo, m, m_inv, norm);
        }
    }
#endif
}

static sc_ulimb_t poly_limb_resultant_euclidean(const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    sc_ulimb_t *scratch, const sc_mod_t *mod)
{
    const sc_ulimb_t m     = mod->m;
    const sc_ulimb_t m_inv = mod->m_inv;
    const sc_ulimb_t norm  = mod->norm;

    if (a == b) {
        return 0;
    }
    else if (1 == len_b) {
        if (1 == len_a) {
            return 1;
        }
        else if (2 == len_a) {
            return b[0];
        }
        else {
            return limb_powmod2(b[0], len_a - 1, m, m_inv, norm);
        }
    }
    else {
        // len_a >= len_b >= 2

        if (NULL == scratch) {
            return 0;
        }

        sc_ulimb_t res = 1;
 
        sc_ulimb_t *u, *v, *r;
        sc_ulimb_t l1, l2;
 
        u = scratch;
        v = u + len_a;
        r = v + len_a;
 
        poly_limb_copy(u, len_a, a);
        poly_limb_copy(v, len_b, b);
        l1 = len_a;
        l2 = len_b;

        while (1) {
            sc_ulimb_t *t;
            size_t lc, lr, l0;

            l0 = l1;
            l1 = l2;
            lc = v[l1 - 1];

            // Compute r = u % v, reducing the length l2 accordingly
            poly_limb_rem_mod(r, &lr, u, l0, v, l1, mod);
            l2 = poly_limb_degree(r, lr) + 1;

            // Swap u, v and r circularly
            t = u;
            u = v;
            v = r;
            r = t;

            // If there is a remainder calculate the new leading coefficient and resultant
            if (l2 > 0) {
                lc  = limb_powmod2(lc, l0 - l2, m, m_inv, norm);
                res = limb_mul_mod_norm(res, lc, m, m_inv, norm);

                // If l0 and l1 are odd negate the resultant
                if (l0 & l1 & 1) {
                    res = limb_negate_mod(res, m);
                }  
            }
            else {
                // If the remainder has disappeared update the leading coefficient using l0 only
                if (1 == l1) {
                    lc  = limb_powmod2(lc, l0 - 1, m, m_inv, norm);
                    res = limb_mul_mod_norm(res, lc, m, m_inv, norm);
                }
                else {
                    res = 0;
                }

                break;
            }
        };

        return res;
    }
}

static void halfgcd_rem_mod(sc_ulimb_t *r, size_t *len_r, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *modulus)
{
    if (len_a >= len_b) {
        poly_limb_rem_mod(r, len_r, a, len_a, b, len_b, modulus);
        *len_r = poly_limb_degree(r, *len_r) + 1;
    }
    else {
        poly_limb_copy(r, len_a, a);
        *len_r = len_a;
    }
}

// Initialise the Half-GCD matrix
static void halfgcd_mat_one(sc_ulimb_t **m, size_t *len_m)
{
    m[0][0] = m[3][0] = SC_LIMB_WORD(1);
    len_m[0] = len_m[3] = 1;
    len_m[1] = len_m[2] = 0;
}

// Change the b pointer to a shifted by an offset.
static void set_shifted_ptr(sc_ulimb_t **b, size_t *len_b,
    const sc_ulimb_t *a, size_t len_a, const size_t m)
{
    *b     = (sc_ulimb_t*) a + m;
    *len_b = (len_a >= m)? len_a - m : 0;
}

// Change the b pointer to a truncated version of a.
static void set_truncate_ptr(sc_ulimb_t **b, size_t *len_b,
    const sc_ulimb_t *a, size_t len_a, const size_t m)
{
    *b     = (sc_ulimb_t*) a;
    *len_b = SC_MIN(len_a, m);
}

// A helper function for poly_limb_mat_mul_classical() that
// multiply-accumulates two polynomials modulo a limb-sized modulus.
static SC_FORCE_INLINE void poly_limb_mat_mul_step(sc_ulimb_t *c, size_t *len_c,
    sc_ulimb_t *t, const sc_mod_t *modulus,
    const sc_ulimb_t *a0, size_t len_a0, const sc_ulimb_t *a1, size_t len_a1,
    const sc_ulimb_t *b0, size_t len_b0, const sc_ulimb_t *b1, size_t len_b1)
{
    size_t len_t;

    poly_limb_mul_mod(c, a0, len_a0, b0, len_b0, modulus);
    *len_c = (0 == len_a0 || 0 == len_b0)? 0 : len_a0 + len_b0 - 1;
    poly_limb_mul_mod(t, a1, len_a1, b1, len_b1, modulus);
    len_t  = (0 == len_a1 || 0 == len_b1)? 0 : len_a1 + len_b1 - 1;
    poly_limb_add_mod(c, c, *len_c, t, len_t, modulus);
    *len_c = SC_MAX(*len_c, len_t);
}

// Classical multiplication of 2x2 matrices using 8 polynomial
// modular multiplications and 4 polynomial modular additions.
// [A11 A12]   [B11 B12]   [C11 C12]
// [A21 A22] * [B21 B22] = [C21 C22]
// i.e. C11 = A11 * B11 + A12 * B21
static void poly_limb_mat_mul_classical(sc_ulimb_t **c, size_t *len_c,
    const sc_ulimb_t **a, const size_t *len_a,
    const sc_ulimb_t **b, const size_t *len_b,
    sc_ulimb_t *t, const sc_mod_t *modulus)
{
    poly_limb_mat_mul_step(c[0], &len_c[0], t, modulus,
        a[0], len_a[0], a[1], len_a[1],
        b[0], len_b[0], b[2], len_b[2]);
    poly_limb_mat_mul_step(c[1], &len_c[1], t, modulus,
        a[0], len_a[0], a[1], len_a[1],
        b[1], len_b[1], b[3], len_b[3]);
    poly_limb_mat_mul_step(c[2], &len_c[2], t, modulus,
        a[2], len_a[2], a[3], len_a[3],
        b[0], len_b[0], b[2], len_b[2]);
    poly_limb_mat_mul_step(c[3], &len_c[3], t, modulus,
        a[2], len_a[2], a[3], len_a[3],
        b[1], len_b[1], b[3], len_b[3]);
}

// Uses "Implementation of Strassen’s Algorithm for Matrix Multiplication”
// to trade multiplications for additions. This uses Winograd's variant of
// Strassen's algorithm to reduce add/sub's from 18 to 15.
static void poly_limb_mat_mul_strassen(sc_ulimb_t **c, size_t *len_c,
    const sc_ulimb_t **a, const size_t *len_a,
    const sc_ulimb_t **b, const size_t *len_b,
    sc_ulimb_t *t0, sc_ulimb_t *t1, const sc_mod_t *modulus)
{
    size_t len_t0, len_t1;

    poly_limb_sub_mod(t0, a[0], len_a[0], a[2], len_a[2], modulus);
    len_t0 = SC_MAX(len_a[0], len_a[2]);
    poly_limb_sub_mod(t1, b[3], len_b[3], b[1], len_b[1], modulus);
    len_t1 = SC_MAX(len_b[3], len_b[1]);
    poly_limb_mul_mod(c[2], t0, len_t0, t1, len_t1, modulus);
    len_c[2] = (0 == len_t0 || 0 == len_t1)? 0 : len_t0 + len_t1 - 1;

    poly_limb_add_mod(t0, a[2], len_a[2], a[3], len_a[3], modulus);
    len_t0 = SC_MAX(len_a[2], len_a[3]);
    poly_limb_sub_mod(t1, b[1], len_b[1], b[0], len_b[0], modulus);
    len_t1 = SC_MAX(len_b[1], len_b[0]);
    poly_limb_mul_mod(c[3], t0, len_t0, t1, len_t1, modulus);
    len_c[3] = (0 == len_t0 || 0 == len_t1)? 0 : len_t0 + len_t1 - 1;

    poly_limb_sub_mod(t0, t0, len_t0, a[0], len_a[0], modulus);
    len_t0 = SC_MAX(len_t0, len_a[0]);
    poly_limb_sub_mod(t1, b[3], len_b[3], t1, len_t1, modulus);
    len_t1 = SC_MAX(len_b[3], len_t1);
    poly_limb_mul_mod(c[1], t0, len_t0, t1, len_t1, modulus);
    len_c[1] = (0 == len_t0 || 0 == len_t1)? 0 : len_t0 + len_t1 - 1;

    poly_limb_sub_mod(t0, a[1], len_a[1], t0, len_t0, modulus);
    len_t0 = SC_MAX(len_a[1], len_t0);
    poly_limb_mul_mod(c[0], t0, len_t0, b[3], len_b[3], modulus);
    len_c[0] = (0 == len_t0 || 0 == len_b[3])? 0 : len_t0 + len_b[3] - 1;

    poly_limb_mul_mod(t0, a[0], len_a[0], b[0], len_b[0], modulus);
    len_t0 = (0 == len_a[0] || 0 == len_b[0])? 0 : len_a[0] + len_b[0] - 1;

    poly_limb_add_mod(c[1], t0, len_t0, c[1], len_c[1], modulus);
    len_c[1] = SC_MAX(len_t0, len_c[1]);
    poly_limb_add_mod(c[2], c[1], len_c[1], c[2], len_c[2], modulus);
    len_c[2] = SC_MAX(len_c[1], len_c[2]);
    poly_limb_add_mod(c[1], c[1], len_c[1], c[3], len_c[3], modulus);
    len_c[1] = SC_MAX(len_c[1], len_c[3]);
    poly_limb_add_mod(c[3], c[2], len_c[2], c[3], len_c[3], modulus);
    len_c[3] = SC_MAX(len_c[2], len_c[3]);
    poly_limb_add_mod(c[1], c[1], len_c[1], c[0], len_c[0], modulus);
    len_c[1] = SC_MAX(len_c[1], len_c[0]);
    poly_limb_sub_mod(t1, t1, len_t1, b[2], len_b[2], modulus);
    len_t1 = SC_MAX(len_t1, len_b[2]);
    poly_limb_mul_mod(c[0], a[3], len_a[3], t1, len_t1, modulus);
    len_c[0] = (0 == len_a[3] || 0 == len_t1)? 0 : len_a[3] + len_t1 - 1;

    poly_limb_sub_mod(c[2], c[2], len_c[2], c[0], len_c[0], modulus);
    len_c[2] = SC_MAX(len_c[2], len_c[0]);
    poly_limb_mul_mod(c[0], a[1], len_a[1], b[2], len_b[2], modulus);
    len_c[0] = (0 == len_a[1] || 0 == len_b[2])? 0 : len_a[1] + len_b[2] - 1;

    poly_limb_add_mod(c[0], c[0], len_c[0], t0, len_t0, modulus);
    len_c[0] = (len_c[0] > len_t0)? len_c[0] : len_t0;
}

// Multiplication of two 2x2 matrices
static void poly_limb_mat_mul(sc_ulimb_t **c, size_t *len_c,
    const sc_ulimb_t **a, const size_t *len_a,
    const sc_ulimb_t **b, const size_t *len_b,
    sc_ulimb_t *t0, sc_ulimb_t *t1, const sc_mod_t *modulus)
{
    // Find the minimum value of the input polynomials
    const size_t min = SC_MIN(len_a[0],
                       SC_MIN(len_a[1],
                       SC_MIN(len_a[2],
                       SC_MIN(len_a[3],
                       SC_MIN(len_b[0],
                       SC_MIN(len_b[1],
                       SC_MIN(len_b[2],
                              len_b[3])))))));

    // Use Strassen multiplication if the minimum value of any of the input
    // polynomials is less than a predefined threshold
    if (min < POLY_2X2_MATRIX_STRASSEN_THRESH) {
        poly_limb_mat_mul_classical(c, len_c, a, len_a, b, len_b, t0, modulus);
    }
    else {
        poly_limb_mat_mul_strassen(c, len_c, a, len_a, b, len_b, t0, t1, modulus);
    }
}

// GCD function for Half-GCD algorithm to deal with polynomials
// as they get to smaller sizes
static SINT32 poly_limb_mod_halfgcd_recursive_iter(sc_ulimb_t **m, size_t *len_m,
    sc_ulimb_t **aa, size_t *len_aa, sc_ulimb_t **bb, size_t *len_bb,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    sc_ulimb_t *q, sc_ulimb_t **tt, sc_ulimb_t **t, const sc_mod_t *modulus,
    sc_halfgcd_resultant_t *res)
{
    const size_t hlen = len_a >> 1;
    SINT32 sgn = 1;

    // Set the Half-GCD matrix to its initial state
    halfgcd_mat_one(m, len_m);

    // Use copies of a and b so as not to destroy them
    poly_limb_copy(*aa, len_a, a);
    poly_limb_copy(*bb, len_b, b);
    *len_aa = len_a;
    *len_bb = len_b;

    // Iterate over aa and bb until len_bb is greater than hlen
    while (*len_bb > hlen) {
        size_t len_q, len_tt, len_t;

        if (res) {
           res->lc = (*bb)[*len_bb - 1];
        }

        // q = quo(aa/bb), tt = rem(aa/bb)
        poly_limb_divrem_mod(q, &len_q, *tt, &len_tt, *aa, *len_aa, *bb, *len_bb, modulus);

        if (res) {
            if (len_tt >= hlen + 1) {
                if (len_tt >= 1) {
                    res->lc  = limb_powmod2(res->lc, *len_aa - len_tt, modulus->m, modulus->m_inv, modulus->norm);
                    res->res = limb_mul_mod_norm(res->res, res->lc,
                        modulus->m, modulus->m_inv, modulus->norm);
              
                    if ((((*len_aa + res->off) | (*len_bb + res->off)) & 1) == 0) {
                        res->res = limb_negate_mod(res->res, modulus->m);
                    }
                }
                else {
                    if (*len_bb == 1) {
                        res->lc  = limb_powmod2(res->lc, *len_aa - 1, modulus->m, modulus->m_inv, modulus->norm);
                        res->res = limb_mul_mod_norm(res->res, res->lc,
                            modulus->m, modulus->m_inv, modulus->norm);
                    }
                    else {
                        res->res = 0;
                    }
                }
            }
            else {
                res->l0 = *len_aa;
                res->l1 = *len_bb;
            }
        }

        // Set aa == bb, bb == tt
        poly_limb_swap_pointers(bb, len_bb, tt, &len_tt);
        poly_limb_swap_pointers(aa, len_aa, tt, &len_tt);

        // t = m[3] + q * m[2], set m[3] = m[2], m[2] = t
        poly_limb_mul_mod(*tt, q, len_q, m[2], len_m[2], modulus);
        len_tt = poly_limb_degree(*tt, len_q + len_m[2] - 1) + 1;
        poly_limb_add_mod(*t, m[3], len_m[3], *tt, len_tt, modulus);
        len_t  = poly_limb_degree(*t, SC_MAX(len_m[3], len_tt)) + 1;
        poly_limb_swap_pointers(&m[3], &len_m[3], &m[2], &len_m[2]);
        poly_limb_swap_pointers(&m[2], &len_m[2], t, &len_t);

        // t = m[1] + q * m[0], set m[1] = m[0], m[0] = t
        poly_limb_mul_mod(*tt, q, len_q, m[0], len_m[0], modulus);
        len_tt = poly_limb_degree(*tt, len_q + len_m[0] - 1) + 1;
        poly_limb_add_mod(*t, m[1], len_m[1], *tt, len_tt, modulus);
        len_t  = poly_limb_degree(*t, SC_MAX(len_m[1], len_tt)) + 1;
        poly_limb_swap_pointers(&m[1], &len_m[1], &m[0], &len_m[0]);
        poly_limb_swap_pointers(&m[0], &len_m[0], t, &len_t);

        sgn = -sgn;
    }

    return sgn;
}

// A helper function for poly_limb_mod_halfgcd_recursive() for
// readability purposes
static inline void poly_limb_mod_halfgcd_recursive_step(
    const sc_ulimb_t *x, size_t len_x,
    const sc_ulimb_t *y, size_t len_y,
    sc_ulimb_t *t, size_t *len_t,
    sc_ulimb_t *a, size_t *len_a,
    sc_ulimb_t *b, size_t len_b,
    sc_ulimb_t *c, size_t *len_c,
    sc_ulimb_t **m, size_t *len_m,
    size_t m_0, size_t m_1, SINT32 sign_m, const size_t a_2,
    const const sc_mod_t *modulus, SINT32 sub_flag)
{
    poly_limb_mul_mod(a, m[m_0], len_m[m_0], x, len_x, modulus);
    poly_limb_mul_mod(t, m[m_1], len_m[m_1], y, len_y, modulus);
    *len_a = len_m[m_0] + len_x - 1;
    *len_t = len_m[m_1] + len_y - 1;

    if ((sub_flag && sign_m < 0) || (!sub_flag && sign_m >= 0)) {
        poly_limb_sub_mod(a, t, *len_t, a, *len_a, modulus);
    }
    else {
        poly_limb_sub_mod(a, a, *len_a, t, *len_t, modulus);
    }
    *len_a = SC_MAX(*len_a, *len_t);
    *len_a = poly_limb_degree(a, *len_a) + 1;
    poly_limb_reset(a + *len_a, a_2 + len_b - *len_a);

    set_shifted_ptr(&c, len_c, a, *len_a, a_2);
    poly_limb_add_mod(c, c, *len_c, b, len_b, modulus);
    *len_a = SC_MAX(*len_a, (a_2 + len_b));
    *len_a = poly_limb_degree(a, *len_a) + 1;
}

// A recursive function used to generate the Half-GCD matrices.
static SINT32 poly_limb_mod_halfgcd_recursive(sc_ulimb_t **m, size_t *len_m,
    sc_ulimb_t *aa, size_t *len_aa, sc_ulimb_t *bb, size_t *len_bb,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus, sc_ulimb_t *w, SINT32 flag,
    sc_halfgcd_resultant_t *res)
{
    const size_t hlen = len_a >> 1;
    if ((hlen + 1) > len_b) {
        if (flag) {
            halfgcd_mat_one(m, len_m);
        }
        poly_limb_copy(aa, len_a, a);
        poly_limb_copy(bb, len_b, b);
        *len_aa = len_a;
        *len_bb = len_b;

        return SC_LIMB_WORD(1);
    }

    size_t len_a0, len_b0, len_a4, len_b4, len_x, len_y, len_c0, len_d0;
    sc_ulimb_t *a0, *b0, *a4, *b4, *x, *y, *c0, *d0;

    size_t len_a2, len_b2, len_a3, len_b3, len_q, len_d, len_t0;
    sc_ulimb_t *a2, *b2, *a3, *b3, *q, *d, *t0, *t1;

    sc_ulimb_t *mat_r[4], *mat_s[4];
    size_t len_mat_r[4], len_mat_s[4];
    SINT32 sgn_mat_r, sgn_mat_s;

    // Memory assignment from the input scratch memory w
    a2   = w;
    b2   = a2   + len_a;
    a3   = b2   + len_a;
    b3   = a3   + len_a;
    q    = b3   + len_a;
    d    = q    + ((len_a + 1)>>1);
    t0   = d    + len_a;
    t1   = t0   + len_a;
    mat_r[0] = t1   + ((len_a + 1) >> 1);
    mat_r[1] = mat_r[0] + ((len_a + 1) >> 1);
    mat_r[2] = mat_r[1] + ((len_a + 1) >> 1);
    mat_r[3] = mat_r[2] + ((len_a + 1) >> 1);
    mat_s[0] = mat_r[3] + ((len_a + 1) >> 1);
    mat_s[1] = mat_s[0] + ((len_a + 1) >> 1);
    mat_s[2] = mat_s[1] + ((len_a + 1) >> 1);
    mat_s[3] = mat_s[2] + ((len_a + 1) >> 1);

    w += 6 * len_a + 10 * ((len_a + 1) >> 1);

    set_shifted_ptr(&a0, &len_a0, a, len_a, hlen);
    set_shifted_ptr(&b0, &len_b0, b, len_b, hlen);

    if (res) {
        res->lc   = b[len_b - 1];
        res->l0  -= hlen;
        res->l1  -= hlen;
        res->off += hlen;
    }

    if (len_a0 < POLY_LIMB_HALFGCD_THRESHOLD) {
        sgn_mat_r = poly_limb_mod_halfgcd_recursive_iter(mat_r, len_mat_r, &a3, &len_a3, &b3, &len_b3,
            a0, len_a0, b0, len_b0, q, &t0, &t1, modulus, res);
    }
    else  {
        sgn_mat_r = poly_limb_mod_halfgcd_recursive(mat_r, len_mat_r, a3, &len_a3, b3, &len_b3,
            a0, len_a0, b0, len_b0, modulus, w, 1, res);
    }

    if (res) {
        res->off -= hlen;
        res->l0  += hlen;
        res->l1  += hlen;
    }

    set_truncate_ptr(&x, &len_x, a, len_a, hlen);
    set_truncate_ptr(&y, &len_y, b, len_b, hlen);

    poly_limb_mod_halfgcd_recursive_step(x, len_x, y, len_y,
        t0, &len_t0, b2, &len_b2, b3, len_b3, b4, &len_b4,
        mat_r, len_mat_r, 2, 0, sgn_mat_r, hlen, modulus, 0);
    poly_limb_mod_halfgcd_recursive_step(x, len_x, y, len_y,
        t0, &len_t0, a2, &len_a2, a3, len_a3, a4, &len_a4,
        mat_r, len_mat_r, 3, 1, sgn_mat_r, hlen, modulus, 1);

    if (len_b2 < (hlen + 1)) {
        poly_limb_copy(aa, len_a2, a2);
        poly_limb_copy(bb, len_b2, b2);
        *len_aa = len_a2;
        *len_bb = len_b2;
 
        if (flag) {
            poly_limb_copy(m[0], len_mat_r[0], mat_r[0]);
            poly_limb_copy(m[1], len_mat_r[1], mat_r[1]);
            poly_limb_copy(m[2], len_mat_r[2], mat_r[2]);
            poly_limb_copy(m[3], len_mat_r[3], mat_r[3]);
            len_m[0] = len_mat_r[0];
            len_m[1] = len_mat_r[1];
            len_m[2] = len_mat_r[2];
            len_m[3] = len_mat_r[3];
        }
 
        return sgn_mat_r;
    }
    else {
        size_t k = 2 * hlen - len_b2 + 1;

        if (res) {
            if (len_b2 < len_b) {
                if (len_b2 >= 1) {
                    res->lc  = limb_powmod2(res->lc, res->l0 - len_b2, modulus->m, modulus->m_inv, modulus->norm);
                    res->res = limb_mul_mod_norm(res->res, res->lc,
                        modulus->m, modulus->m_inv, modulus->norm);

                    if ((((res->l0 + res->off) | (res->l1 + res->off)) & 1) == 0) {
                        res->res = limb_negate_mod(res->res, modulus->m);
                    }
                }
                else {
                    if (res->l1 == 1) {
                        res->lc  = limb_powmod2(res->lc, res->l0 - 1, modulus->m, modulus->m_inv, modulus->norm);
                        res->res = limb_mul_mod_norm(res->res, res->lc,
                            modulus->m, modulus->m_inv, modulus->norm);
                    }
                    else {
                        res->res = 0;
                    }
                }
            }

            res->lc = b2[len_b2 - 1];
            
            res->l0 = len_a2;
            res->l1 = len_b2;
        }

        poly_limb_divrem_mod(q, &len_q, d, &len_d, a2, len_a2, b2, len_b2, modulus);
        set_shifted_ptr(&c0, &len_c0, b2, len_b2, k);
        set_shifted_ptr(&d0, &len_d0, d, len_d, k);

        if (res) {
            if (len_d >= hlen + 1) {
                if (len_d >= 1) {
                    res->lc  = limb_powmod2(res->lc, len_a2 - len_d, modulus->m, modulus->m_inv, modulus->norm);
                    res->res = limb_mul_mod_norm(res->res, res->lc,
                        modulus->m, modulus->m_inv, modulus->norm);

                    if ((((len_a2 + res->off) | (len_b2 + res->off)) & 1) == 0) {
                        res->res = limb_negate_mod(res->res, modulus->m);
                    }
                }
                else {
                    if (len_b2 == 1) {
                        res->lc  = limb_powmod2(res->lc, len_a2 - 1, modulus->m, modulus->m_inv, modulus->norm);
                        res->res = limb_mul_mod_norm(res->res, res->lc,
                            modulus->m, modulus->m_inv, modulus->norm);
                    }
                    else {
                        res->res = 0;
                    }
                }
                  
                res->l0 = len_b2;
                res->l1 = len_d;
            }

            res->off += k;
            res->l0  -= k;
            res->l1  -= k;
        }

        if (len_c0 < POLY_LIMB_HALFGCD_THRESHOLD) {
            sgn_mat_s = poly_limb_mod_halfgcd_recursive_iter(mat_s, len_mat_s, &a3, &len_a3, &b3, &len_b3,
                c0, len_c0, d0, len_d0, a2, &t0, &t1, modulus, res);
        }
        else  {
            sgn_mat_s = poly_limb_mod_halfgcd_recursive(mat_s, len_mat_s, a3, &len_a3, b3, &len_b3,
                c0, len_c0, d0, len_d0, modulus, w, 1, res);
        }

        if (res) {
            res->off -= k;
            res->l0  += k;
            res->l1  += k;
        }

        set_truncate_ptr(&x, &len_x, b2, len_b2, k);
        set_truncate_ptr(&y, &len_y, d, len_d, k);

        poly_limb_mod_halfgcd_recursive_step(x, len_x, y, len_y,
            t0, &len_t0, bb, len_bb, b3, len_b3, b4, &len_b4,
            mat_s, len_mat_s, 2, 0, sgn_mat_s, k, modulus, 0);
        poly_limb_mod_halfgcd_recursive_step(x, len_x, y, len_y,
            t0, &len_t0, aa, len_aa, a3, len_a3, a4, &len_a4,
            mat_s, len_mat_s, 3, 1, sgn_mat_s, k, modulus, 1);

        if (flag) {
            poly_limb_swap_pointers(&mat_s[0], &len_mat_s[0], &mat_s[2], &len_mat_s[2]);
            poly_limb_swap_pointers(&mat_s[1], &len_mat_s[1], &mat_s[3], &len_mat_s[3]);

            poly_limb_mul_mod(t0, mat_s[2], len_mat_s[2], q, len_q, modulus);
            len_t0 = len_q + len_mat_s[2] - 1;
            poly_limb_add_mod(mat_s[0], mat_s[0], len_mat_s[0], t0, len_t0, modulus);
            len_mat_s[0] = (len_mat_s[0] > len_t0)? len_mat_s[0] : len_t0;
            poly_limb_mul_mod(t0, mat_s[3], len_mat_s[3], q, len_q, modulus);
            len_t0 = len_q + len_mat_s[3] - 1;
            poly_limb_add_mod(mat_s[1], mat_s[1], len_mat_s[1], t0, len_t0, modulus);
            len_mat_s[1] = (len_mat_s[1] > len_t0)? len_mat_s[1] : len_t0;

            poly_limb_mat_mul(m, len_m, (const sc_ulimb_t **)mat_r, len_mat_r,
                (const sc_ulimb_t **)mat_s, len_mat_s, a2, b2, modulus);
        }

        return -(sgn_mat_r * sgn_mat_s);
    }
}

static size_t poly_limb_resultant_halfgcd_2(sc_ulimb_t **mm, size_t **len_mm, 
    sc_ulimb_t *a, size_t *len_a, sc_ulimb_t *b, size_t *len_b, 
    const sc_ulimb_t *x, size_t len_x, const sc_ulimb_t *y, size_t len_y, 
    sc_ulimb_t *r, const sc_mod_t *modulus)
{
    const size_t depth = 22 * len_x + 16 * (sc_ceil_log2(len_x) + 1);
    size_t sgn_m;
    sc_halfgcd_resultant_t res;
    sc_ulimb_t *scratch;

    res.res = *r;
    res.lc  = y[len_y - 1];
    res.l0  = len_x;
    res.l1  = len_y;
    res.off = 0;

    scratch = SC_MALLOC(sizeof(sc_ulimb_t) * depth);

    if (NULL == mm) {
        sgn_m = poly_limb_mod_halfgcd_recursive(NULL, NULL, 
                    a, len_a, b, len_b, 
                    x, len_x, y, len_y, modulus, scratch, 0, &res);
    }
    else {
        sgn_m = poly_limb_mod_halfgcd_recursive(mm, *len_mm, 
                    a, len_a, b, len_b, 
                    x, len_x, y, len_y, modulus, scratch, 1, &res);
    }

    if (*len_b < len_y) {
        if (1 <= *len_b) {
            res.lc  = limb_powmod2(res.lc, res.l0 - *len_b, modulus->m, modulus->m_inv, modulus->norm);
            res.res = limb_mul_mod_norm(res.res, res.lc,
                modulus->m, modulus->m_inv, modulus->norm);

            if (0 == ((res.l0 | res.l1) & 1)) {
                res.res = limb_negate_mod(res.res, modulus->m);
            }
        }
        else {
            if (1 == res.l1) {
                res.lc  = limb_powmod2(res.lc, res.l0 - 1, modulus->m, modulus->m_inv, modulus->norm);
                res.res = limb_mul_mod_norm(res.res, res.lc,
                    modulus->m, modulus->m_inv, modulus->norm);
            }
            else {
                res.res = 0;
            }
        }
    }

    *r = res.res;

    SC_FREE(scratch, sizeof(sc_ulimb_t) * depth);

    return sgn_m;
}

static sc_ulimb_t poly_limb_resultant_halfgcd(const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    sc_ulimb_t *scratch, const sc_mod_t *modulus)
{
    const size_t cutoff = (modulus->b_norm <= 8)?
        POLY_LIMB_SMALL_GCD_THRESH : POLY_LIMB_LARGE_GCD_THRESH;

    size_t len_x, len_y, len_r;
    sc_ulimb_t *x, *y, *r;

    const sc_ulimb_t m     = modulus->m;
    const sc_ulimb_t m_inv = modulus->m_inv;
    const sc_ulimb_t norm  = modulus->norm;

    if (a == b) {
        return 0;
    }
    else if (1 == len_b) {
        if (1 == len_a) {
            return 1;
        }
        else if (2 == len_a) {
            return b[0];
        }
        else {
            return limb_powmod2(b[0], len_a - 1, m, m_inv, norm);
        }
    }

    x = SC_MALLOC(sizeof(sc_ulimb_t) * (SC_MIN(len_a, len_b) + 2 * len_b));
    y = x + SC_MIN(len_a, len_b);
    r = y + len_b;

    sc_ulimb_t res;
    sc_ulimb_t lc = b[len_b - 1];

    halfgcd_rem_mod(r, &len_r, a, len_a, b, len_b, modulus);

    // If the remainder is zero the resultant is computed as the
    // product of the modular multiplicative inverse of the modulus and the
    // leading coefficient.
    if (0 == len_r) {
        if (1 == len_b) {
            lc  = limb_powmod2(lc, len_a - 1, m, m_inv, norm);
            res = limb_mod_reduction_norm(0, lc, m, m_inv, norm);
        }
        else {
            res = 0;
        }
    }
    else {
        lc  = limb_powmod2(lc, len_a - len_r, m, m_inv, norm);
        res = limb_mod_reduction_norm(0, lc, m, m_inv, norm);

        // If the length of a and b are even then negate the resultant
        if (0 == ((len_a | len_b) & 1)) {
            res = limb_negate_mod(res, m);
        }

        poly_limb_resultant_halfgcd_2(NULL, NULL, x, &len_x, y, &len_y, b, len_b, r, len_r, &res, modulus);

        while (0 != len_y) {
            lc = y[len_y - 1];
            
            halfgcd_rem_mod(r, &len_r, x, len_x, y, len_y, modulus);

            if (0 == len_r) {
               if (1 == len_y) {
                  lc  = limb_powmod2(lc, len_x - 1, m, m_inv, norm);
                  res = limb_mul_mod_norm(res, lc, m, m_inv, norm);
               }
               else {
                  res = 0;
               }
              
               break;
            }
            else {
               lc  = limb_powmod2(lc, len_x - len_r, m, m_inv, norm);
               res = limb_mul_mod_norm(res, lc, m, m_inv, norm);

               if (0 == ((len_x | len_y) & 1)) {
                  res = limb_negate_mod(res, m);
               }
            }

            if (len_y < cutoff) {
                sc_ulimb_t res1 = poly_limb_resultant_euclidean(y, len_y, (const sc_ulimb_t *)r, len_r, scratch, modulus);
                res = limb_mul_mod_norm(res, res1, m, m_inv, norm);
                break;
            }

            poly_limb_resultant_halfgcd_2(NULL, NULL, x, &len_x, y, &len_y, y, len_y, r, len_r, &res, modulus);
        }
    }

    SC_FREE(x, sizeof(sc_ulimb_t) * (SC_MIN(len_a, len_b) + 2 * len_b));

    return res;
}

sc_ulimb_t poly_limb_resultant(const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    sc_ulimb_t *scratch, const sc_mod_t *modulus)
{
    const size_t cutoff = (modulus->b_norm <= 8)?
        POLY_LIMB_SMALL_GCD_THRESH : POLY_LIMB_LARGE_GCD_THRESH;

    if (len_a < cutoff) {
        return poly_limb_resultant_euclidean(a, len_a, b, len_b, scratch, modulus);
    }
    else {
        return poly_limb_resultant_halfgcd(a, len_a, b, len_b, scratch, modulus);
    }
}

// Optimised division for small polynomials of equal length
static void poly_limb_divrem_mod_diff_0(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len, const sc_ulimb_t *b,
    const sc_mod_t *modulus)
{
    const sc_ulimb_t inv_l = (1 == b[len-1])? 1 :
                            limb_inv_mod(b[len-1], modulus->m);
 
    // q = LC(a) * (1/lc(b)) mod m
    q[0] = limb_mul_mod_norm(a[len-1], inv_l, modulus->m, modulus->m_inv, modulus->norm);

    if (1 < len) {
        // r = (a - qb) mod m
        poly_limb_mul_mod_scalar(r, b, len, q[0], modulus);
        poly_limb_sub_mod(r, a, len-1, r, len-1, modulus);
    }

    *len_q = 1;
    *len_r = len-1;
}

// Optimised division for small polynomails where a is 1 degree larger than b
static void poly_limb_divrem_mod_diff_1(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const sc_ulimb_t inv_l = (1 == b[len_b-1])? 1 :
                            limb_inv_mod(b[len_b-1], modulus->m);
 
    if (1 == len_b) {
        // NOTE: len_a >= len_b, i.e. single-precision division using
        // multiplication of 1/b
        poly_limb_mul_mod_scalar(q, a, len_a, inv_l, modulus);
    }
    else {
        // q[1] = LC(a) * (1/LC(b)), q[0] = (LC2(a) - q[1] * LC2(b)) * (1/LC(b))
        sc_ulimb_t temp;
        q[1] = limb_mul_mod_norm(a[len_a-1], inv_l, modulus->m, modulus->m_inv, modulus->norm);
        temp = limb_mul_mod_norm(q[1], b[len_b-2], modulus->m, modulus->m_inv, modulus->norm);
        temp = limb_sub_mod(a[len_a-2], temp, modulus->m);
        q[0] = limb_mul_mod_norm(temp, inv_l, modulus->m, modulus->m_inv, modulus->norm);

        // r = a - (q[1] * b[len_b-3:0] * B + q[0] * b[len_b-2:0])
        poly_limb_mul_mod_scalar(r, b, len_b-1, q[0], modulus);
        if (len_b > 2) {
            poly_limb_addmul_mod_scalar(r+1, b, len_b-2, q[1], modulus);
        }
        poly_limb_sub_mod(r, a, len_b-1, r, len_b-1, modulus);
    }

    *len_q = 2;
    *len_r = len_b-1;
}

static void poly_limb_divrem_mod_normal_2(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    SINT32 i, j;
    sc_ulimb_t *b2    = w;
    sc_ulimb_t *r2    = w + 2*(len_b - 1);
    sc_ulimb_t *ptr_q = q - len_b + 1;

    // Pre-compute the modular multiplicative inverse of LC(b)
    const sc_ulimb_t inv_l = limb_inv_mod(b[len_b - 1], modulus->m);
 
    // Store the denominator and numerator as interlaved tuples
    for (i=(SINT32)len_b-1; i--;) {
        b2[2*i    ] = b[i];
        b2[2*i + 1] = SC_LIMB_WORD(0);
    }
    for (i=(SINT32)len_a; i--;) {
        r2[2*i    ] = a[i];
        r2[2*i + 1] = SC_LIMB_WORD(0);
    }

    // Compute the coefficient until the we reach the LC(b) position
    for (j=(SINT32)len_a-1; j>=(SINT32)len_b-1;) {
        // While the remainder is zero set the quotient from the leading
        // coefficient position to zero
        sc_ulimb_t temp = limb_mod_ll(r2[2*j+1], r2[2*j],
            modulus->m, modulus->m_inv, modulus->norm);
        while (((j + 1)>=(SINT32)len_b) && (SC_LIMB_WORD(0) == temp)) {
            ptr_q[j--] = SC_LIMB_WORD(0);
            if ((j + 1) >= (SINT32)len_b) {
                temp = limb_mod_ll(r2[2*j+1], r2[2*j],
                    modulus->m, modulus->m_inv, modulus->norm);
            }
        }
 
        // If the remainder is still significant relative to the quotient position
        // the quotient corresponding to the LC(b) position must be computed
        // as the current remainder times the multiplicative inverse of LC(b).
        if ((j + 1) >= (SINT32)len_b) {
            ptr_q[j] = limb_mul_mod_norm(temp, inv_l,
                modulus->m, modulus->m_inv, modulus->norm);
 
            // if b is sufficiently long update r2
            if (len_b > 1) {
                const sc_ulimb_t c = limb_sub_mod(SC_LIMB_WORD(0), ptr_q[j], modulus->m);
                limb_mp_addmul_1(r2 + 2 * (j - len_b + 1), b2, 2 * len_b - 2, c);
            }
            j--;
        }
    }

    // The quotient is computed so derive the remainder from r2
    for (j=0; j<len_b-1; j++) {
        r[j] = limb_mod_ll(r2[2*j+1], r2[2*j],
            modulus->m, modulus->m_inv, modulus->norm);
    }

    // Assign the quotient and remainder lengths
    *len_q = len_a - len_b + 1;
    *len_r = len_b - 1;
}

static void poly_limb_div_mod_normal_2(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    SINT32 i, j;
    sc_ulimb_t *b2    = w;
    sc_ulimb_t *r2    = w + 2*(len_b - 1);

    // Pre-compute the modular multiplicative inverse of LC(b)
    const sc_ulimb_t inv_l = limb_inv_mod(b[len_b - 1], modulus->m);
 
    // Store the denominator and numerator as interlaved tuples
    for (i=(SINT32)len_b-1; i--;) {
        b2[2*i    ] = b[i];
        b2[2*i + 1] = SC_LIMB_WORD(0);
    }
    for (i=(SINT32)(len_a - len_b + 1); i--;) {
        r2[2*i    ] = a[len_b + i - 1];
        r2[2*i + 1] = SC_LIMB_WORD(0);
    }

    // Compute the coefficient until the we reach the LC(b) position
    for (j=(SINT32)(len_a - len_b); j>=0;) {
        // While the remainder is zero set the quotient from the leading
        // coefficient position to zero
        sc_ulimb_t temp = limb_mod_ll(r2[2*j+1], r2[2*j],
            modulus->m, modulus->m_inv, modulus->norm);
        while ((j >= 0) && (SC_LIMB_WORD(0) == temp)) {
            q[j--] = SC_LIMB_WORD(0);
            if (j  >= 0) {
                temp = limb_mod_ll(r2[2*j+1], r2[2*j],
                    modulus->m, modulus->m_inv, modulus->norm);
            }
        }
 
        // If the remainder is still significant relative to the quotient position
        // the quotient corresponding to the LC(b) position must be computed
        // as the current remainder times the multiplicative inverse of LC(b).
        if (j >= 0) {
            q[j] = limb_mul_mod_norm(temp, inv_l,
                modulus->m, modulus->m_inv, modulus->norm);
 
            // if b is sufficiently long update r2
            size_t len = SC_MIN(len_b - 1, j);
            if (len > 0) {
                const sc_ulimb_t c = limb_sub_mod(SC_LIMB_WORD(0), q[j], modulus->m);
                limb_mp_addmul_1(r2 + 2 * (j - len), b2 + 2*(len_b - 1) - 2*len, 2 * len, c);
            }
            j--;
        }
    }

    // Assign the quotient and remainder lengths
    *len_q = len_a - len_b + 1;
}

static void poly_limb_divrem_mod_normal_3(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    SINT32 i, j;
    sc_ulimb_t *b3    = w;
    sc_ulimb_t *r3    = w + 3*(len_b - 1);
    sc_ulimb_t *ptr_q = q - len_b + 1;

    // Pre-compute the modular multiplicative inverse of LC(b)
    const sc_ulimb_t inv_l = limb_inv_mod(b[len_b - 1], modulus->m);
 
    // Store the denominator and numerator as interlaved triplets
    for (i=(SINT32)len_b-1; i--;) {
        b3[3*i    ] = b[i];
        b3[3*i + 1] = SC_LIMB_WORD(0);
        b3[3*i + 2] = SC_LIMB_WORD(0);
    }
    for (i=(SINT32)len_a; i--;) {
        r3[3*i    ] = a[i];
        r3[3*i + 1] = SC_LIMB_WORD(0);
        r3[3*i + 2] = SC_LIMB_WORD(0);
    }

    // Compute the coefficient until the we reach the LC(b) position
    for (j=(SINT32)len_a-1; j>=(SINT32)len_b-1;) {
        // While the remainder is zero set the quotient from the leading
        // coefficient position to zero
        sc_ulimb_t temp = limb_mod_lll(r3[3*j+2], r3[3*j+1], r3[3*j],
            modulus->m, modulus->m_inv, modulus->norm);
        while (((j + 1)>=(SINT32)len_b) && (SC_LIMB_WORD(0) == temp)) {
            ptr_q[j--] = SC_LIMB_WORD(0);
            if ((j + 1) >= (SINT32)len_b) {
                temp = limb_mod_lll(r3[3*j+2], r3[3*j+1], r3[3*j],
                    modulus->m, modulus->m_inv, modulus->norm);
            }
        }
 
        // If the remainder is still significant relative to the quotient position
        // the quotient corresponding to the LC(b) position must be computed
        // as the current remainder times the multiplicative inverse of LC(b).
        if ((j + 1) >= (SINT32)len_b) {
            ptr_q[j] = limb_mul_mod_norm(temp, inv_l,
                modulus->m, modulus->m_inv, modulus->norm);
 
            // if b is sufficiently long update r3
            if (len_b > 1) {
                const sc_ulimb_t c = limb_sub_mod(SC_LIMB_WORD(0), ptr_q[j], modulus->m);
                limb_mp_addmul_1(r3 + 3 * (j - len_b + 1), b3, 3 * len_b - 3, c);
            }
            j--;
        }
    }

    // The quotient is computed so derive the remainder from r3
    for (j=0; j<len_b-1; j++) {
        r[j] = limb_mod_lll(r3[3*j+2], r3[3*j+1], r3[3*j],
            modulus->m, modulus->m_inv, modulus->norm);
    }

    // Assign the quotient and remainder lengths
    *len_q = len_a - len_b + 1;
    *len_r = len_b - 1;
}

static void poly_limb_div_mod_normal_3(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    SINT32 i, j;
    sc_ulimb_t *b3    = w;
    sc_ulimb_t *r3    = w + 3*(len_b - 1);

    // Pre-compute the modular multiplicative inverse of LC(b)
    const sc_ulimb_t inv_l = limb_inv_mod(b[len_b - 1], modulus->m);
 
    // Store the denominator and numerator as interlaved triplets
    for (i=(SINT32)len_b-1; i--;) {
        b3[3*i    ] = b[i];
        b3[3*i + 1] = SC_LIMB_WORD(0);
        b3[3*i + 2] = SC_LIMB_WORD(0);
    }
    for (i=(SINT32)(len_a - len_b + 1); i--;) {
        r3[3*i    ] = a[len_b + i - 1];
        r3[3*i + 1] = SC_LIMB_WORD(0);
        r3[3*i + 2] = SC_LIMB_WORD(0);
    }

    // Compute the coefficient until the we reach the LC(b) position
    for (j=(SINT32)(len_a-len_b); j>=0;) {
        // While the remainder is zero set the quotient from the leading
        // coefficient position to zero
        sc_ulimb_t temp = limb_mod_lll(r3[3*j+2], r3[3*j+1], r3[3*j],
            modulus->m, modulus->m_inv, modulus->norm);
        while ((j >= 0) && (SC_LIMB_WORD(0) == temp)) {
            q[j--] = SC_LIMB_WORD(0);
            if (j >= 0) {
                temp = limb_mod_lll(r3[3*j+2], r3[3*j+1], r3[3*j],
                    modulus->m, modulus->m_inv, modulus->norm);
            }
        }
 
        // If the remainder is still significant relative to the quotient position
        // the quotient corresponding to the LC(b) position must be computed
        // as the current remainder times the multiplicative inverse of LC(b).
        if (j >= 0) {
            q[j] = limb_mul_mod_norm(temp, inv_l,
                modulus->m, modulus->m_inv, modulus->norm);
 
            // if b is sufficiently long update r3
            size_t len = SC_MIN(len_b - 1, j);
            if (len > 0) {
                const sc_ulimb_t c = limb_sub_mod(SC_LIMB_WORD(0), q[j], modulus->m);
                limb_mp_addmul_1(r3 + 3 * (j - len), b3 + 3*(len_b-1)- 3*len, 3 * len, c);
            }
            j--;
        }
    }

    // Assign the quotient and remainder lengths
    *len_q = len_a - len_b + 1;
}

static void poly_limb_rem_mod_normal_2(sc_ulimb_t *r, size_t *len_r,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    SINT32 i, j;
    sc_ulimb_t *b2    = w;
    sc_ulimb_t *r2    = w + 2*(len_b - 1);

    // Pre-compute the modular multiplicative inverse of LC(b)
    const sc_ulimb_t inv_l = limb_inv_mod(b[len_b - 1], modulus->m);
 
    // Store the denominator and numerator as interlaved triplets
    for (i=(SINT32)len_b-1; i--;) {
        b2[2*i    ] = b[i];
        b2[2*i + 1] = SC_LIMB_WORD(0);
    }
    for (i=(SINT32)len_a; i--;) {
        r2[2*i    ] = a[i];
        r2[2*i + 1] = SC_LIMB_WORD(0);
    }

    // Compute the coefficient until the we reach the LC(b) position
    for (j=(SINT32)len_a-1; j>=(SINT32)len_b-1; j--) {
        // While the remainder is zero set the quotient from the leading
        // coefficient position to zero
        sc_ulimb_t temp = limb_mod_ll(r2[2*j+1], r2[2*j],
            modulus->m, modulus->m_inv, modulus->norm);
 
        // If the remainder is still significant relative to the quotient position
        // the quotient corresponding to the LC(b) position must be computed
        // as the current remainder times the multiplicative inverse of LC(b).
        if (0 != temp && len_b > 1) {
            const sc_ulimb_t q = limb_mul_mod_norm(temp, inv_l,
                modulus->m, modulus->m_inv, modulus->norm);
            const sc_ulimb_t c = limb_negate_mod(q, modulus->m);
            limb_mp_addmul_1(r2 + 2 * (j - len_b + 1), b2, 2 * len_b - 2, c);
        }
    }

    // The quotient is computed so derive the remainder from r3
    for (j=0; j<len_b-1; j++) {
        r[j] = limb_mod_ll(r2[2*j+1], r2[2*j],
            modulus->m, modulus->m_inv, modulus->norm);
    }

    // Assign the remainder lengths
    *len_r = len_b - 1;
}

static void poly_limb_rem_mod_normal_3(sc_ulimb_t *r, size_t *len_r,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    SINT32 i, j;
    sc_ulimb_t *b3    = w;
    sc_ulimb_t *r3    = w + 3*(len_b - 1);

    // Pre-compute the modular multiplicative inverse of LC(b)
    const sc_ulimb_t inv_l = limb_inv_mod(b[len_b - 1], modulus->m);
 
    // Store the denominator and numerator as interlaved triplets
    for (i=(SINT32)len_b-1; i--;) {
        b3[3*i    ] = b[i];
        b3[3*i + 1] = SC_LIMB_WORD(0);
        b3[3*i + 2] = SC_LIMB_WORD(0);
    }
    for (i=(SINT32)len_a; i--;) {
        r3[3*i    ] = a[i];
        r3[3*i + 1] = SC_LIMB_WORD(0);
        r3[3*i + 2] = SC_LIMB_WORD(0);
    }

    // Compute the coefficient until the we reach the LC(b) position
    for (j=(SINT32)len_a-1; j>=(SINT32)len_b-1; j--) {
        // While the remainder is zero set the quotient from the leading
        // coefficient position to zero
        sc_ulimb_t temp = limb_mod_lll(r3[3*j+2], r3[3*j+1], r3[3*j],
            modulus->m, modulus->m_inv, modulus->norm);
 
        // If the remainder is still significant relative to the quotient position
        // the quotient corresponding to the LC(b) position must be computed
        // as the current remainder times the multiplicative inverse of LC(b).
        if (0 != temp && len_b > 1) {
            const sc_ulimb_t q = limb_mul_mod_norm(temp, inv_l,
                modulus->m, modulus->m_inv, modulus->norm);
            const sc_ulimb_t c = limb_negate_mod(q, modulus->m);
            limb_mp_addmul_1(r3 + 3 * (j - len_b + 1), b3, 3 * len_b - 3, c);
        }
    }

    // The quotient is computed so derive the remainder from r3
    for (j=0; j<len_b-1; j++) {
        r[j] = limb_mod_lll(r3[3*j+2], r3[3*j+1], r3[3*j],
            modulus->m, modulus->m_inv, modulus->norm);
    }

    // Assign the remainder lengths
    *len_r = len_b - 1;
}

static void poly_limb_divrem_mod_normal(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const size_t bits =
        2 * modulus->b_norm + SC_LIMB_BITS - limb_clz(len_a - len_b + 1);

    if (2*bits <= SC_LIMB_BITS) {
        poly_limb_divrem_mod_normal_2(q, len_q, r, len_r,
            w, a, len_a, b, len_b, modulus);
    }
    else {
        poly_limb_divrem_mod_normal_3(q, len_q, r, len_r,
            w, a, len_a, b, len_b, modulus);
    }
}

static void poly_limb_rem_mod_normal(sc_ulimb_t *r, size_t *len_r,
    sc_ulimb_t *w, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const size_t bits =
        2 * modulus->b_norm + SC_LIMB_BITS - limb_clz(len_a - len_b + 1);

    if (2*bits <= SC_LIMB_BITS) {
        poly_limb_rem_mod_normal_2(r, len_r,
            w, a, len_a, b, len_b, modulus);
    }
    else {
        poly_limb_rem_mod_normal_3(r, len_r,
            w, a, len_a, b, len_b, modulus);
    }
}

static void poly_limb_divrem_divconquer_recursive(sc_ulimb_t *q, sc_ulimb_t *p,
    sc_ulimb_t *w, sc_ulimb_t *v,
    const sc_ulimb_t *a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    if (len_b <= POLY_LIMB_DIVCONQUER_THRESH) {
        // Non-recursive division once threshold has been exceeded

        sc_ulimb_t *t = v;
        sc_ulimb_t *w = t + 2*len_b - 1;
        size_t len_q, len_r;
        
        // t = a * B^(len_b-1)
        poly_limb_copy(t + len_b - 1, len_b, a + len_b - 1);
        poly_limb_reset(t, len_b - 1);
        
        // q = t / b, r = t % b
        poly_limb_divrem_mod_normal(q, &len_q, p, &len_r, w, t, 2 * len_b - 1, b, len_b, modulus);
        
        // p = -p
        poly_limb_negate_mod(p, p, len_r, modulus);
    }
    else
    {
        // Recursive computation of q = q1*x^(len_b >> 1) + q2 and p = dq1 * x^(len_b >> 1) + dq2

        const size_t n2 = len_b >> 1;
        const size_t n1 = len_b - n2;

        // Memory assignment of read-only polynomials
        const sc_ulimb_t *p1 = a + 2*n2;
        const sc_ulimb_t *p2;
        const sc_ulimb_t *d1 = b + n2;
        const sc_ulimb_t *d2 = b;
        const sc_ulimb_t *d3 = b + n1;
        const sc_ulimb_t *d4 = b;

        // Memory assignment of polynomials
        sc_ulimb_t *w1   = w;
        sc_ulimb_t *w2   = w + n2;
        sc_ulimb_t *q1   = q + n2;
        sc_ulimb_t *q2   = q;
        sc_ulimb_t *dq1  = p + n2;
        sc_ulimb_t *d1q1 = p + n2 - (n1 - 1);

        sc_ulimb_t *d2q1, *d3q2, *d4q2, *t;

        // q1 = p1 / d1, a (2*n1-1) x n1 division => q1 is of lenth n1
        poly_limb_divrem_divconquer_recursive(q1, d1q1, w1, v, p1, d1, n1, modulus);

        // d2q1 = d2 * q1, of length n1 + n2 - 1
        d2q1 = w1;
        poly_limb_mul_mod(d2q1, q1, n1, d2, n2, modulus);

        // dq1 = d1 * q1 * x^n2 + d2 * q1, of length n1 + n2 - 1
        // Split it into a segment of length n1 - 1 at dq1 and a piece
        // of length n2 at p.
        poly_limb_copy(dq1, n1 - 1, d2q1);
        if (n2 > (n1 - 1)) {
            p[0] = d2q1[n1 - 1];
        }
        poly_limb_add_mod(d1q1, d1q1, n1 - 1, d2q1 + n2, n1 - 1, modulus);

        // t = a/x^n2 - dq1 of length (2*n1 + n2 - 1), but we are not
        // interested in the top n1 coeffs as they will be zero, so this
        // has effective length n1 + n2 - 1
        t = w1;
        poly_limb_sub_mod(t, a + n1 + n2 - 1, n2, p, n2, modulus);
        p2 = t - (n2 - 1);

        // q2 = t / d3, a (2*n2-1) x n2 division => q2 is of length n2
        d3q2 = p;
        poly_limb_divrem_divconquer_recursive(q2, d3q2, w2, v, p2, d3, n2, modulus);

        // d4q2 = d4 * q2, of length n1 + n2 - 1
        d4q2 = w1;
        poly_limb_mul_mod(d4q2, d4, n1, q2, n2, modulus);

        // dq2 = d3q2 * x^n1 + d4q2, of length n1 + n2 - 1
        // where d3q2 is truncated to length n2 - 1
        poly_limb_add_mod(p + n1, p + n1, n2 - 1, d3q2, n2 - 1, modulus);
        poly_limb_copy(p, n2, d4q2);
        poly_limb_add_mod(p + n2, p + n2, n1 - 1, d4q2 + n2, n1 - 1, modulus);
    }
}

static void poly_limb_divrem_divconquer2(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    if (len_a < (2*len_b - 1)) {
        // Convert unbalanced division into a 2.n1 - 1 by n1 division
        const size_t n1 = len_a - len_b + 1;
        const size_t n2 = len_b - n1;
        const size_t depth = (n1 - 1) + len_b - 1 + poly_limb_divrem_mod_divconquer_limbcount(n1, modulus->norm);

        const sc_ulimb_t *p1 = a + n2;
        const sc_ulimb_t *d1 = b + n2;
        const sc_ulimb_t *d2 = b;

        sc_ulimb_t *v    = SC_MALLOC(sizeof(sc_ulimb_t) * depth);
        sc_ulimb_t *w    = v + poly_limb_divrem_mod_divconquer_limbcount(n1, modulus->norm);
        sc_ulimb_t *d1q1 = r + n2;
        sc_ulimb_t *d2q1 = w;

        poly_limb_divrem_divconquer_recursive(q, d1q1, w, v, p1, d1, n1, modulus);

        // Compute d2q1 = q * d2, of length len_b - 1
        if (n1 >= n2) {
            poly_limb_mul_mod(d2q1, q, n1, d2, n2, modulus);
        }
        else {
            poly_limb_mul_mod(d2q1, d2, n2, q, n1, modulus);
        }

        // Compute r = d1q1 * x^n1 + d2q1, of length len_b - 1; 
        // then compute r = a - r
        poly_limb_copy(r, n2, d2q1);
        poly_limb_add_mod(r + n2, r + n2, n1 - 1, d2q1 + n2, n1 - 1, modulus);
        poly_limb_sub_mod(r, a, len_b - 1, r, len_b - 1, modulus);

        SC_FREE(v, sizeof(sc_ulimb_t) * depth);
    }
    else {
        // len_a = 2 * len_b - 1
        const size_t depth = len_b - 1 + poly_limb_divrem_mod_divconquer_limbcount(len_b, modulus->norm);
        sc_ulimb_t *v = SC_MALLOC(sizeof(sc_ulimb_t) * depth);
        sc_ulimb_t *w = v + poly_limb_divrem_mod_divconquer_limbcount(len_b, modulus->norm);
 
        poly_limb_divrem_divconquer_recursive(q, r, w, v, a, b, len_b, modulus);
        poly_limb_sub_mod(r, a, len_b - 1, r, len_b - 1, modulus);

        SC_FREE(v, sizeof(sc_ulimb_t) * depth);
    }

    *len_r = len_b - 1;
    *len_q = len_a - len_b + 1;
}

static void poly_limb_divrem_divconquer(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    if (len_a <= (2 * len_b - 1)) {
        poly_limb_divrem_divconquer2(q, len_q, r, len_r, a, len_a, b, len_b, modulus);
    }
    else { // len_a > 2 * len_b - 1
        size_t shift, n = 2 * len_b - 1, depth;
        sc_ulimb_t *s, *p, *w, *v, *t;

        *len_r = len_b - 1;
        *len_q = len_a - len_b + 1;

        depth = len_a + 2 * (len_b - 1) + n + poly_limb_divrem_mod_divconquer_limbcount(len_b, modulus->norm);
        s = SC_MALLOC(sizeof(sc_ulimb_t) * depth);
        p = s + len_a;
        w = p + (len_b - 1);
        t = w + (len_b - 1);
        v = t + n;

        poly_limb_copy(s, len_a, a);

        while (len_a >= n) {
            shift = len_a - n;
            poly_limb_divrem_divconquer_recursive(q + shift, p, w, v, s + shift, b, len_b, modulus);
            poly_limb_sub_mod(s + shift, s + shift, len_b - 1, p, len_b - 1, modulus);
            len_a -= len_b;
        }

        if (len_a >= len_b) {
            size_t len_t;
            poly_limb_divrem_divconquer2(q, len_q, t, &len_t, s, len_a, b, len_b, modulus);
            poly_limb_copy(s, len_a, t);
        }

        poly_limb_copy(r, len_b-1, s);
        SC_FREE(s, sizeof(sc_ulimb_t) * depth);
    }
}

void poly_limb_divrem_mod(sc_ulimb_t *q, size_t *len_q, sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    if (len_a < len_b) {
        poly_limb_copy(r, len_a, a);
        poly_limb_reset(q, 0);
        *len_r = len_a;
        *len_q = 0;
    }
    else if (len_a == len_b) {
        // Optimised division where deg(a) = deg(b)
        poly_limb_divrem_mod_diff_0(q, len_q, r, len_r, a, len_a, b, modulus);
    }
    else if (len_a == (len_b + 1)) {
        // Optimised division where deg(a) = deg(b) + 1
        poly_limb_divrem_mod_diff_1(q, len_q, r, len_r, a, len_a, b, len_b, modulus);
    }
    else if (len_b >= POLY_LIMB_DIVREM_DIVCONQUER_THRESH) {
        // Divide-and-conquer division
        poly_limb_divrem_divconquer(q, len_q, r, len_r, a, len_a, b, len_b, modulus);
    }
    else {
        // The long division method that is used elsewhere when the polynomials are
        // sufficiently reduced in length
        const SINT32 depth = poly_limb_divrem_mod_limbcount(len_a, len_b, modulus->norm);
        sc_ulimb_t *w = SC_MALLOC(sizeof(sc_ulimb_t) * depth);
        poly_limb_divrem_mod_normal(q, len_q, r, len_r, w, a, len_a, b, len_b, modulus);
        SC_FREE(w, sizeof(sc_ulimb_t) * depth);
    }
}

void poly_limb_div_mod(sc_ulimb_t *q, size_t *len_q,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const size_t bits =
        2 * modulus->b_norm + SC_LIMB_BITS - limb_clz(len_a - len_b + 1);
    const SINT32 depth = (bits <=     SC_LIMB_BITS)? len_a - len_b + 1 :
                         (bits <= 2 * SC_LIMB_BITS)? 2*len_a           :
                                                     3*len_a;

    sc_ulimb_t *w = SC_MALLOC(sizeof(sc_ulimb_t) * depth);

    if (2*bits <= SC_LIMB_BITS) {
        poly_limb_div_mod_normal_2(q, len_q, w, a, len_a, b, len_b, modulus);
    }
    else {
        poly_limb_div_mod_normal_3(q, len_q, w, a, len_a, b, len_b, modulus);
    }

    SC_FREE(w, sizeof(sc_ulimb_t) * depth);
}

static void poly_limb_rem_mod_diff_1(sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const sc_ulimb_t inv = (1 == b[len_b-1])? 1 : limb_inv_mod(b[len_b-1], modulus->m);

    if (len_b > 1) {
        sc_ulimb_t t, q0, q1;
        q1 = limb_mul_mod_norm(a[len_a-1], inv, modulus->m, modulus->m_inv, modulus->norm);
        t  = limb_mul_mod_norm(q1, b[len_b-2], modulus->m, modulus->m_inv, modulus->norm);
        t  = limb_sub_mod(a[len_a-2], t, modulus->m);
        q0 = limb_mul_mod_norm(t, inv, modulus->m, modulus->m_inv, modulus->norm);

        if (SC_LIMB_BITS + 2 <= 2 * modulus->norm) {
            limb_mp_mul_1(r, b, len_b - 1, q0);
            if (len_b > 2)
                limb_mp_addmul_1(r + 1, b, len_b - 2, q1);
            poly_limb_mod(r, r, len_b - 1, modulus);
        }
        else {
            poly_limb_mul_mod_scalar(r, b, len_b - 1, q0, modulus);
            if (len_b > 2) {
                poly_limb_addmul_mod_scalar(r + 1, b, len_b - 2, q1, modulus);
            }
        }

        poly_limb_sub_mod(r, a, len_b-1, r, len_b - 1, modulus);
    }

    *len_r = len_b - 1;
}

void poly_limb_rem_mod(sc_ulimb_t *r, size_t *len_r, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *modulus)
{
    if (len_a == (len_b + 1)) {
        poly_limb_rem_mod_diff_1(r, len_r, a, len_a, b, len_b, modulus);
    }
    else {
        SINT32 depth = poly_limb_divrem_mod_limbcount(len_a, len_b, modulus->norm);
        depth *= sizeof(sc_ulimb_t);
        sc_ulimb_t *w = SC_MALLOC(depth);
        poly_limb_rem_mod_normal(r, len_r, w, a, len_a, b, len_b, modulus);
        SC_FREE(w, depth);
    }
}

// A wrapper function for poly_limb_mod_halfgcd_recursive() that will obtain
// dynamic memory and provide the initial call to the recursive function.
static SINT32 poly_limb_mod_halfgcd(sc_ulimb_t **m, size_t *len_m,
                             sc_ulimb_t *s, size_t *len_s, sc_ulimb_t *t, size_t *len_t,
                             const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
                             const sc_mod_t *modulus)
{
    const size_t len_w = 22 * len_a + 16 * (sc_ceil_log2(len_a) + 1);
    SINT32 sign_m;

    sc_ulimb_t *w = SC_MALLOC(sizeof(sc_ulimb_t) * len_w);
    sign_m = poly_limb_mod_halfgcd_recursive(m, len_m, s, len_s, t, len_t, a, len_a, b, len_b, modulus, w, 1, NULL);
    SC_FREE(w, sizeof(sc_ulimb_t) * len_w);

    return sign_m;
}

SINT32 poly_limb_gcd_mod_euclidean(sc_ulimb_t *g,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    if (len_a < len_b) {
        poly_limb_gcd_mod(g, b, len_b, a, len_a, modulus);
    }

    if (1 == len_b) {
        g[0] = b[0];
        return 1;
    }

    SINT32 steps;
    size_t len_r1, len_r2 = 0, len_g = 0;

    sc_ulimb_t *f, *r1, *r2, *r3, *t;
    f = SC_MALLOC((2*len_b-3) * sizeof(sc_ulimb_t));
    r1 = f;
    r2 = r1 + len_b - 1;
    r3 = g;

    poly_limb_rem_mod(r1, &len_r1, a, len_a, b, len_b, modulus);
    len_r1 = poly_limb_degree(r1, len_a - 1) + 1;

    if (1 < len_r1) {
        poly_limb_rem_mod(r2, &len_r2, b, len_b, r1, len_r1, modulus);
        len_r2 = poly_limb_degree(r2, len_r1 - 1) + 1;
    }
    else {
        if (0 == len_r1) {
            poly_limb_copy(g, len_b, b);
            SC_FREE(f, (2*len_b-3) * sizeof(sc_ulimb_t));
            return len_b;
        }
        else {
            g[0] = r1[0];
            SC_FREE(f, (2*len_b-3) * sizeof(sc_ulimb_t));
            return 1;
        }
    }

    for (steps=2; len_r2>1;) {
        poly_limb_rem_mod(r3, &len_r1, r1, len_r1, r2, len_r2, modulus);
        len_r1 = len_r2--;
        len_r2 = poly_limb_degree(r3, len_r2) + 1;
        t = r1; r1 = r2; r2 = r3; r3 = t;

        steps++;
        if (3 == steps) {
            steps = 0;
        }
    }

    if (1 == len_r2) {
        len_g = 1;
        if (steps) {
            g[0] = r2[0];
        }
    }
    else {
        len_g = len_r1;
        if (1 != steps) {
            poly_limb_copy(g, len_r1, r1);
        }
    }

    SC_FREE(f, (2*len_b-3) * sizeof(sc_ulimb_t));
    return len_g;
}

SINT32 poly_limb_gcd_mod_halfgcd(sc_ulimb_t *g,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const sc_ulimb_t cutoff = (modulus->b_norm <= 8)? 
        POLY_LIMB_SMALL_GCD_THRESH : POLY_LIMB_LARGE_GCD_THRESH;

    sc_ulimb_t *x = SC_MALLOC(sizeof(sc_ulimb_t) * 2 * len_b);
    sc_ulimb_t *r = x + len_b;

    size_t len_g, len_x, len_r;

    halfgcd_rem_mod(r, &len_r, a, len_a, b, len_b, modulus);

    if (0 == len_r) {
        poly_limb_copy(g, len_b, b);
        len_g = len_b;
    }
    else {
        poly_limb_mod_halfgcd(NULL, NULL, g, &len_g, x, &len_x, b, len_b, r, len_r, modulus);

        while (0 != len_x) {
            halfgcd_rem_mod(r, &len_r, g, len_g, x, len_x, modulus);

            if (0 == len_r) {
                poly_limb_copy(g, len_x, x);
                len_g = len_x;
                break;
            }
            if (len_x < cutoff) {
                len_g = poly_limb_gcd_mod_euclidean(g, x, len_x, r, len_r, modulus);
                break;
            }

            poly_limb_mod_halfgcd(NULL, NULL, g, &len_g, x, &len_x, x, len_x, r, len_r, modulus);
        }
    }

    SC_FREE(x, sizeof(sc_ulimb_t) * 2 * len_b);
    return len_g;
}

SINT32 poly_limb_gcd_mod(sc_ulimb_t *g,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const sc_ulimb_t cutoff = (modulus->b_norm <= 8)? 
        POLY_LIMB_SMALL_GCD_THRESH : POLY_LIMB_LARGE_GCD_THRESH;

    if (len_a < cutoff) {
        return poly_limb_gcd_mod_euclidean(g, a, len_a, b, len_b, modulus);
    }
    else {
        return poly_limb_gcd_mod_halfgcd(g, a, len_a, b, len_b, modulus);
    }
}

// Calculate the XGCD of two limb polynomials modulo m. Used as an alternative to
// poly_limb_xgcd_mod_halfgcd() for smaller polynomials.
static SINT32 poly_limb_xgcd_mod_euclidean(sc_ulimb_t *g, sc_ulimb_t *x, sc_ulimb_t *y,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    // Reset the output variables
    poly_limb_reset(g, len_b);
    poly_limb_reset(x, len_b - 1);
    poly_limb_reset(y, len_a - 1);

    // Early termination if the length of b is 1
    if (1 == len_b) {
        g[0] = b[0];
        y[0] = 1;
        return 1;
    }

    size_t len_q, len_r = 0, len_g = 0;

    sc_ulimb_t *q, *r;
    q = SC_MALLOC((2*len_a) * sizeof(sc_ulimb_t));
    r = q + len_a;

    // Perform the first division outside the loop to allow
    // the remainder to be checked and early termination to occur
    poly_limb_rem_mod(r, &len_r, a, len_a, b, len_b, modulus);
    len_r = poly_limb_degree(r, len_b - 1) + 1;

    // If the first remainder is zero then the GCD(a,b) is b as
    // we enforce the convention that len_a >= len_b
    if (0 == len_r) {
        // ax + by = GCD(a,b), where b = GCD(a,b) so y = 1 and x = 0
        poly_limb_copy(g, len_b, b);
        y[0]  = 1;
        len_g = len_b;
    }
    else {
        // Create temporary storage for five polynomials of length len_b
        const SINT32 depth = SC_MAX(5*len_b, len_a + len_b);
        sc_ulimb_t *w, *d, *u, *v1, *v3, *temp;
        w  = SC_MALLOC(depth * sizeof(sc_ulimb_t));
        d  = w + len_b;
        u  = d + len_b;
        v1 = u + len_b;
        v3 = v1 + len_b;

        // Initialise the lengths
        size_t len_w, len_d, len_u, len_v1, len_v3, len_temp;
        len_d  = len_b;
        len_u  = 0;
        len_v1 = 1;
        len_v3 = 0;

        // Initialise the variables
        poly_limb_copy(d, len_b, b);
        v1[0]    = 1;
        temp     = v3;
        v3       = r;
        r        = temp;
        len_temp = len_v3;
        len_v3   = len_r;
        len_r    = len_temp;

        // Euclidean GCD until v3 is 0
        do {
            // q = d/v3, r = d%v3
            poly_limb_divrem_mod(q, &len_q, r, &len_r, d, len_d, v3, len_v3, modulus);
            len_r = poly_limb_degree(r, len_r) + 1;

            // w = v1 * q
            if (len_v1 >= len_q) {
                poly_limb_mul_mod(w, v1, len_v1, q, len_q, modulus);
            }
            else {
                poly_limb_mul_mod(w, q, len_q, v1, len_v1, modulus);
            }
            len_w = len_q + len_v1 - 1;

            // u -= w
            poly_limb_sub_mod(u, u, len_u, w, len_w, modulus);
            len_u = poly_limb_degree(u, SC_MAX(len_u, len_w)) + 1;

            // swap(u,v1)
            temp     = u;
            u        = v1;
            v1       = temp;
            len_temp = len_u;
            len_u    = len_v1;
            len_v1   = len_temp;

            // rotate_swap(d, v3, r)
            temp     = d;
            d        = v3;
            v3       = r;
            r        = temp;
            len_temp = len_d;
            len_d    = len_v3;
            len_v3   = len_r;
            len_r    = len_temp;
        } while (0 != len_v3);

        // The GCD(a,b) is equal to d, x = u
        poly_limb_copy(g, len_d, d);
        poly_limb_copy(x, len_u, u);

        // Compute y = (g - ax)/b
        len_q = len_a + len_u - 1;
        poly_limb_mul_mod(q, a, len_a, x, len_u, modulus);
        poly_limb_negate_mod(q, q, len_q, modulus);
        poly_limb_add_mod(q, g, len_d, q, len_q, modulus);
        poly_limb_divrem_mod(y, &len_temp, w, &len_w, q, len_q, b, len_b, modulus);

        SC_FREE(w, depth * sizeof(sc_ulimb_t));
        len_g = len_d;
    }

    SC_FREE(q, (2*len_a) * sizeof(sc_ulimb_t));
    return len_g;
}

// Calculate the XGCD of two limb polynomials modulo m. Used as an alternative to
// poly_limb_xgcd_mod_euclidean() for larger polynomials. This will use
// poly_limb_xgcd_mod_euclidean() internally to calculate the XGCD when the
// polynomial length is sufficiently reduced by the Half-GCD algorithm.
static SINT32 poly_limb_xgcd_mod_halfgcd(sc_ulimb_t *g, sc_ulimb_t *x, sc_ulimb_t *y,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    const size_t cutoff = (modulus->b_norm <= 8)?
        POLY_LIMB_SMALL_GCD_THRESH : POLY_LIMB_LARGE_GCD_THRESH;

    size_t len_g, len_x, len_y;

    // Check for early termination that satisifes ax + by = GCD(a,b)
    if (1 == len_b) {
        // If b = GCD(a,b) then y = 1 and x = 0
        g[0]  = b[0];
        y[0]  = 1;
        len_g = 1;
        len_x = 0;
        len_y = 1;
    }
    else {
        size_t len_q, len_r;
        sc_ulimb_t *q = SC_MALLOC(sizeof(sc_ulimb_t) * (len_a + len_b));
        sc_ulimb_t *r = q + len_a;

        // Check if a%b == 0
        poly_limb_divrem_mod(q, &len_q, r, &len_r, a, len_a, b, len_b, modulus);
        if (0 == len_r) {
            // If b = GCD(a,b) then y = 1 and x = 0
            poly_limb_copy(g, len_b, b);
            y[0]  = 1;
            len_g = len_b;
            len_x = 0;
            len_y = 1;
        }
        else {
            sc_ulimb_t *h, *j, *v, *w, *mat_r[4];
            size_t len_h, len_j, len_v, len_w, len_mat_r[4], depth;
            SINT32 sign_mat_r;

            // Set the polynomial lengths of all the intermediate values
            len_h = len_j = len_b;
            len_v = len_w = len_a + len_b - 2;
            len_mat_r[0] = len_mat_r[1] = len_mat_r[2] = len_mat_r[3] = (len_b + 1) >> 1;
            depth = 2 * len_h + 2 * len_v + 4 * len_mat_r[0];

            // Allocate temporary memory and assign it as appropriate
            h = SC_MALLOC(sizeof(sc_ulimb_t) * depth);
            j = h + len_h;
            v = j + len_j;
            w = v + len_v;
            mat_r[0] = w + len_w;
            mat_r[1] = mat_r[0] + len_mat_r[0];
            mat_r[2] = mat_r[1] + len_mat_r[1];
            mat_r[3] = mat_r[2] + len_mat_r[2];

            // Create the initial Half-GCD matrix
            sign_mat_r = poly_limb_mod_halfgcd(mat_r, len_mat_r, h, &len_h, j, &len_j,
                b, len_b, r, len_r, modulus);

            // Depending upon the matrix sign assign the Bezout polynomials
            if (sign_mat_r > 0) {
                // If positive, x = -R[1] and y = R[0]
                poly_limb_negate_mod(x, mat_r[1], len_mat_r[1], modulus);
                poly_limb_copy(y, len_mat_r[0], mat_r[0]);
            }
            else {
                // If negative, x = R[1] and y = -R[0]
                poly_limb_copy(x, len_mat_r[1], mat_r[1]);
                poly_limb_negate_mod(y, mat_r[0], len_mat_r[0], modulus);
            }
            len_x = len_mat_r[1];
            len_y = len_mat_r[0];

            while (len_j != 0) {
                // q = h/j, r = h%j, v = qy
                poly_limb_divrem_mod(q, &len_q, r, &len_r, h, len_h, j, len_j, modulus);
                poly_limb_mul_mod(v, q, len_q, y, len_y, modulus);
                len_v = len_q + len_y - 1;

                poly_limb_swap(x, &len_x, y, &len_y);

                // y = y - v mod q
                poly_limb_sub_mod(y, y, len_y, v, len_v, modulus);
                len_y = (len_y > len_v)? len_y : len_v;

                // If perfectly divisible we've found a cofactor
                if (0 == len_r) {
                    poly_limb_copy(g, len_j, j);
                    len_g = len_j;
                    goto cofactor;
                }

                // If the j polynomial reaches a length threshold we can early terminate
                // using the now efficient poly_limb_xgcd_mod_euclidean()
                if (len_j < cutoff) {
                    sc_ulimb_t *p0 = mat_r[0];
                    sc_ulimb_t *p1 = mat_r[1];
                    size_t len_p0 = len_r - 1;
                    size_t len_p1 = len_j - 1;

                    // GCD(a,b) = GCD(j,r)
                    len_g  = poly_limb_xgcd_mod_euclidean(g, p0, p1, j, len_j, r, len_r, modulus);
                    len_p0 = poly_limb_degree(p0, len_p0) + 1;
                    len_p1 = poly_limb_degree(p1, len_p1) + 1;

                    // x = x*p0 + y*p1
                    poly_limb_mul_mod(v, x, len_x, p0, len_p0, modulus);
                    len_v = len_x + len_p0 - 1;
                    poly_limb_mul_mod(w, y, len_y, p1, len_p1, modulus);
                    len_w = len_y + len_p1 - 1;
                    poly_limb_add_mod(x, v, len_v, w, len_w, modulus);
                    len_x = (len_v > len_w)? len_v : len_w;

                    goto cofactor;
                }

                // Continue with the iterative Half-GCD
                sign_mat_r = poly_limb_mod_halfgcd(mat_r, len_mat_r, h, &len_h, j, &len_j,
                    j, len_j, r, len_r, modulus);

                // v = R[1] * y, w = R[2] * x
                poly_limb_mul_mod(v, mat_r[1], len_mat_r[1], y, len_y, modulus);
                len_v = len_mat_r[1] + len_y - 1;
                poly_limb_mul_mod(w, mat_r[2], len_mat_r[2], x, len_x, modulus);
                len_w = len_mat_r[2] + len_x - 1;

                // q = R[3] * x, x = | q - v |
                poly_limb_mul_mod(q, mat_r[3], len_mat_r[3], x, len_x, modulus);
                len_q = len_mat_r[3] + len_x - 1;
                if (sign_mat_r > 0) {
                    poly_limb_sub_mod(x, q, len_q, v, len_v, modulus);
                }
                else {
                    poly_limb_sub_mod(x, v, len_v, q, len_q, modulus);
                }
                len_x = (len_q > len_v)? len_q : len_v;

                // q = R[0] * y, y = | q - w |
                poly_limb_mul_mod(q, mat_r[0], len_mat_r[0], y, len_y, modulus);
                len_q = len_mat_r[0] + len_y - 1;
                if (sign_mat_r > 0) {
                    poly_limb_sub_mod(y, q, len_q, w, len_w, modulus);
                }
                else {
                    poly_limb_sub_mod(y, w, len_w, q, len_q, modulus);
                }
                len_y = (len_q > len_w)? len_q : len_w;
            }

            poly_limb_copy(g, len_h, h);
            len_g = len_h;

cofactor:
            // y = (g - x*a) / b
            poly_limb_mul_mod(v, x, len_x, a, len_a, modulus);
            len_v = len_x + len_a - 1;
            poly_limb_sub_mod(w, g, len_g, v, len_v, modulus);
            len_w = SC_MAX(len_g, len_v);
            poly_limb_div_mod(y, &len_y, w, len_w, b, len_b, modulus);

            SC_FREE(h, sizeof(sc_ulimb_t) * depth);
        }

        SC_FREE(q, sizeof(sc_ulimb_t) * (len_a + len_b));
    }

    poly_limb_reset(x + len_x, len_b - 1 - len_x);
    poly_limb_reset(y + len_y, len_a - 1 - len_y);
    return len_g;
}

// Calculate the XGCD of two limb polynomials modulo m.
SINT32 poly_limb_xgcd_mod(sc_ulimb_t *g, sc_ulimb_t *x, sc_ulimb_t *y,
    const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus)
{
    if (len_a < len_b) {
        return poly_limb_xgcd_mod(g, y, x, b, len_b, a, len_a, modulus);
    }

    const size_t cutoff = (modulus->b_norm <= 8)?
        POLY_LIMB_SMALL_GCD_THRESH : POLY_LIMB_LARGE_GCD_THRESH;

    if (len_a < cutoff) {
        return poly_limb_xgcd_mod_euclidean(g, x, y, a, len_a, b, len_b, modulus);
    }
    else {
        return poly_limb_xgcd_mod_halfgcd(g, x, y, a, len_a, b, len_b, modulus);
    }
}


