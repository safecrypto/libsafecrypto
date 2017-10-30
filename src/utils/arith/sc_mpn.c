/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

#include "sc_mpn.h"
#include "limb.h"
#include <assert.h>


#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION


/// @todo Find the optimal value to switch from Gradeschool to Karatsuba
#define MPN_MUL_GRADESCHOOL_THRESH     (32)



SINT32 mpn_cmp(const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n)
{
    while (n--) {
        if (in1[n] != in2[n]) {
            return (in1[n] > in2[n])? 1 : -1;
        }
    }
    return 0;
}

SINT32 mpn_cmp_n(const sc_ulimb_t *in1, size_t in1_n, const sc_ulimb_t *in2, size_t in2_n)
{
    if (in1_n < in2_n) {
        return -1;
    }
    else if (in1_n > in2_n) {
        return 1;
    }
    else {
        return mpn_cmp(in1, in2, in1_n);
    }
}

void mpn_copy(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n)
{
#if 1
    while (n--) {
        out[n] = in[n];
    }
#else
    size_t i;
    for (i=0; i<n; i++) {
        out[i] = in[i];
    }
#endif
}

void mpn_zero(sc_ulimb_t* inout, size_t n)
{
    while (n--) {
        inout[n] = 0;
    }
}

SINT32 mpn_zero_p(const sc_ulimb_t *in, size_t n)
{
    while (n && in[--n]) {
    }
    return 0 == n && 0 == in[0];
}

void mpn_com(sc_ulimb_t* out, const sc_ulimb_t *in, size_t n)
{
    while (n--) {
        *out++ = ~(*in++);
    }
}

size_t mpn_normalized_size(const sc_ulimb_t *inout, size_t n)
{
    while (n > 0 && 0 == inout[n - 1]) {
        n--;
    }
    return n;
}

sc_ulimb_t mpn_lshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n, size_t count)
{
    sc_ulimb_t h, l, retval;
    size_t bits = SC_LIMB_BITS - count;

    assert(count > 0 && count < SC_LIMB_BITS);

    in  += n;
    out += n;

    l      = *--in;
    retval = l >> bits;
    h      = l << count;
    while (--n) {
        l      = *--in;
        *--out = h | (l >> bits);
        h      = l << count;
    }
    *--out = h;

    return retval;
}

sc_ulimb_t mpn_rshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n, size_t count)
{
    sc_ulimb_t h, l, retval;
    size_t bits = SC_LIMB_BITS - count;

    assert(count > 0 && count < SC_LIMB_BITS);

    h      = *in++;
    retval = h << bits;
    l      = h >> count;
    while (--n) {
        h      = *in++;
        *out++ = l | (h << bits);
        l      = h >> count;
    }
    *out = l;

    return retval;
}

sc_ulimb_t mpn_add_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2)
{
    // Use the function's local copy of in2 to use as the carry word
    size_t i = 0;
    do {
        sc_ulimb_t temp = in1[i] + in2;
        out[i] = temp;
        in2    = temp < in2;
        i++;
    } while (i < n);
    return in2;
}

sc_ulimb_t mpn_add_n(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n)
{
    size_t i;
    sc_ulimb_t c = 0;

    for (i=0; i<n; i++) {
        sc_ulimb_t temp = in1[i] + c;
        c      = temp < c;
        temp  += in2[i];
        c     += temp < in2[i];
        out[i] = temp;
    }
    return c;
}

sc_ulimb_t mpn_add(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n1, const sc_ulimb_t *in2, size_t n2)
{
    sc_ulimb_t c;
    assert(n1 >= n2);
    c = mpn_add_n(out, in1, in2, n2);
    if (n1 > n2) {
        c = mpn_add_1(out + n2, in1 + n2, n1 - n2, c);
    }
    return c;
}

sc_ulimb_t mpn_addmul_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2)
{
    sc_ulimb_t c, h, l;

    c = 0;
    do {
        // Calculate the product
        limb_mul_hi_lo(&h, &l, *in1++, in2);

        // Add the carry word and update the carry using the MSW
        l += c;
        c  = h + (l < c);

        // Add the LSW of the product from the output, update the carry
        // and write the output word
        l  = *out + l;
        c += l < *out;
        *out++ = l;
    } while (--n);

    return c;
}


sc_ulimb_t mpn_sub_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2)
{
    // Use the function's local copy of in2 to use as the carry word
    size_t i;
    for (i=0; i<n; i++) {
        sc_ulimb_t c = in1[i] < in2;
        out[i] = in1[i] - in2;
        in2 = c;
    }
    return in2;
}

sc_ulimb_t mpn_sub_n(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n)
{
    size_t i;
    sc_ulimb_t c = 0;

    for (i=0; i<n; i++) {
        sc_ulimb_t temp = in2[i] + c;
        c      = temp < c;
        c     += in1[i] < temp;
        out[i] = in1[i] - temp;
    }
    return c;
}

sc_ulimb_t mpn_sub(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n1, const sc_ulimb_t *in2, size_t n2)
{
    sc_ulimb_t c;
    assert(n1 >= n2);
    c = mpn_sub_n(out, in1, in2, n2);
    if (n1 > n2) {
        c = mpn_sub_1(out + n2, in1 + n2, n1 - n2, c);
    }
    return c;
}

sc_ulimb_t mpn_submul_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2)
{
    sc_ulimb_t c, h, l;

    c = 0;
    do {
        // Calculate the product
        limb_mul_hi_lo(&h, &l, *in1++, in2);

        // Add the carry word and update the carry using the MSW
        l += c;
        c  = h + (l < c);

        // Subtract the LSW of the product from the output, update the carry
        // and write the output word
        l  = *out - l;
        c += l > *out;
        *out++ = l;
    } while (0 != --n);

    return c;
}

// A special case for a single-precision denominator that is pre-inverted to form
// a limb-sized fixed-point reciprocal.
// NOTE: The numerator is destroyed and the remainder is returned
static sc_ulimb_t mpn_div_qr_1_preinv(sc_ulimb_t *q_limbs, const sc_ulimb_t *n_limbs,
    size_t n, const sc_mod_t *mod)
{
    size_t i;
    sc_ulimb_t rem = 0;
    sc_ulimb_t *temp = NULL;

    // Normalise the numerator
    if (mod->norm > 0) {
        temp = SC_MALLOC(n * sizeof(sc_ulimb_t));
        rem = mpn_lshift(temp, n_limbs, n, mod->norm);
        n_limbs = temp;
    }

    // Iteratively divide each limb of the numerator, storing the result
    i = n;
    while (i--) {
        sc_ulimb_t quo;
        udiv_qrnnd_preinv(&quo, &rem, rem, n_limbs[i], mod->m << mod->norm, mod->m_inv);
        if (q_limbs) {
            q_limbs[i] = quo;
        }
    }

    // Release intermediate memory
    if (mod->norm > 0) {
        SC_FREE(temp, n * sizeof(sc_ulimb_t));
    }

    // Ensure that the remainder is returned as a de-normalised value
    return rem >> mod->norm;
}

// A special case for a double-precision denominator that is pre-inverted to form
// a limb-sized fixed-point reciprocal. The denominator is passed as a normalised
// pair of values in the mod struct.
// NOTE: The numerator is destroyed.
static void mpn_div_qr_2_preinv(sc_ulimb_t *q_limbs, sc_ulimb_t *r_limbs,
    const sc_ulimb_t *n_limbs, size_t n, const sc_mod_t *mod)
{
    SINT32 i = n - 2;
    sc_ulimb_t r1 = 0, r0;
    sc_ulimb_t *temp;

    // Normalise the numerator by norm bits, otherwise r1 is zero
    if (mod->norm) {
        temp = SC_MALLOC(n * sizeof(sc_ulimb_t));
        r1 = mpn_lshift(temp, n_limbs, n, mod->norm);
        n_limbs = temp;
    }

    // r0 is always the most significant numerator word
    r0 = n_limbs[n - 1];

    // Iteratively perform a 3-by-2 division to obtain the quotient from most significant
    // to least significant word
    do {
        sc_ulimb_t quo;
        udiv_qrnnndd_preinv(&quo, &r1, &r0, r1, r0, n_limbs[i], mod->m, mod->m_low, mod->m_inv);
        if (q_limbs) {
            q_limbs[i] = quo;
        }
    } while (i--);

    // De-normalise the remainder by right shifting by norm bits
    if (mod->norm) {
        r0   = (r0 >> mod->norm) | (r1 << mod->b_norm);
        r1 >>= mod->norm;
        SC_FREE(temp, n * sizeof(sc_ulimb_t));
    }

    // Return the two de-normalised remainder words
    r_limbs[1] = r1;
    r_limbs[0] = r0;
}

sc_ulimb_t mpn_div_qr_1(sc_ulimb_t *q_limbs, sc_ulimb_t *qh, const sc_ulimb_t *n_limbs,
    size_t n, sc_ulimb_t d)
{
    sc_ulimb_t r;

    // Detect a power of 2 and right-shift, otherwise perform a division
    if (d > 1 && (d & (d-1)) == 0) {
        UINT32 shift;
        shift = limb_ctz(d);
        r     = n_limbs[0] & (d - 1);
        *qh   = (d & SC_LIMB_HIGHBIT)? (d <= n_limbs[n-1]) : n_limbs[n-1] >> shift;

        if (q_limbs) {
            mpn_rshift(q_limbs, n_limbs, n, shift);
        }
        return r;
    }
    else {
        sc_ulimb_t dummy = 0;
        sc_mod_t mod;
        limb_mod_init(&mod, d);
        if (d & SC_LIMB_HIGHBIT) {
            *qh = (d <= n_limbs[n-1]);
        }
        else {
            udiv_qrnnd_preinv(qh, &dummy, dummy, n_limbs[n-1], mod.m << mod.norm, mod.m_inv);
        }
        r = mpn_div_qr_1_preinv(q_limbs, n_limbs, n, &mod);
        return r;
    }
}

static void mpn_div_qr_general(sc_ulimb_t *q_limbs, sc_ulimb_t *n_limbs,
    size_t n, const sc_ulimb_t *d_limbs, size_t dn, const sc_mod_t *mod)
{
    size_t i;
    sc_ulimb_t q, inv, d1, d0, n1;
    inv = mod->m_inv;
    d1  = d_limbs[dn-1];
    d0  = d_limbs[dn-2];
    n1  = 0;

    // Normalise the numerator by left shifting by norm bits
    if (mod->norm) {
        n1 = mpn_lshift(n_limbs, n_limbs, n, mod->norm);
    }

    // Calculate the quotient in descending order over 'n - dn' iterations
    i = n - dn;
    do {
        sc_ulimb_t n0 = n_limbs[dn - 1 + i];
        if (n1 == d1 && n0 == d0) {
            // If the numerator and denominator are identical the quotient is set to
            // the maximum limb value and the product of the quotient and denominator is
            // subtracted from the numerator.
            q = SC_LIMB_MASK;
            mpn_submul_1(n_limbs + i, d_limbs, dn, q);
            n1 = n_limbs[dn - 1 + i];
        }
        else {
            // Divide 'n1|n0|n_limbs[dn-2+i]' by 'd1|d0' and subtract the product of the quotient
            // and denominator from the numerator
            sc_ulimb_t c, c2;
            udiv_qrnnndd_preinv(&q, &n1, &n0, n1, n0, n_limbs[dn - 2 + i], d1, d0, inv);
            c   = mpn_submul_1(n_limbs + i, d_limbs, dn - 2, q);

            // Subtract the carry from the middle numerator limb and copy to the numerator output
            c2  = n0 < c;
            n0 -= c;
            n_limbs[dn - 2 + i] = n0;

            // Subtract the carry from the upper numerator limb
            c   = n1 < c2;
            n1 -= c2;

            // If there is a carry it must be propagated through the numerator and accounted for by
            // decrementing the quotient
            if (c) {
                n1 += d1 + mpn_add_n(n_limbs + i, n_limbs + i, d_limbs, dn - 1);
                q--;
            }
        }

        // Update the output quotient
        if (q_limbs) {
            q_limbs[i] = q;
        }
    } while (0 != i--);

    // Carry the numerator word to the most significant remainder/numerator word indexed by n1
    n_limbs[dn - 1] = n1;

    // De-normalise the least significant numerator words
    if (mod->norm) {
        mpn_rshift(n_limbs, n_limbs, dn, mod->norm);
    }
}

static void mpn_div_qr_preinv(sc_ulimb_t *q_limbs, sc_ulimb_t *n_limbs,
    size_t n, const sc_ulimb_t *d_limbs, size_t dn, sc_mod_t *mod)
{
    if (1 == dn) {
        // Special case with a single precision denominator
       n_limbs[0] = mpn_div_qr_1_preinv(q_limbs, n_limbs, n, mod);
    }
    else if (2 == dn) {
        // Special case with a double precision denominator
        mpn_div_qr_2_preinv(q_limbs, n_limbs, n_limbs, n, mod);
    }
    else {
        // The general case
        mpn_div_qr_general(q_limbs, n_limbs, n, d_limbs, dn, mod);
    }
}

sc_ulimb_t mpn_divrem(sc_ulimb_t *q_limbs, size_t qn, const sc_ulimb_t *n_limbs, size_t n_len, const sc_ulimb_t *d, size_t d_len)
{
    /// @todo Create mpn_divrem()
    return 0;
}

sc_ulimb_t mpn_divrem_1(sc_ulimb_t *q_limbs, size_t q_frac_n, const sc_ulimb_t *n_limbs, size_t n, sc_ulimb_t d)
{
    // The remainder is returned while a fractional quotient is written to q_limbs
    // with q_frac_n fractional limbs and n integer limbs
    size_t i;
    sc_mod_t mod;
    limb_mod_init(&mod, d);

    sc_ulimb_t rem = 0;
    sc_ulimb_t *temp = NULL;

    // Normalise the numerator
    if (mod.norm > 0) {
        temp = SC_MALLOC(n * sizeof(sc_ulimb_t));
        rem = mpn_lshift(temp, n_limbs, n, mod.norm);
        n_limbs = temp;
    }

    // Iteratively divide each integer limb of the numerator, storing the result
    i = n;
    while (i--) {
        sc_ulimb_t quo;
        udiv_qrnnd_preinv(&quo, &rem, rem, n_limbs[i], mod.m << mod.norm, mod.m_inv);
        if (q_limbs) {
            q_limbs[i + q_frac_n] = quo;
        }
    }

    // Release intermediate memory
    if (mod.norm > 0) {
        SC_FREE(temp, n * sizeof(sc_ulimb_t));
    }

    // Iteratively divide each fractional limb of the numerator, storing the result
    i = q_frac_n;
    while (i--) {
        sc_ulimb_t quo;
        udiv_qrnnd_preinv(&quo, &rem, rem, SC_LIMB_WORD(0), mod.m << mod.norm, mod.m_inv);
        if (q_limbs) {
            q_limbs[i] = quo;
        }
    }

    return rem >> mod.norm;
}

// NOTE: The numerator will be overwritten
void mpn_div_qr(sc_ulimb_t *q_limbs, sc_ulimb_t *n_limbs,
    size_t n, const sc_ulimb_t *d_limbs, size_t dn)
{
    sc_ulimb_t *temp = NULL;
    sc_mod_t mod;

    if (1 == dn) {
        // Special case for a single limb divisor
        limb_mod_init(&mod, d_limbs[0]);
    }
    else if (2 == dn) {
        // Special case for a two limb divisor
        limb_mod_init_2(&mod, d_limbs[1], d_limbs[0]);
    }
    else {
        // General case
        sc_ulimb_t d1, d0;
        d1 = d_limbs[dn-1];
        d0 = d_limbs[dn-2];
        mod.norm = limb_clz(d1);
        mod.b_norm = SC_LIMB_BITS - mod.norm;
        if (mod.norm) {
            d1 = (d1 << mod.norm) | (d0 >> mod.b_norm);
            d0 = (d0 << mod.norm) | (d_limbs[dn-3] >> mod.b_norm);
        }
        mod.m = d1;
        mod.m_low = d0;
        mod.m_inv = limb_inverse_3by2(d1, d0);
    }

    // Normalise the divisor if it is not a special case and
    // it contains leading zeros in the MSW
    if (dn > 2 && mod.norm > 0) {
        temp = SC_MALLOC(dn * sizeof(sc_ulimb_t));
        mpn_lshift(temp, d_limbs, dn, mod.norm);
        d_limbs = temp;
    }

    // Perform the division with the precomputed inverse
    mpn_div_qr_preinv(q_limbs, n_limbs, n, d_limbs, dn, &mod);

    // Free resources associated with divisor normalisation
    if (temp) {
        SC_FREE(temp, dn * sizeof(sc_ulimb_t));
    }
}

static sc_ulimb_t mpn_mul_gradeschool(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t in1_n, const sc_ulimb_t *in2, size_t in2_n)
{
    out[in1_n] = mpn_mul_1(out, in1, in1_n, *in2);
    while (--in2_n) {
        out++;
        in2++;
        out[in1_n] = mpn_addmul_1(out, in1, in1_n, *in2);
    }

    return out[in1_n - 1];
}

static sc_ulimb_t mpn_mul_karatsuba(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t in1_n, const sc_ulimb_t *in2, size_t in2_n)
{
#if 1
    mpn_mul_gradeschool(out, in1, in1_n, in2, in2_n);
#else
    size_t i, min_n, max_n;
    sc_ulimb_t *x0, *x1, *y0, *y1, *t1, *x0y0, *x1y1;
    const sc_ulimb_t *temp_a, *temp_b;

    // Determine the minimum number of limbs and divide by two
    min_n   = SC_MIN(in1_n, in2_n);
    min_n   = (min_n + 1) >> 1;
    max_n   = SC_MAX(in1_n, in2_n);
    max_n   = max_n - min_n;

    // Inialialise the temporary variables
    x0   = SC_MALLOC(sizeof(sc_ulimb_t) * (2 * max_n + 2));
    x1   = SC_MALLOC(sizeof(sc_ulimb_t) * (in1_n - min_n));
    y0   = SC_MALLOC(sizeof(sc_ulimb_t) * 4 * max_n);
    y1   = SC_MALLOC(sizeof(sc_ulimb_t) * (in2_n - min_n));
    t1   = SC_MALLOC(sizeof(sc_ulimb_t) * 4 * max_n);
    x0y0 = SC_MALLOC(sizeof(sc_ulimb_t) * (2 * min_n + 2));
    x1y1 = SC_MALLOC(sizeof(sc_ulimb_t) * (2 * max_n + 2));

    // Copy the lower half of in1 and in2 into x0 and y0
    temp_a = in1;
    temp_b = in2;
    for (i=0; i<min_n; i++) {
        x0[i] = *temp_a++;
        y0[i] = *temp_b++;
    }

    // Copy what remains of in1 into x1
    for (i=0; i<in1_n - min_n; i++) {
        x1[i] = *temp_a++;;
    }

    // Copy what remains of in2 into x2
    for (i=0; i<in2_n - min_n; i++) {
        y1[i] = *temp_b++;;
    }

    fprintf(stderr, "in1_n=%zu, in2_n=%zu, min_n=%zu\n", in1_n, in2_n, min_n);


#if 0
#define PRINT_KARATSUBA(s, x, n)
#else
#define PRINT_KARATSUBA(s, x, n) \
    fprintf(stderr, "%s", s); \
    for (i=0; i<n; i++) { \
        fprintf(stderr, "%016lX ", x[i]); \
    } \
    fprintf(stderr, "\n");
#endif


    PRINT_KARATSUBA("x0=", x0, min_n);
    PRINT_KARATSUBA("x1=", x1, in1_n - min_n);
    PRINT_KARATSUBA("y0=", y0, min_n);
    PRINT_KARATSUBA("y1=", y1, in2_n - min_n);

    // Determine the size of the lower halves x0 and y0 (for efficiency)

    // z0   = x0y0
    // z1   = (x1 + x0) * (y1 + y0)
    // z2   = x1y1
    // p    = z2*B**2 + (z1-z2-z0)*B + z0

    // x0y0 = x0 * y0
    mpn_mul(x0y0, x0, min_n, y0, min_n);
    PRINT_KARATSUBA("x0y0=", x0y0, 2*min_n);

    // x1y1 = x1 * y1
    if (in1_n >= in2_n) {
        mpn_mul(x1y1, x1, in1_n - min_n, y1, in2_n - min_n);
    }
    else {
        mpn_mul(x1y1, y1, in2_n - min_n, x1, in1_n - min_n);
    }
    PRINT_KARATSUBA("x1y1=", x1y1, in1_n + in2_n - 2*min_n);

    // t1   = x1 + x0
    if ((in1_n - min_n) >= min_n) {
        t1[in1_n - min_n] = mpn_add(t1, x1, in1_n - min_n, x0, min_n);
        PRINT_KARATSUBA("t1= x1 + x0 = ", t1, in1_n - min_n + 1);
    }
    else {
        t1[min_n] = mpn_add(t1, x0, min_n, x1, in1_n - min_n);
        PRINT_KARATSUBA("t1= x1 + x0 = ", t1, min_n+1);
    }

    // t0   = x0 = y1 + y0
    x0[min_n] = mpn_add(x0, y0, min_n, y1, in2_n - min_n);
    PRINT_KARATSUBA("t0=x0= y1 + y0 = ", x0, min_n+1);

    // t1   = y0 = (x1 + x0) * (y1 + y0)
    if ((in1_n - min_n) >= min_n) {
        mpn_mul(y0, t1, in1_n - min_n + 1, x0, min_n + 1);
        PRINT_KARATSUBA("y0=(x1 + x0) * (y1 + y0) = ", y0, in1_n + 1);
    }
    else {
        mpn_mul(y0, t1, min_n + 1, x0, min_n + 1);
        PRINT_KARATSUBA("y0=(x1 + x0) * (y1 + y0) = ", y0, 2*min_n+1);
    }

    // t2   = x0 = x0y0 + x1y1
    x0[SC_MAX(in1_n + in2_n - 2*min_n, 2*min_n)] = mpn_add(x0, x1y1, in1_n + in2_n - 2*min_n, x0y0, 2*min_n);
    PRINT_KARATSUBA("x0=x0y0 + x1y1 = ", x0, SC_MAX(in1_n + in2_n - 2*min_n, 2*min_n));

    // t1   = (x1 + x0) * (y1 + y0) - x0y0 - x1y1
    mpn_zero(t1, min_n);
    if ((in1_n - min_n) >= min_n) {
        mpn_sub(t1+min_n, y0, in1_n + 1, x0, SC_MAX(in1_n + in2_n - 2*min_n, 2*min_n));
        PRINT_KARATSUBA("t1= (x1 + x0) * (y1 + y0) - x0y0 - x1y1 = ", t1, in1_n + min_n + 1);

        // t1   = t1 + x0y0
        /*out[in1_n + min_n + 1] = */mpn_add(out, t1, in1_n + min_n + 1, x0y0, 2*min_n);
        PRINT_KARATSUBA("t1= t1 + x0y0 = ", out, in1_n + min_n);

        // out  = t1 + x1y1
        mpn_add(out+2*min_n, x1y1, in1_n + in2_n - 2*min_n, out+2*min_n, in1_n - min_n + 1);
        PRINT_KARATSUBA("out= t1 + x1y1 = ", out, in1_n + in2_n);
    }
    else {
        mpn_sub(t1+min_n, y0, 2*min_n + 1, x0, SC_MAX(in1_n + in2_n - 2*min_n, 2*min_n));
        PRINT_KARATSUBA("t1= (x1 + x0) * (y1 + y0) - x0y0 - x1y1 = ", t1, 3*min_n+1);

        // t1   = t1 + x0y0
        out[3*min_n+1] = mpn_add(out, t1, 3*min_n+1, x0y0, 2*min_n);
        PRINT_KARATSUBA("t1= t1 + x0y0 = ", out, 3*min_n+1);

        // out  = t1 + x1y1
        mpn_add(out+2*min_n, x1y1, in1_n + in2_n - 2*min_n, out+2*min_n, min_n+1);
        PRINT_KARATSUBA("out= t1 + x1y1 = ", out, in1_n + in2_n);
    }

    // Free resources associated with the temporary variables
    SC_FREE(x0,   sizeof(sc_ulimb_t) * (2 * max_n + 2));
    SC_FREE(x1,   sizeof(sc_ulimb_t) * (in1_n - min_n));
    SC_FREE(y0,   sizeof(sc_ulimb_t) * 4 * max_n);
    SC_FREE(y1,   sizeof(sc_ulimb_t) * (in2_n - min_n));
    SC_FREE(t1,   sizeof(sc_ulimb_t) * 4 * max_n);
    SC_FREE(x0y0, sizeof(sc_ulimb_t) * (2 * min_n + 2));
    SC_FREE(x1y1, sizeof(sc_ulimb_t) * (2 * max_n + 2));

    // Return the most significant word
    return out[in1_n + in2_n - 1];
#endif
}

sc_ulimb_t mpn_mul_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2)
{
    sc_ulimb_t h, l, carry;

    carry = 0;
    while (n--) {
        // Calculate the product
        limb_mul_hi_lo(&h, &l, *in1++, in2);

        // Add the carry word and update the carry using the MSW
        l     += carry;
        carry  = h + (l < carry);

        // Write the output word
        *out++ = l;
    }

    return carry;
}

void mpn_mul_n(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n)
{
    mpn_mul(out, in1, n, in2, n);
}

sc_ulimb_t mpn_mul(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t in1_n, const sc_ulimb_t *in2, size_t in2_n)
{
    // NOTE: It is guaranteed that in1_n >= in2_n

    if (in1 == in2 && in1_n == in2_n) {
        return mpn_sqr(out, in1, in1_n);
    }

    if (in2_n < 2*MPN_MUL_GRADESCHOOL_THRESH || ((in2_n + 1) >> 1) < MPN_MUL_GRADESCHOOL_THRESH) {
        return mpn_mul_gradeschool(out, in1, in1_n, in2, in2_n);
    }
    else {
        return mpn_mul_karatsuba(out, in1, in1_n, in2, in2_n);
    }
}

sc_ulimb_t mpn_sqr(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n)
{
    size_t in2_n = n;
    const sc_ulimb_t *in2 = in;

    out[n] = mpn_mul_1(out, in, n, *in);
    while (--in2_n) {
        out++;
        in2++;
        out[n] = mpn_addmul_1(out, in, n, *in2);
    }

    return out[n - 1];
}

#endif // USE_SAFECRYPTO_MULTIPLE_PRECISION

