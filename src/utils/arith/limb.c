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

#include "utils/arith/limb.h"
#include "utils/arith/limb_base.h"
#include "utils/arith/sc_math.h"
#include "safecrypto_types.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"
//#include "utils/third_party/libtommath-develop/tommath.h"

#include <math.h>
#include <assert.h>




// This requires platform-specific optimisation, this code is generic.
extern void udiv_qrnnd(sc_ulimb_t * const q, sc_ulimb_t * const r,
    sc_ulimb_t n1, sc_ulimb_t n0, sc_ulimb_t d);

extern void udiv_qrnnd_preinv(sc_ulimb_t * const q, sc_ulimb_t * const r,
    sc_ulimb_t n1, sc_ulimb_t n0, sc_ulimb_t d, sc_ulimb_t d_inv);

extern void udiv_qrnnndd_preinv(sc_ulimb_t * const q,
    sc_ulimb_t * const r1, sc_ulimb_t * const r0,
    sc_ulimb_t n2, sc_ulimb_t n1, sc_ulimb_t n0,
    sc_ulimb_t d1, sc_ulimb_t d0, sc_ulimb_t d_inv);

/// Addition of 2B integers, {s1,s0} = {a1,a0} + {b1,b0}
extern void limb_add_hi_lo(sc_ulimb_t * const s1, sc_ulimb_t * const s0,
    sc_ulimb_t a1, sc_ulimb_t a0,
    sc_ulimb_t b1, sc_ulimb_t b0);

/// Subtraction of 2B integers, {s1,s0} = {a1,a0} - {b1,b0}
extern void limb_sub_hi_lo(sc_ulimb_t * const s1, sc_ulimb_t * const s0,
    sc_ulimb_t a1, sc_ulimb_t a0,
    sc_ulimb_t b1, sc_ulimb_t b0);

/// Multiplication of 2B integers, {w1,w0} = u * v
extern void limb_mul_hi_lo(sc_ulimb_t * const w1, sc_ulimb_t * const w0,
	sc_ulimb_t u, sc_ulimb_t v);

/// Squaring of 2B integers, {w1,w0} = u * u
extern void limb_sqr_hi_lo(sc_ulimb_t * const w1, sc_ulimb_t * const w0,
	sc_ulimb_t u);

/// Modular reduction of 2B integers
/// @return {hi,lo} % mod->m
extern sc_ulimb_t limb_mod_reduction(sc_ulimb_t hi, sc_ulimb_t lo,
	const sc_ulimb_t m, const sc_ulimb_t m_inv);
extern sc_ulimb_t limb_mod_reduction_norm(sc_ulimb_t hi, sc_ulimb_t lo,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);

/// Modular reduction of 2B integers with normalisation
/// @{
extern sc_ulimb_t limb_mod_l(sc_ulimb_t lo,
	const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);
extern sc_ulimb_t limb_mod_ll(sc_ulimb_t hi, sc_ulimb_t lo,
	const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);
extern sc_ulimb_t limb_mod_lll(sc_ulimb_t hi, sc_ulimb_t mi, sc_ulimb_t lo,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);
/// @}

/// Negation of a limb variable modulo m
extern sc_ulimb_t limb_negate_mod(sc_ulimb_t x, const sc_ulimb_t m);

// Count the number of leading zero bits in a limb argument
extern SINT32 limb_clz(sc_ulimb_t n);

// Count the number of trailing zero bits in a limb argument
extern SINT32 limb_ctz(sc_ulimb_t n);

/// Modular addition modulo m
extern sc_ulimb_t limb_add_mod(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m);

/// Modular addition modulo m with normalisation
extern sc_ulimb_t limb_add_mod_norm(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m);

/// Modular subtraction modulo m
extern sc_ulimb_t limb_sub_mod(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m);

/// Modular subtraction modulo m with normalisation
extern sc_ulimb_t limb_sub_mod_norm(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m);

/// Modular multiplication modulo m using the preinverted m_inv
sc_ulimb_t limb_mul_mod(sc_ulimb_t a, sc_ulimb_t b,
    const sc_ulimb_t m, const sc_ulimb_t m_inv)
{
    sc_ulimb_t hi, lo;
    limb_mul_hi_lo(&hi, &lo, a, b);
    return limb_mod_reduction(hi, lo, m, m_inv);
}

sc_ulimb_t limb_sqr_mod(sc_ulimb_t a,
    const sc_ulimb_t m, const sc_ulimb_t m_inv)
{
    sc_ulimb_t hi, lo;
    limb_sqr_hi_lo(&hi, &lo, a);
    return limb_mod_reduction(hi, lo, m, m_inv);
}

sc_ulimb_t limb_mul_mod_norm(sc_ulimb_t a, sc_ulimb_t b,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    sc_ulimb_t q0, q1, r, p_hi, p_lo;

    a >>= norm;

    // Multiply, a * b
    limb_mul_hi_lo(&p_hi, &p_lo, a, b);

    // Reduce mod m
    limb_mul_hi_lo(&q1, &q0, m_inv, p_hi);
    limb_add_hi_lo(&q1, &q0, q1, q0, p_hi, p_lo);

    r  = (p_lo - (q1 + 1) * m);
    if (r >= q0) {
        r += m;
    }
    if (r >= m) {
        r -= m;
    }
    return r;
}

sc_ulimb_t limb_sqr_mod_norm(sc_ulimb_t a,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    sc_ulimb_t q0, q1, r, p_hi, p_lo;

    a >>= norm;

    // multiply
    limb_sqr_hi_lo(&p_hi, &p_lo, a);

    // reduce mod n
    limb_mul_hi_lo(&q1, &q0, m_inv, p_hi);
    limb_add_hi_lo(&q1, &q0, q1, q0, p_hi, p_lo);

    r  = (p_lo - (q1 + 1) * m);
    if (r >= q0) {
        r += m;
    }
    if (r >= m) {
        r -= m;
    }

    return r;
}

// Calculate the multiplicative inverse of x modulo y
sc_ulimb_t limb_inv_mod(sc_ulimb_t x, sc_ulimb_t y)
{
    sc_ulimb_t y0, quo, rem;
    sc_slimb_t t2;
    sc_slimb_t v1 = 0;
    sc_slimb_t v2 = 1;

    // If x > y then swap x and y, and v1 and v2
    if (x > y) {
        return limb_inv_mod(y, x);
    }

    y0 = y;

    // If x and y both have MSB set then swap and
    // scale the parameters
    if ((y & x) & (SC_LIMB_WORD(1) << (SC_LIMB_BITS-1))) {
        quo = y - x;
        y   = x;
        t2  = v2;
        v2  = v1 - v2;
        v1  = t2;
        x   = quo;
    }

    // Whilst the second value has second MSB set
    while (x & (SC_LIMB_WORD(1) << (SC_LIMB_BITS-2))) {
        quo = y - x;
        y   = x;
        t2  = v2;
        if (quo < x) {
            v2 = v1 - v2;
            x = quo;
        }
        else if (quo < (x << 1)) {
            v2 = v1 - (v2 << 1);
            x = quo - y;
        }
        else {
            v2 = v1 - 3 * v2;
            x = quo - (y << 1);
        }
        v1  = t2;
    }

    while (x) {
        if (y < (x << 2)) {
            quo = y - x;       // NOTE: Same as loop above
            y   = x;
            t2  = v2;
            if (quo < x) {
                v2 = v1 - v2;
                x = quo;
            }
            else if (quo < (x << 1)) {
                v2 = v1 - (v2 << 1);
                x = quo - y;
            }
            else {
                v2 = v1 - 3 * v2;
                x = quo - (y << 1);
            }
            v1  = t2;
        }
        else {
#if 1
            limb_udivrem(&quo, &rem, y, x);
#else
            quo = y / x;
            rem = y - x * quo;
#endif
            y   = x;
            t2  = v2;
            v2  = v1 - quo * v2;
            v1  = t2;
            x   = rem;
        }
    }

    // Ensure that the inverse is positive modulo y
    if (v1 < 0) {
        v1 += y0;
    }

    return v1;
}


extern sc_ulimb_t limb_inverse(sc_ulimb_t p);
extern sc_ulimb_t limb_inverse_3by2(sc_ulimb_t ph, sc_ulimb_t pl);

sc_ulimb_t limb_powmod2_ui(sc_ulimb_t a, sc_ulimb_t exp,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    sc_ulimb_t x;

    if (m == (SC_LIMB_WORD(1) << norm) || (a == 0 && exp != 0)) return SC_LIMB_WORD(0);

    x = SC_LIMB_WORD(1) << norm;

    if (exp) {
        while (0 == (exp & 1)) {
           a = limb_sqr_mod_norm(a, m, m_inv, norm);
           exp >>= 1;
        }

        if (a >= m) {
           x = limb_mod_l(a, m, m_inv, norm);
        }
        else {
           x = a;
        }

        while (exp >>= 1) {
            a = limb_sqr_mod_norm(a, m, m_inv, norm);
            if (exp & 1) {
                x = limb_mul_mod_norm(x, a, m, m_inv, norm);
            }
        }
    }

    return x;
}

sc_ulimb_t limb_powmod2(sc_ulimb_t a, sc_slimb_t exp,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    //sc_ulimb_t norm;
    if (exp < SC_LIMB_WORD(0)) {
        a = limb_inv_mod(a, m);
        exp = -exp;
    }

    //norm = limb_clz(m);
    return limb_powmod2_ui(a << norm, exp, m << norm, m_inv, norm) >> norm;
}

/// Initialise the modulus structure with all associated parameters
void limb_mod_init(sc_mod_t *mod, sc_ulimb_t m)
{
    mod->m      = m;
    mod->m_inv  = limb_inverse(m);
    mod->norm   = limb_clz(m);
    mod->b_norm = SC_LIMB_BITS - mod->norm;
}

/// Initialise the modulus structure with all associated parameters
/// For a double word modulus
void limb_mod_init_2(sc_mod_t *mod, sc_ulimb_t mh, sc_ulimb_t ml)
{
    mod->norm   = limb_clz(mh);
    mod->b_norm = SC_LIMB_BITS - mod->norm;
    if (mod->norm) {
        mh   = (mh << mod->norm) | (ml >> mod->b_norm);
        ml <<= mod->norm;
    }
    mod->m      = mh;
    mod->m_low  = ml;
    mod->m_inv  = limb_inverse_3by2(mh, ml);
}

sc_ulimb_t limb_gcd(sc_ulimb_t a, sc_ulimb_t b)
{
    // Swap a and b if b > a
    if (b > a) {
        return limb_gcd(b, a);
    }

    sc_ulimb_t s, quo, t;

    // Iteratively update the variables while b is non-zero
    while (1) {
        // Verify that b is non-zero
        if (0 == b) {
            goto finish;
        }

        quo = limb_udiv(a, b);
        t   = b * quo;
        s   = a - t;
        a   = b;
        b   = s;
    }

finish:
    return a;
}

sc_ulimb_t limb_xgcd(sc_ulimb_t a, sc_ulimb_t b, sc_ulimb_t *x, sc_ulimb_t *y)
{
    // Swap a and b if b > a
    if (b > a) {
        return limb_xgcd(b, a, y, x);
    }

    sc_ulimb_t old_x, old_y, quo, s;
    sc_ulimb_big_t t;
    *x    = 0;
    old_x = 1;
    *y    = 1;
    old_y = 0;

    // Iteratively update the variables while b is non-zero
    while (1) {
        // Verify that b is non-zero
        if (0 == b) {
            goto finish;
        }

        quo   = limb_udiv(a, b);
        t     = (sc_ulimb_big_t)b * (sc_ulimb_big_t)quo;
        s     = a - (sc_ulimb_t)t;
        a     = b;
        b     = s;

        s     = *x;
        t     = (sc_ulimb_big_t)quo * (sc_ulimb_big_t)(*x);
        *x    = old_x - (sc_ulimb_t)t;
        old_x = s;

        s     = *y;
        t     = (sc_ulimb_big_t)quo * (sc_ulimb_big_t)(*y);
        *y    = old_y - (sc_ulimb_t)t;
        old_y = s;
    }

finish:
    *x = old_x;
    *y = old_y;
    return a;
}

// Calculates the Binary Extended GCD such that u(2a) - vb = 1
// NOTE: a must be half of it's intended value, a MUST be even and b MUST be odd
void limb_binxgcd(sc_ulimb_t a, sc_ulimb_t b, sc_ulimb_t *x, sc_ulimb_t *y)
{
    sc_ulimb_t alpha, beta, u, v;
    u     = 1;
    v     = 0;
    alpha = a;
    beta  = b;
    
    // The invariant maintained from here on is: 2a = u*2*alpha - v*beta
    while (a > 0) {
        a >>= 1;
        if ((u & 1) == 0) {    // Remove a common factor of 2 in u and v
            u >>= 1;
            v >>= 1;
        }
        else {
            // Set u = (u + beta) >> 1, but that can overflow so care must be taken
            // This uses Dietz (see "Understanding Integer Overflow in C/C++", ICSE 2012)
            //u = ((u ^ beta) >> 1) + (u & beta);
            // This may be patented...
            u = (u >> 1) + (beta >> 1) + (u & beta & 1);
            v = (v >> 1) + alpha;
        }
    }
    *x = u;
    *y = v;
}
