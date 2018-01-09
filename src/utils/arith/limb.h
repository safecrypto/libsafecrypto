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

#pragma once
#include "safecrypto_types.h"
#include "safecrypto_private.h"
#include "utils/sampling/sampling.h"
#include "utils/arith/sc_math.h"
#include <string.h>

#include "utils/arith/sc_mp.h"


/// A typedef'd struct used to store a modulus and associated
/// magic inversion and norm
SC_STRUCT_PACK_START
typedef struct sc_mod_t {
    sc_ulimb_t m;
    sc_ulimb_t m_low;
    sc_ulimb_t m_inv;
    sc_ulimb_t norm;
    sc_ulimb_t b_norm;
} SC_STRUCT_PACKED sc_mod_t;
SC_STRUCT_PACK_END


/// Count the number of leading zero bits in a limb argument
SC_INLINE SINT32 limb_clz(sc_ulimb_t n)
{
#if SC_LIMB_BITS == 64
    return sc_clz_64(n);
#else
    return sc_clz_32(n);
#endif
}

/// Count the number of trailing zero bits in a limb argument
SC_INLINE SINT32 limb_ctz(sc_ulimb_t n)
{
#if SC_LIMB_BITS == 64
    return sc_ctz_64(n);
#else
    return sc_ctz_32(n);
#endif
}


/// {s1,s0} = {a1,a0} + {b1,b0}
SC_INLINE void limb_add_hi_lo(sc_ulimb_t * const s1, sc_ulimb_t * const s0,
                    sc_ulimb_t a1, sc_ulimb_t a0,
                    sc_ulimb_t b1, sc_ulimb_t b0)
{
    *s0 = a0 + b0;
    *s1 = a1 + b1 + (*s0 < a0);
}

/// {s1,s0} = {a1,a0} - {b1,b0}
SC_INLINE void limb_sub_hi_lo(sc_ulimb_t * const s1, sc_ulimb_t * const s0,
                    sc_ulimb_t a1, sc_ulimb_t a0,
                    sc_ulimb_t b1, sc_ulimb_t b0)
{
    *s1 = a1 - b1 - (a0 < b0);
    *s0 = a0 - b0;
}

SC_INLINE void limb_mul_add_hi_lo(sc_ulimb_t * const w1, sc_ulimb_t * const w0,
    sc_ulimb_t a1, sc_ulimb_t a0,
    sc_ulimb_t u, sc_ulimb_t v)
{
    // This will not auto-vectorise, but the number of instructions
    // saved and the speed of the multiply more than compensates. Using a
    // union to read the result also saves a shift.
    union u {
        sc_ulimb_t     result[2];
        sc_ulimb_big_t big;
    };
    union u t;
    t.result[0] = a0;
    t.result[1] = a1;
    t.big += (sc_ulimb_big_t) u * (sc_ulimb_big_t) v;
    *w1 = t.result[1];
    *w0 = t.result[0];
}

/// {w1,w0} = u * v
SC_INLINE void limb_mul_hi_lo(sc_ulimb_t * const w1, sc_ulimb_t * const w0,
    sc_ulimb_t u, sc_ulimb_t v)
{
#if defined(HAVE_128BIT)
    // This will not auto-vectorise, but the number of instructions
    // saved and the speed of the multiply more than compensates. Using a
    // union to read the result also saves a shift.
    union u {
        sc_ulimb_t     result[2];
        sc_ulimb_big_t big;
    };
    union u t;
	t.big = (sc_ulimb_big_t) u * (sc_ulimb_big_t) v;
	*w1 = t.result[1];
	*w0 = t.result[0];
#else
    // Half-word multiplies with integrated carry propagation to
    // save a few instructions, essentially identical to below
    sc_ulimb_t t0 = SC_LIMB_LOW(u) * SC_LIMB_LOW(v);
    sc_ulimb_t t1 = SC_LIMB_HIGH(u) * SC_LIMB_LOW(v) + SC_LIMB_HIGH(t0);
    sc_ulimb_t t2 = SC_LIMB_HIGH(v) * SC_LIMB_LOW(u) + SC_LIMB_LOW(t1);
    *w0  = SC_LIMB_B2(SC_LIMB_LOW(t2)) + SC_LIMB_LOW(t0);
    *w1  = SC_LIMB_HIGH(u) * SC_LIMB_HIGH(v);
    *w1 += SC_LIMB_HIGH(t2) + SC_LIMB_HIGH(t1);
#endif
}

/// {w1,w0} = u^2
SC_INLINE void limb_sqr_hi_lo(sc_ulimb_t * const w1, sc_ulimb_t * const w0,
    sc_ulimb_t u)
{
#if defined(HAVE_128BIT)
	union u {
        sc_ulimb_t     result[2];
        sc_ulimb_big_t big;
    };
    union u t;
    t.big = (sc_ulimb_big_t) u;
    t.big *= t.big;
    *w1 = t.result[1];
    *w0 = t.result[0];
#else
    sc_ulimb_t c  = SC_LIMB_HIGH(u) * SC_LIMB_LOW(u);
    sc_ulimb_t t0 = SC_LIMB_LOW(u) * SC_LIMB_LOW(u);
    sc_ulimb_t t1 = c + SC_LIMB_HIGH(t0);
    sc_ulimb_t t2 = c + SC_LIMB_LOW(t1);
    *w0 = SC_LIMB_B2(SC_LIMB_LOW(t2)) + SC_LIMB_LOW(t0);
    *w1 = SC_LIMB_HIGH(u) * SC_LIMB_HIGH(u);
    *w1 += SC_LIMB_HIGH(t2) + SC_LIMB_HIGH(t1);
#endif
}

/// This requires platform-specific optimisation, this code is generic.
SC_INLINE void udiv_qrnnd(sc_ulimb_t * const q, sc_ulimb_t * const r,
    sc_ulimb_t n1, sc_ulimb_t n0, sc_ulimb_t d)
{
    sc_ulimb_big_t n = ((sc_ulimb_big_t)n1 << SC_LIMB_BITS) | (sc_ulimb_big_t)n0;
    *q = n / d;
    *r = n % d;
}

SC_INLINE void udiv_qrnnd_preinv(sc_ulimb_t * const q, sc_ulimb_t * const r,
    sc_ulimb_t n1, sc_ulimb_t n0, sc_ulimb_t d, sc_ulimb_t d_inv)
{
    sc_ulimb_t h, l, mask;
    limb_mul_hi_lo(&h, &l, n1, d_inv);
    limb_add_hi_lo(&h, &l, h, l, n1 + 1, n0);
    *r = n0 - h * d;
    mask = -(sc_ulimb_t)(*r > l);
    h += mask;
    *r += mask & d;
    if (*r >= d) {
        *r -= d;
        h++;
    }
    *q = h;
}

SC_INLINE void udiv_qrnnndd_preinv(sc_ulimb_t * const q,
    sc_ulimb_t * const r1, sc_ulimb_t * const r0,
    sc_ulimb_t n2, sc_ulimb_t n1, sc_ulimb_t n0,
    sc_ulimb_t d1, sc_ulimb_t d0, sc_ulimb_t d_inv)
{
    sc_ulimb_t q0, t1, t0, mask;
    limb_mul_hi_lo(q, &q0, n2, d_inv);
    limb_add_hi_lo(q, &q0, *q, q0, n2, n1);

    *r1 = n1 - d1 * (*q);
    limb_sub_hi_lo(r1, r0, *r1, n0, d1, d0);
    limb_mul_hi_lo(&t1, &t0, d0, *q);
    limb_sub_hi_lo(r1, r0, *r1, *r0, t1, t0);
    *q = *q + 1;

    mask = -(sc_ulimb_t)(*r1 >= q0);
    *q += mask;
    limb_add_hi_lo(r1, r0, *r1, *r0, mask & d1, mask & d0);
    if (*r1 >= d1) {
        if (*r1 > d1 || *r0 >= d0) {
            *q = *q + 1;
            limb_sub_hi_lo(r1, r0, *r1, *r0, d1, d0);
        }
    }
}

// Compute invx = (B^2 - B*x - 1)/x = (B^2 - 1)/x - B
// If m = 1/x = B + invx, then m*x = B^2 - 1
// Therefore, q1*B + q0 = n2*B + n2(m-B) = n2*B + n2*(invx)
SC_INLINE sc_ulimb_t limb_inverse(sc_ulimb_t p)
{
    sc_ulimb_t inv, dummy;
    sc_ulimb_t lz = limb_clz(p);
    p <<= lz;
    udiv_qrnnd(&inv, &dummy, ~p, SC_LIMB_MASK, p);
    return inv;
}

// Compute invx = floor((B^3 - 1)/(Bx1 + x0)) - B
SC_INLINE sc_ulimb_t limb_inverse_3by2(sc_ulimb_t ph, sc_ulimb_t pl)
{   
    sc_ulimb_half_t mh, ml, qh, ql;
    sc_ulimb_t prod, rem, m;

    // Split the high word into two using the half-limb base b
    // i.e. ph = b * mh + ml
    mh   = ph >> SC_LIMB_BITS2;
    ml   = ph & SC_LIMB_MASK_LOW;

    // Approximate the high half of the quotient
    qh   = ~ph / mh;

    // Get the upper half-limb 3/2 inverse
    //  qh  = floor((b^3 - 1) / (b*mh + ml)) - b
    //      = floor((b^3 - 1) / ph) - b
    //      = floor((b^3 - b*ph - 1) / ph)
    //      = floor((b(b^2 - ph) - 1) / ph)
    //      = floor((b(~ph + 1) - 1) / ph)
    //  rem = b(~ph) + b - 1 - qh * ph
    //      = b(~ph) + b - 1 - qh(b*mh + ml)
    //      = b(~ph - qh*mh) - qh*ml + b - 1
    prod = (sc_ulimb_t) qh * mh;
    rem  = ((~ph - prod) << SC_LIMB_BITS2) | SC_LIMB_MASK_LOW;
    prod = (sc_ulimb_t) qh * ml;

    // Adjustment by at most 2
    if (rem < prod) {
        qh--;
        rem += ph;

        // Check if carry was omitted and adjust
        if (rem >= ph && rem < prod) {
            qh--;
            rem += ph;
        }
    }
    rem -= prod;

    // Obtain the low half of the quotient
    //  ql = floor((b*rem + b - 1) / ph)
    prod = (rem >> SC_LIMB_BITS2) * qh + rem;
    ql   = (prod >> SC_LIMB_BITS2) + 1;
    rem  = (rem << SC_LIMB_BITS2) + SC_LIMB_MASK_LOW - ql * ph;
    if (rem >= (prod << SC_LIMB_BITS2)) {
        ql--;
        rem += ph;
    }
    m = ((sc_ulimb_t) qh << SC_LIMB_BITS2) + ql;
    if (rem >= ph) {
        m++;
        rem -= ph;
    }

    // Convert the 2/1 inverse of ph to a 3/2 inverse of B*ph + pl
    if (pl) {
        sc_ulimb_t pm1, pm0;
        rem = ~rem + pl;
        if (rem < pl) {
            m--;
            if (rem >= ph) {
                m--;
                rem -= ph;
            }
            rem -= ph;
        }
        limb_mul_hi_lo(&pm1, &pm0, pl, m);
        rem += pm1;
        if (rem < pm1) {
            m--;
            m -= (rem > ph) | ((rem == ph) & (pm0 > pl));
        }
    }

    return m;
}

SC_INLINE sc_ulimb_t limb_mod_reduction(sc_ulimb_t hi, sc_ulimb_t lo,
    const sc_ulimb_t m, const sc_ulimb_t m_inv)
{
    sc_ulimb_t q0, q1, r;
    limb_mul_hi_lo(&q1, &q0, m_inv, hi);
    limb_add_hi_lo(&q1, &q0, q1, q0, hi, lo);
    r  = lo - (q1 + 1) * m;
    if (r >= q0) {
    	r += m;
    }
    if (r >= m) {
    	r -= m;
    }
    return r;
}

SC_INLINE sc_ulimb_t limb_mod_reduction_norm(sc_ulimb_t hi, sc_ulimb_t lo,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    sc_ulimb_t q0, q1, r, r1;
    const sc_ulimb_t u1 = SC_LIMB_LSHIFT(hi, norm) +
                          SC_LIMB_RSHIFT(lo, SC_LIMB_BITS - norm);
    const sc_ulimb_t u0 = SC_LIMB_LSHIFT(lo, norm);
    const sc_ulimb_t mn = SC_LIMB_LSHIFT(m, norm);
    limb_mul_hi_lo(&q1, &q0, m_inv, u1);
    limb_add_hi_lo(&q1, &q0, q1, q0, u1, u0);
    r1  = u0 - (q1 + 1) * mn;
    if (r1 >= q0) {
        r1 += mn;
    }
    if (r1 >= mn) {
        r1 -= mn;
    }
    r   = SC_LIMB_RSHIFT(r1, norm);
    return r;
}

SC_INLINE sc_ulimb_t limb_mod_l(sc_ulimb_t lo,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    sc_ulimb_t q0, q1, r;
    sc_ulimb_t u1, u0;

    sc_ulimb_t mn = SC_LIMB_LSHIFT(m, norm);

    u1 = SC_LIMB_RSHIFT(lo, SC_LIMB_BITS - norm);
    u0 = SC_LIMB_LSHIFT(lo, norm);
    limb_mul_hi_lo(&q1, &q0, m_inv, u1);
    limb_add_hi_lo(&q1, &q0, q1, q0, u1, u0);

    r  = u0 - (q1 + 1) * mn;
    if (r >= q0) {
        r += mn;
    }
    if (r >= mn) {
    	r -= mn;
    }

    return SC_LIMB_RSHIFT(r, norm);
}

SC_INLINE sc_ulimb_t limb_mod_ll(sc_ulimb_t hi, sc_ulimb_t lo,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    sc_ulimb_t q0, q1, r;
    sc_ulimb_t u1, u0;

    sc_ulimb_t mn = SC_LIMB_LSHIFT(m, norm);

    if (hi >= m)
    {
        u1 = SC_LIMB_RSHIFT(hi, SC_LIMB_BITS - norm);
        u0 = SC_LIMB_LSHIFT(hi, norm);

        limb_mul_hi_lo(&q1, &q0, m_inv, u1);
        limb_add_hi_lo(&q1, &q0, q1, q0, u1, u0);

        r = (u0 - (q1 + 1) * mn);

        if (r >= q0) {
            r += mn;
        }

        if (r < mn) {
            hi = r >> norm;
        }
        else {
            hi = (r - mn) >> norm;
        }
    }

    u1 = SC_LIMB_LSHIFT(hi, norm) + SC_LIMB_RSHIFT(lo, SC_LIMB_BITS - norm);
    u0 = SC_LIMB_LSHIFT(lo, norm);
    limb_mul_hi_lo(&q1, &q0, m_inv, u1);
    limb_add_hi_lo(&q1, &q0, q1, q0, u1, u0);

    r = u0 - (q1 + 1) * m;

    if (r >= q0) {
        r += m;
    }
    if (r >= mn) {
    	r -= mn;
    }

    return SC_LIMB_RSHIFT(r, norm);
}

SC_INLINE sc_ulimb_t limb_mod_lll(sc_ulimb_t hi, sc_ulimb_t mi, sc_ulimb_t lo,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm)
{
    sc_ulimb_t q0, q1, r;
    sc_ulimb_t u1, u0;

    sc_ulimb_t mn = SC_LIMB_LSHIFT(m, norm);

    u1 = SC_LIMB_LSHIFT(hi, norm) + SC_LIMB_RSHIFT(mi, SC_LIMB_BITS - norm);
    u0 = SC_LIMB_LSHIFT(mi, norm);

    limb_mul_hi_lo(&q1, &q0, m_inv, u1);
    limb_add_hi_lo(&q1, &q0, q1, q0, u1, u0);

    r = (u0 - (q1 + 1) * m);

    if (r >= q0) {
        r += mn;
    }

    if (r < mn) {
        mi = r >> norm;
    }
    else {
        mi = (r - mn) >> norm;
    }

    u1 = SC_LIMB_LSHIFT(mi, norm) + SC_LIMB_RSHIFT(lo, SC_LIMB_BITS - norm);
    u0 = SC_LIMB_LSHIFT(lo, norm);

    limb_mul_hi_lo(&q1, &q0, m_inv, u1);
    limb_add_hi_lo(&q1, &q0, q1, q0, u1, u0);

    r = (u0 - (q1 + 1) * m);

    if (r >= q0) {
        r += mn;
    }
    if (r >= mn) {
    	r -= mn;
    }

    return SC_LIMB_RSHIFT(r, norm);
}

SC_INLINE sc_ulimb_t limb_negate_mod(sc_ulimb_t x, const sc_ulimb_t m)
{
#if 0
    return (0 != x) * (m -x);
#else
    if (x) {
        return m - x;
    }
    else {
        return 0;
    }
#endif
}


SC_INLINE sc_ulimb_t limb_add_mod(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m)
{
    // NOTE: Assumes a and b are modulo m!
    sc_ulimb_t hi, lo;
    limb_add_hi_lo(&hi, &lo, 0, a, 0, b);
    if (hi || (0 == hi && lo >= m)) {
        limb_sub_hi_lo(&hi, &lo, hi, lo, 0, m);
    }
    return lo;
}

SC_INLINE sc_ulimb_t limb_add_mod_norm(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m)
{
    sc_ulimb_t sum = a + b;
    return sum - m + (((sum - m) >> (SC_LIMB_BITS-1)) & m);
}

SC_INLINE sc_ulimb_t limb_sub_mod(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m)
{
    // NOTE: Assumes a and b are modulo m!
    // Subtract b from a, ensuring that the result lies within 0 to m
    return a - b + (b > a) * m;
}

SC_INLINE sc_ulimb_t limb_sub_mod_norm(sc_ulimb_t a, sc_ulimb_t b, const sc_ulimb_t m)
{
    sc_ulimb_t diff = a - b;
    return ((diff >> (SC_LIMB_BITS-1)) & m) + diff;
}

sc_ulimb_t limb_mul_mod(sc_ulimb_t a, sc_ulimb_t b,
    const sc_ulimb_t m, const sc_ulimb_t m_inv);
sc_ulimb_t limb_sqr_mod(sc_ulimb_t a,
    const sc_ulimb_t m, const sc_ulimb_t m_inv);
sc_ulimb_t limb_mul_mod_norm(sc_ulimb_t a, sc_ulimb_t b,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);
sc_ulimb_t limb_sqr_mod_norm(sc_ulimb_t a,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);

sc_ulimb_t limb_powmod2_ui(sc_ulimb_t a, sc_ulimb_t exp,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);

sc_ulimb_t limb_powmod2(sc_ulimb_t a, sc_slimb_t exp,
    const sc_ulimb_t m, const sc_ulimb_t m_inv, const sc_ulimb_t norm);

// Calculate the multiplicative inverse of x modulo y
sc_ulimb_t limb_inv_mod(sc_ulimb_t x, sc_ulimb_t y);

/// Initialise the modulus structure with all associated parameters
void limb_mod_init(sc_mod_t *mod, sc_ulimb_t m);

/// Initialise the modulus structure with all associated parameters
/// For a double word modulus
void limb_mod_init_2(sc_mod_t *mod, sc_ulimb_t mh, sc_ulimb_t ml);

sc_ulimb_t limb_gcd(sc_ulimb_t a, sc_ulimb_t b);
sc_ulimb_t limb_xgcd(sc_ulimb_t a, sc_ulimb_t b, sc_ulimb_t *x, sc_ulimb_t *y);
void limb_binxgcd(sc_ulimb_t a, sc_ulimb_t b, sc_ulimb_t *x, sc_ulimb_t *y);
