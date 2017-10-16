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

#include "utils/arith/limb_base.h"
#include "utils/arith/sc_math.h"
#include "safecrypto_types.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"



UINT32 mont_umul32(UINT32 abar, UINT32 bbar, UINT32 m, UINT32 mprime)
{
    UINT32 thi, tlo, tmmhi, tmmlo, uhi, ulo, tm, overflow;

    // t = abar * bbar
    umul32(&thi, &tlo, abar, bbar);

    // u = (t + ((t * mprime) & mask) * m) >> 64
    tm = tlo * mprime;             // The 64-bit mask means only the low order
                                   // 64 bits of t * mprime are required
    umul32(&tmmhi, &tmmlo, tm, m); // tmm = tm * m
    ulo = tlo + tmmlo;             // 128-bit addition of t and tmm
    uhi = thi + tmmhi;
    if (ulo < tlo) {
        uhi++;                     // Propagate the carry
    }

    // Detect overflow
    overflow = (uhi < thi) || ((uhi == thi) && (ulo < tlo));

    // A 64-bit shift of u results in uhi becoming ulo, followed by a
    // range check
    if (overflow > 0 || uhi >= m) {
        uhi -= m;
    }

    // Return the result
    return uhi;
}

#if SC_LIMB_BITS == 64
void umul32(UINT32 *hi, UINT32 *lo, UINT32 u, UINT32 v)
{
    UINT64 p = (UINT64) u * (UINT64) v;
    *hi  = p >> 32;
    *lo  = p & 0xFFFFFFFF;
}

void umul64(UINT64 *hi, UINT64 *lo, UINT64 u, UINT64 v)
{
    UINT64 ulo, uhi, vlo, vhi, t0, t1, t2;
    ulo = u & 0xFFFFFFFF;
    uhi = u >> 32;
    vlo = v & 0xFFFFFFFF;
    vhi = v >> 32;
    t0  = ulo * vlo;
    t1  = uhi * vlo + (t0 >> 32);
    t2  = vhi * ulo + (t1 & 0xFFFFFFFF);
    *lo = ((t2 & 0xFFFFFFFF) << 32) + (t0 & 0xFFFFFFFF);
    *hi = uhi * vhi + (t2 >> 32) + (t1 >> 32);
}

UINT64 mont_umul64(UINT64 abar, UINT64 bbar, UINT64 m, UINT64 mprime)
{
    UINT64 thi, tlo, tmmhi, tmmlo, uhi, ulo, tm, overflow;

    // t = abar * bbar
    umul64(&thi, &tlo, abar, bbar);

    // u = (t + ((t * mprime) & mask) * m) >> 64
    tm = tlo * mprime;             // The 64-bit mask means only the low order
                                   // 64 bits of t * mprime are required
    umul64(&tmmhi, &tmmlo, tm, m); // tmm = tm * m
    ulo = tlo + tmmlo;             // 128-bit addition of t and tmm
    uhi = thi + tmmhi;
    if (ulo < tlo) {
        uhi++;                     // Propagate the carry
    }

    // Detect overflow
    overflow = (uhi < thi) || ((uhi == thi) && (ulo < tlo));

    // A 64-bit shift of u results in uhi becoming ulo, followed by a
    // range check
    if (overflow > 0 || uhi >= m) {
        uhi -= m;
    }

    // Return the result
    return uhi;
}

UINT32 udiv32(UINT32 n, UINT32 d)
{
    return n / d;
}

UINT32 urem32(UINT32 n, UINT32 d)
{
    return n % d;
}

UINT32 umod32(UINT32 n1, UINT32 n0, UINT32 d)
{
    UINT64 n = ((UINT64)n1 << 32) | (UINT64)n0;
    return (UINT32)(n / d);
}

void udivrem32(UINT32 *q, UINT32 *r, UINT32 n, UINT32 d)
{
    *q = n / d;
    *r = n % d;
}

UINT64 udiv64(UINT64 n, UINT64 d)
{
    return n / d;
}

UINT64 urem64(UINT64 n, UINT64 d)
{
    return n % d;
}

UINT64 umod64(UINT64 n1, UINT64 n0, UINT64 d)
{
#ifdef HAVE_128BITS
    UINT128 n = ((UINT128)n1 << 64) | (UINT128)n0;
    return (UINT64)(n % d);
#else
    size_t i;
    SINT64 t;
    for (i=64; i--;) {
        t  = (SINT64) n1 >> 63;
        n1 = (n1 << 1) | (n0 >> 63);
        n0 <<= 1;
        if ((n1 | t) >= d) {
            n1 -= d;
            n0++;
        }
    }
    return n1;
#endif
}

void udivrem64(UINT64 *q, UINT64 *r, UINT64 n, UINT64 d)
{
    *q = n / d;
    *r = n % d; /// @todo Check if faster than *r = n - d * (*q)
}

#else

void umul32(UINT32 *hi, UINT32 *lo, UINT32 u, UINT32 v)
{
    UINT32 ulo = (u & 0xFFFF);
    UINT32 uhi = (u >> 16);
    UINT32 vlo = (v & 0xFFFF);
    UINT32 vhi = (v >> 16);
    UINT32 t0 = ulo * vlo;
    UINT32 t1 = uhi * vlo + (t0 >> 16);
    UINT32 t2 = vhi * ulo + (t1 & 0xFFFF);
    *lo  = ((t2 & 0xFFFF) << 16) + (t0 & 0xFFFF);
    *hi  = uhi * vhi + (t2 >> 16) + (t1 >> 16);
}

void umul64(UINT64 *hi, UINT64 *lo, UINT64 u, UINT64 v)
{
    UINT64 ulo = (u & 0xFFFFFFFF);
    UINT64 uhi = (u >> 32);
    UINT64 vlo = (v & 0xFFFFFFFF);
    UINT64 vhi = (v >> 32);
    UINT32 t0_lo, t0_hi, t1_lo, t1_hi, t2_lo, t2_hi, hi_lo, hi_hi;
    umul32(&t0_hi, &t0_lo, ulo, vlo);
    umul32(&t1_hi, &t1_lo, uhi, vlo);
    umul32(&t2_hi, &t2_lo, ulo, vhi);
    umul32(&hi_hi, &hi_lo, uhi, vhi);
    UINT64 t1 = ((UINT64)t1_hi << 32) + t1_lo + t0_hi;
    UINT64 t2 = ((UINT64)t2_hi << 32) + t2_lo + t1_lo;
    *lo  = ((t2 & 0xFFFFFFFF) << 32) + t0_lo;
    *hi  = ((UINT64)hi_hi << 32) + hi_lo + (t2 >> 32) + (t1 >> 32);
}

UINT32 udiv32(UINT32 n, UINT32 d)
{
    return n / d;
}

UINT32 urem32(UINT32 n, UINT32 d)
{
    return n % d;
}

UINT32 umod32(UINT32 n1, UINT32 n0, UINT32 d)
{
    size_t i;
    SINT32 t;
    for (i=32; i--;) {
        t  = (SINT32) n1 >> 31;
        n1 = (n1 << 1) | (n0 >> 31);
        n0 <<= 1;
        if ((n1 | t) >= d) {
            n1 -= d;
            n0++;
        }
    }
    return n1;
}

void udivrem32(UINT32 *q, UINT32 *r, UINT32 n, UINT32 d)
{
    *q = n / d;
    *r = n % d; /// @todo Check if faster than *r = n - d * (*q)
}

static SC_INLINE UINT32 divl(UINT64 n, UINT32 d)
{
    UINT32 q  = n / d;
    return q;
}

UINT64 udiv64(UINT64 n, UINT64 d)
{
    if ((d >> 32) == 0) {
        UINT64 b = 1ULL << 32;
        UINT32 n1 = n >> 32;
        UINT32 n0 = n; 
        UINT32 d0 = d;

        return divl(b * (n1 % d0) + n0, d0) + b * (n1 / d0); 
    }
    else {
        // Based on the algorithm and proof available from
        // http://www.hackersdelight.org/revisions.pdf.
        if (n < d) {
            return 0;
        }
        else {
            UINT32 d1 = d >> 32;
            SINT32 s = sc_clz_32(d1);
            UINT64 q = divl(n >> 1, (d << s) >> 32) >> (31 - s);
            return n - (q - 1) * d < d ? q - 1 : q; 
        }
    }
}

UINT64 urem64(UINT64 n, UINT64 d)
{
    return n - d * udiv64(n, d);
}

UINT64 umod64(UINT64 n1, UINT64 n0, UINT64 d)
{
    size_t i;
    SINT64 t;
    for (i=64; i--;) {
        t  = (SINT64) n1 >> 63;
        n1 = (n1 << 1) | (n0 >> 63);
        n0 <<= 1;
        if ((n1 | t) >= d) {
            n1 -= d;
            n0++;
        }
    }
    return n1;
}

void udivrem64(UINT64 *q, UINT64 *r, UINT64 n, UINT64 d)
{
    *q = udiv64(n, d);
    *r = n - d * (*q);
}

#endif



#if SC_LIMB_BITS == 64

sc_ulimb_t limb_udiv(sc_ulimb_t n, sc_ulimb_t d)
{
    return udiv64(n, d);
}

sc_ulimb_t limb_urem(sc_ulimb_t n, sc_ulimb_t d)
{
    return urem64(n, d);
}

sc_ulimb_t limb_umod(sc_ulimb_t n1, sc_ulimb_t n0, sc_ulimb_t d)
{
    return umod64(n1, n0, d);
}

void limb_udivrem(sc_ulimb_t *q, sc_ulimb_t *r, sc_ulimb_t n, sc_ulimb_t d)
{
    udivrem64(q, r, n, d);
}

void limb_umul(sc_ulimb_t *hi, sc_ulimb_t *lo, sc_ulimb_t u, sc_ulimb_t v)
{
    umul64(hi, lo, u, v);
}

sc_ulimb_t limb_mont_mul(sc_ulimb_t abar, sc_ulimb_t bbar, sc_ulimb_t m, sc_ulimb_t mprime)
{
    return mont_umul64(abar, bbar, m, mprime);
}

#else

sc_ulimb_t limb_udiv(sc_ulimb_t n, sc_ulimb_t d)
{
    return udiv32(n, d);
}

sc_ulimb_t limb_urem(sc_ulimb_t n, sc_ulimb_t d)
{
    return urem32(n, d);
}

sc_ulimb_t limb_umod(sc_ulimb_t n1, sc_ulimb_t n0, sc_ulimb_t d)
{
    return umod32(n1, n0, d);
}

void limb_udivrem(sc_ulimb_t *q, sc_ulimb_t *r, sc_ulimb_t n, sc_ulimb_t d)
{
    UINT32 quo, rem;
    udivrem32(&quo, &rem, n, d);
    *q = quo;
    *r = rem;
}

void limb_umul(sc_ulimb_t *hi, sc_ulimb_t *lo, sc_ulimb_t u, sc_ulimb_t v)
{
    umul32(hi, lo, u, v);
}

sc_ulimb_t limb_mont_mul(sc_ulimb_t abar, sc_ulimb_t bbar, sc_ulimb_t m, sc_ulimb_t mprime)
{
    return mont_umul32(abar, bbar, m, mprime);
}

#endif
