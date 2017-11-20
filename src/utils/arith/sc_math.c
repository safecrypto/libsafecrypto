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

#include <stdio.h>
#include "sc_math.h"
#include <math.h>


//-------------------------- Constant-time comparison -------------------------//

#if NATIVE_WORD_SIZE == 64
volatile SINT32 sc_const_time_lessthan(volatile UINT64 a, volatile UINT64 b)
{
    return ((((a ^ b) & ((a - b) ^ b)) ^ (a - b)) & 0x8000000000000000L) >> 63;
}
#else
volatile SINT32 sc_const_time_lessthan(volatile UINT32 a, volatile UINT32 b)
{
    return ((((a ^ b) & ((a - b) ^ b)) ^ (a - b)) & 0x80000000) >> 31;
}
#endif


//------------------------------ Range limiting -------------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
SINT128 sc_mod_limit_s128(SINT128 x, SINT128 q)
{
#if defined(GNU_GCC_COMPILER) && (__STDC_VERSION__ >= 199901L)
    x -= (x >= q) * q;
    x += (x <= -q) * q;
#else
    if (x >= q) {
        x -= q;
    }
    if (x <= -q) {
        x += q;
    }
#endif
    return x;
}

#endif
#ifdef HAVE_64BIT
SINT64 sc_mod_limit_s64(SINT64 x, SINT64 q)
{
#if defined(GNU_GCC_COMPILER) && (__STDC_VERSION__ >= 199901L)
    x -= (x >= q) * q;
    x += (x <= -q) * q;
#else
    if (x >= q) {
        x -= q;
    }
    if (x <= -q) {
        x += q;
    }
#endif
    return x;
}

#endif
SINT32 sc_mod_limit_s32(SINT32 x, SINT32 q)
{
#if defined(GNU_GCC_COMPILER) && (__STDC_VERSION__ >= 199901L)
    x -= (x >= q) * q;
    x += (x <= -q) * q;
#else
    if (x >= q) {
        x -= q;
    }
    if (x <= -q) {
        x += q;
    }
#endif
    return x;
}

SINT16 sc_mod_limit_s16(SINT16 x, SINT16 q)
{
#if defined(GNU_GCC_COMPILER) && (__STDC_VERSION__ >= 199901L)
    x -= (x >= q) * q;
    x += (x <= -q) * q;
#else
    if (x >= q) {
        x -= q;
    }
    if (x <= -q) {
        x += q;
    }
#endif
    return x;
}

SINT8 sc_mod_limit_s8(SINT8 x, SINT8 q)
{
#if defined(GNU_GCC_COMPILER) && (__STDC_VERSION__ >= 199901L)
    x -= (x >= q) * q;
    x += (x <= -q) * q;
#else
    if (x >= q) {
        x -= q;
    }
    if (x <= -q) {
        x += q;
    }
#endif
    return x;
}



//---------------------------------- Math functions -----------------------------------//


// NOTE: M_LN2 (log_e 2) is defined in math.h as 0.69314718055994530942

// See Nicol N. Schraudolph: A Fast, Compact Approximation of the Exponential Function
// http://nic.schraudolph.org/pubs/Schraudolph99.pdf
#define DBL_EXP_A (0x100000 / M_LN2)
#define DBL_EXP_C (0x3FF00000 - 45799)//60801)
DOUBLE sc_exp_dbl_coarse(DOUBLE y) {
    union
    {
        DOUBLE d;
        struct
        {
#ifdef LITTLE_ENDIAN
            SINT32 j, i;
#else
            SINT32 i, j;
#endif
        } n;
    } eco;

    eco.n.i = DBL_EXP_A*(y) + DBL_EXP_C;
    eco.n.j = 0;
    return eco.d;
}


#define FLT_EXP_A (0x80 / M_LN2)
#define FLT_EXP_C (0x3FF0 - 512)
FLOAT sc_exp_flt_coarse(FLOAT y)
{
    static union
    {
        FLOAT d;
        struct
        {
#ifdef LITTLE_ENDIAN
            SINT16 j, i;
#else
            SINT16 i, j;
#endif
        } n;
    } eco;

    eco.n.i = FLT_EXP_A*(y) + FLT_EXP_C;
    eco.n.j = 0;
    return eco.d;
}


FLOAT sc_pow_estimate_flt(FLOAT a, FLOAT b)
{
    SINT16 e = (SINT16) b;
    union {
        FLOAT d;
        SINT16 x[2];
    } u = { a };
    u.x[1] = (SINT16)((b - e) * (u.x[1] - FLT_EXP_C) + FLT_EXP_C);
    u.x[0] = 0;

    // exponentiation by squaring with the exponent's integer part
    // double r = u.d makes everything much slower, not sure why
    FLOAT r = 1.0;
    while (e) {
        if (e & 1) {
            r *= a;
        }
        a *= a;
        e >>= 1;
    }

    return r * u.d;
}


DOUBLE sc_pow_estimate_dbl(DOUBLE a, DOUBLE b)
{
    SINT32 e = (SINT32) b;
    union {
        DOUBLE d;
        SINT32 x[2];
    } u = { a };
    u.x[1] = (SINT32)((b - e) * (u.x[1] - DBL_EXP_C) + DBL_EXP_C);
    u.x[0] = 0;

    // exponentiation by squaring with the exponent's integer part
    // double r = u.d makes everything much slower, not sure why
    DOUBLE r = 1.0;
    while (e) {
        if (e & 1) {
            r *= a;
        }
        a *= a;
        e >>= 1;
    }

    return r * u.d;
}

DOUBLE factorial_lut_dbl[16] = {
    1,
    1,
    (DOUBLE)1 / (DOUBLE)2,
    (DOUBLE)1 / (DOUBLE)6,
    (DOUBLE)1 / (DOUBLE)24,
    (DOUBLE)1 / (DOUBLE)120,
    (DOUBLE)1 / (DOUBLE)720,
    (DOUBLE)1 / (DOUBLE)5040,
    (DOUBLE)1 / (DOUBLE)40320,
    (DOUBLE)1 / (DOUBLE)362880,
    (DOUBLE)1 / (DOUBLE)3628800,
    (DOUBLE)1 / (DOUBLE)39916800,
    (DOUBLE)1 / (DOUBLE)479001600,
    (DOUBLE)1 / (DOUBLE)1932053504,
    (DOUBLE)1 / (DOUBLE)1278945280,
    (DOUBLE)1 / (DOUBLE)2004310016
};

FLOAT factorial_lut_flt[16] = {
    1,
    1,
    (FLOAT)1 / (FLOAT)2,
    (FLOAT)1 / (FLOAT)6,
    (FLOAT)1 / (FLOAT)24,
    (FLOAT)1 / (FLOAT)120,
    (FLOAT)1 / (FLOAT)720,
    (FLOAT)1 / (FLOAT)5040,
    (FLOAT)1 / (FLOAT)40320,
    (FLOAT)1 / (FLOAT)362880,
    (FLOAT)1 / (FLOAT)3628800,
    (FLOAT)1 / (FLOAT)39916800,
    (FLOAT)1 / (FLOAT)479001600,
    (FLOAT)1 / (FLOAT)1932053504,
    (FLOAT)1 / (FLOAT)1278945280,
    (FLOAT)1 / (FLOAT)2004310016
};

DOUBLE sc_exp_dbl_taylor(DOUBLE y)
{
    SINT32 n = 0;
    DOUBLE taylor = 0;

    DOUBLE *f = factorial_lut_dbl;
    while (n < 8) {
        taylor += ((sc_pow_estimate_dbl(y, n)) * *f++);
        n++;
    }

    return taylor;
}

FLOAT sc_exp_flt_taylor(FLOAT y)
{
    SINT32 n = 0;
    FLOAT taylor = 0;

    FLOAT *f = factorial_lut_flt;
    while (n < 8) {
        taylor += ((sc_pow_estimate_flt(y, n)) * *f++);
        n++;
    }

    return taylor;
}


//------------------------------- LOG BASE 2 --------------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT32 sc_log2_128(UINT128 x)
{
#ifdef HAVE___BUILTIN_CLZ
    UINT64 data = x >> 64;
    if (!data) {
        return sc_log2_64((UINT64)x);
    }
    else {
        return 64 + sc_log2_64(data);
    }
#else
    UINT32 r, shift;
    r =     (x > 0xFFFFFFFFFFFFFFFF) << 6; x >>= r;
    shift = (x > 0xFFFFFFFF        ) << 5; x >>= shift; r |= shift;
    shift = (x > 0xFFFF            ) << 4; x >>= shift; r |= shift;
    shift = (x > 0xFF              ) << 3; x >>= shift; r |= shift;
    shift = (x > 0xF               ) << 2; x >>= shift; r |= shift;
    shift = (x > 0x3               ) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
#endif
}
#endif

#ifdef HAVE_64BIT
UINT32 sc_log2_64(UINT64 x)
{
#if 0//def HAVE___BUILTIN_CLZLL
    return 63 - __builtin_clzll(x) + (x == 0);
#else
    UINT32 r, shift;
    r =     (x > 0xFFFFFFFF) << 5; x >>= r;
    shift = (x > 0xFFFF    ) << 4; x >>= shift; r |= shift;
    shift = (x > 0xFF      ) << 3; x >>= shift; r |= shift;
    shift = (x > 0xF       ) << 2; x >>= shift; r |= shift;
    shift = (x > 0x3       ) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
#endif
}
#endif

UINT32 sc_log2_32(UINT32 x)
{
#if 0//def HAVE___BUILTIN_CLZ
#ifdef HAVE_INT_8BYTES
    return 63 - __builtin_clz(x) + (x == 0);
#else
    return 31 - __builtin_clz(x) + (x == 0);
#endif
#else
    UINT32 r, shift;
    r =     (x > 0xFFFF) << 4; x >>= r;
    shift = (x > 0xFF  ) << 3; x >>= shift; r |= shift;
    shift = (x > 0xF   ) << 2; x >>= shift; r |= shift;
    shift = (x > 0x3   ) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
#endif
}

UINT32 sc_log2_16(UINT16 x)
{
#if 0//def HAVE___BUILTIN_CLZ
#ifdef HAVE_INT_8BYTES
    return 63 - __builtin_clz(x) + (x == 0);
#else
    return 31 - __builtin_clz(x) + (x == 0);
#endif
#else
    UINT32 r, shift;
    r =     (x > 0xFF) << 3; x >>= r;
    shift = (x > 0xF ) << 2; x >>= shift; r |= shift;
    shift = (x > 0x3 ) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
#endif
}

UINT32 sc_log2_8(UINT8 x)
{
#if 0//def HAVE___BUILTIN_CLZ
#ifdef HAVE_INT_8BYTES
    return 63 - __builtin_clz(x) + (x == 0);
#else
    return 31 - __builtin_clz(x) + (x == 0);
#endif
#else
    UINT32 r, shift;
    r =     (x > 0xF) << 2; x >>= r;
    shift = (x > 0x3) << 1; x >>= shift; r |= shift;
    r |= (x >> 1);
    return r;
#endif
}

size_t sc_log2(size_t x)
{
#ifdef __x86_64
    return sc_log2_64(x);
#else
    return sc_log2_32(x);
#endif
}


//--------------------------- CEILING LOG BASE 2 ----------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT32 sc_ceil_log2_128(UINT128 x)
{
    UINT32 log2 = sc_log2_128(x);
    if (x & (x-1)) log2++;
    return log2;
}
#endif

#ifdef HAVE_64BIT
UINT32 sc_ceil_log2_64(UINT64 x)
{
    UINT32 log2 = sc_log2_64(x);
    if (x & (x-1)) log2++;
    return log2;
}
#endif

UINT32 sc_ceil_log2_32(UINT32 x)
{
    UINT32 log2 = sc_log2_32(x);
    if (x & (x-1)) log2++;
    return log2;
}

UINT32 sc_ceil_log2_16(UINT16 x)
{
    UINT32 log2 = sc_log2_16(x);
    if (x & (x-1)) log2++;
    return log2;
}

UINT32 sc_ceil_log2_8(UINT8 x)
{
    UINT32 log2 = sc_log2_8(x);
    if (x & (x-1)) log2++;
    return log2;
}

size_t sc_ceil_log2(size_t x)
{
    size_t log2 = sc_log2(x);
    if (x & (x-1)) log2++;
    return log2;
}



//------------------------------- BIT PARITY --------------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT32 sc_bit_parity_128(UINT128 x)
{
#ifdef HAVE___BUILTIN_PARITYLL
    return __builtin_parityll((UINT64)x) ^ __builtin_parityll((UINT64)(x >> 64));
#else
    x ^= x >> 64;
    x ^= x >> 32;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0xF;
    return (0x6996 >> x) & 1;
#endif
}
#endif

#ifdef HAVE_64BIT
// From https://graphics.stanford.edu/~seander/bithacks.html
// Andrew Shapira, Sep 2007
UINT32 sc_bit_parity_64(UINT64 x)
{
#ifdef HAVE___BUILTIN_PARITYLL
    return __builtin_parityll(x);
#else
    x ^= x >> 1;
    x ^= x >> 2;
    x = (x & 0x1111111111111111UL) * 0x1111111111111111UL;
    return (x >> 60) & 1;
#endif
}
#endif

// From https://graphics.stanford.edu/~seander/bithacks.html
// Andrew Shapira, Sep 2007
UINT32 sc_bit_parity_32(UINT32 x)
{
#ifdef HAVE___BUILTIN_PARITYL
    return __builtin_parityl(x);
#else
    x ^= x >> 1;
    x ^= x >> 2;
    x = (x & 0x11111111U) * 0x11111111U;
    return (x >> 28) & 1;
#endif
}

UINT32 sc_bit_parity_16(UINT16 x)
{
#ifdef HAVE___BUILTIN_PARITYL
    return __builtin_parityl(x);
#else
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0xF;
    return (0x6996 >> x) & 1;
#endif
}

// From https://graphics.stanford.edu/~seander/bithacks.html
UINT32 sc_bit_parity_8(UINT8 x)
{
#ifdef HAVE___BUILTIN_PARITYL
    return __builtin_parityl(x);
#else
    x ^= x >> 4;
    x &= 0xF;
    return (0x6996 >> x) & 1;
#endif
}


//------------------------------ HAMMING WEIGHT -----------------------------//

#ifdef HAVE_64BIT
UINT64 sc_hamming_64(UINT64 x)
{
#ifdef HAVE___BUILTIN_POPCOUNTLL
    return __builtin_popcountll(x);
#else
    x = x - ((x >> 1) & 0x5555555555555555);
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333);
    return ((x + ((x >> 4) & 0x0F0F0F0F0F0F0F0F)) * 0x0101010101010101) >> 56;
#endif
}

#endif
UINT32 sc_hamming_32(UINT32 x)
{
#ifdef HAVE___BUILTIN_POPCOUNTL
    return __builtin_popcountl(x);
#else
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    return ((x + ((x >> 4) & 0x0F0F0F0F)) * 0x01010101) >> 24;
#endif
}

UINT16 sc_hamming_16(UINT16 x)
{
#ifdef HAVE___BUILTIN_POPCOUNTL
    return __builtin_popcountl(x);
#else
    x = x - ((x >> 1) & 0x5555);
    x = (x & 0x3333) + ((x >> 2) & 0x3333);
    return (UINT16)((x + ((x >> 4) & 0x0F0F)) * 0x0101) >> 8;
#endif
}

UINT8 sc_hamming_8(UINT8 x)
{
#ifdef HAVE___BUILTIN_POPCOUNTL
    return __builtin_popcountl(x);
#else
    x = x - ((x >> 1) & 0x55);
    x = (x & 0x33) + ((x >> 2) & 0x33);
    return (UINT8)(x + ((x >> 4) & 0x0F)) * 0x01;
#endif
}


//--------------------------- COUNT TRAILING ZEROS --------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT32 sc_ctz_128(UINT128 x)
{
    UINT64 ctz = sc_ctz_64((UINT64)x);
    if (64 == ctz) {
        ctz += sc_ctz_64(x >> 64);
    }
    return ctz;
}
#endif

#ifdef HAVE_64BIT
UINT32 sc_ctz_64(UINT64 x)
{
#ifdef HAVE___BUILTIN_CTZLL
    return __builtin_ctzll(x);
#else
    UINT32 c = 64;
    x &= -(SINT64)x;
    if (x) c--;
    if (x & 0x00000000FFFFFFFF) c -= 32;
    if (x & 0x0000FFFF0000FFFF) c -= 16;
    if (x & 0x00FF00FF00FF00FF) c -= 8;
    if (x & 0x0F0F0F0F0F0F0F0F) c -= 4;
    if (x & 0x3333333333333333) c -= 2;
    if (x & 0x5555555555555555) c -= 1;
    return c;
#endif
}
#endif

UINT32 sc_ctz_32(UINT32 x)
{
#ifdef HAVE___BUILTIN_CTZ
#ifdef HAVE_INT_8BYTES
    return __builtin_ctz(0x100000000 | x);
#else
    return __builtin_ctz(x);
#endif
#else
    UINT32 c = 32;
    x &= -(SINT32)x;
    if (x) c--;
    if (x & 0x0000FFFF) c -= 16;
    if (x & 0x00FF00FF) c -= 8;
    if (x & 0x0F0F0F0F) c -= 4;
    if (x & 0x33333333) c -= 2;
    if (x & 0x55555555) c -= 1;
    return c;
#endif
}

UINT32 sc_ctz_16(UINT16 x)
{
#ifdef HAVE___BUILTIN_CTZ
    return __builtin_ctz(0x10000 | x);
#else
    UINT32 c = 16;
    x &= -(SINT16)x;
    if (x) c--;
    if (x & 0x00FF) c -= 8;
    if (x & 0x0F0F) c -= 4;
    if (x & 0x3333) c -= 2;
    if (x & 0x5555) c -= 1;
    return c;
#endif
}

UINT32 sc_ctz_8(UINT8 x)
{
#ifdef HAVE___BUILTIN_CTZ
    return __builtin_ctz(0x100 | x);
#else
    UINT32 c = 8;
    x &= -(SINT8)x;
    if (x) c--;
    if (x & 0x0F) c -= 4;
    if (x & 0x33) c -= 2;
    if (x & 0x55) c -= 1;
    return c;
#endif
}



//--------------------------- COUNT LEADING ZEROS ---------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT32 sc_clz_128(UINT128 x)
{
    UINT64 clz = sc_clz_64((UINT64)(x >> 64));
    if (64 == clz) {
        clz += sc_clz_64(x);
    }
    return clz;
}
#endif

#ifdef HAVE_64BIT
UINT32 sc_clz_64(UINT64 x)
{
    if (0 == x) return 64;
#ifdef HAVE___BUILTIN_CLZL
    return __builtin_clzl(x);
#else
    UINT64 n = 0;
    if (x <= 0x00000000ffffffff) n += 32, x <<= 32;
    if (x <= 0x0000ffffffffffff) n += 16, x <<= 16;
    if (x <= 0x00ffffffffffffff) n +=  8, x <<= 8;
    if (x <= 0x0fffffffffffffff) n +=  4, x <<= 4;
    if (x <= 0x3fffffffffffffff) n +=  2, x <<= 2;
    if (x <= 0x7fffffffffffffff) n ++;
    return n;
#endif
}
#endif

UINT32 sc_clz_32(UINT32 x)
{
    if (0 == x) return 32;
#ifdef HAVE___BUILTIN_CLZ
#ifdef HAVE_INT_8BYTES
    return __builtin_clz(x & 0xFFFFFFFF) - 32;
#else
    return __builtin_clz(x);
#endif
#else
    UINT32 n = 0;
    if (x <= 0x0000ffff) n += 16, x <<= 16;
    if (x <= 0x00ffffff) n +=  8, x <<= 8;
    if (x <= 0x0fffffff) n +=  4, x <<= 4;
    if (x <= 0x3fffffff) n +=  2, x <<= 2;
    if (x <= 0x7fffffff) n ++;
    return n;
#endif
}

UINT32 sc_clz_16(UINT16 x)
{
    if (0 == x) return 16;
#ifdef HAVE___BUILTIN_CLZ
#ifdef HAVE_INT_8BYTES
    return __builtin_clz(x & 0xFFFF) - 48;
#else
    return __builtin_clz(x & 0xFFFF) - 16;
#endif
#else
    UINT32 n = 0;
    if (x <= 0x00ff) n +=  8, x <<= 8;
    if (x <= 0x0fff) n +=  4, x <<= 4;
    if (x <= 0x3fff) n +=  2, x <<= 2;
    if (x <= 0x7fff) n ++;
    return n;
#endif
}

UINT32 sc_clz_8(UINT8 x)
{
    if (0 == x) return 8;
#ifdef HAVE___BUILTIN_CLZ
#ifdef HAVE_INT_8BYTES
    return __builtin_clz(x & 0xFF) - 56;
#else
    return __builtin_clz(x & 0xFF) - 24;
#endif
#else
    UINT32 n = 0;
    if (x <= 0x0f) n +=  4, x <<= 4;
    if (x <= 0x3f) n +=  2, x <<= 2;
    if (x <= 0x7f) n ++;
    return n;
#endif
}



//------------------------------- BIT REVERSAL ------------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT128 sc_bit_reverse_128(UINT128 x)
{
#ifdef __arm__
    UINT64 a = x >> 64;
    UINT64 b = x;
    UINT64 y;
    UINT128 z;
    __asm__("rbit %0, %1\n" : "=r"(y) : "r"(a));
    z = y;
    z <<= 64;
    __asm__("rbit %0, %1\n" : "=r"(y) : "r"(b));
    return z | y;
#else
    UINT128 s = sizeof(x) * 8;
    UINT128 mask = ~0;
    while ((s >>= 1) > 0)
    {
        mask ^= (mask << s);
        x = ((x >> s) & mask) | ((x << s) & ~mask);
    }
    return x;
#endif
}
#endif

#ifdef HAVE_64BIT
UINT64 sc_bit_reverse_64(UINT64 x)
{
#ifdef __arm__
    UINT64 y;
    __asm__("rbit %0, %1\n" : "=r"(y) : "r"(x));
    return y;
#else
    x = (((x & 0xaaaaaaaaaaaaaaaa) >>  1) | ((x & 0x5555555555555555) <<  1)); // Swap odd and even
    x = (((x & 0xcccccccccccccccc) >>  2) | ((x & 0x3333333333333333) <<  2)); // Swap pairs
    x = (((x & 0xf0f0f0f0f0f0f0f0) >>  4) | ((x & 0x0f0f0f0f0f0f0f0f) <<  4)); // Swap nibbles
    x = (((x & 0xff00ff00ff00ff00) >>  8) | ((x & 0x00ff00ff00ff00ff) <<  8)); // Swap bytes
    x = (((x & 0xffff0000ffff0000) >> 16) | ((x & 0x0000ffff0000ffff) << 16)); // Swap pairs of bytes
    return (x >> 32) | (x << 32);                                              // Swap 4-byte pairs
#endif
}
#endif

UINT32 sc_bit_reverse_32(UINT32 x)
{
#ifdef __arm__
    UINT32 y;
    __asm__("rbit %0, %1\n" : "=r"(y) : "r"(x));
    return y;
#else
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1)); // Swap odd and even
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2)); // Swap pairs
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4)); // Swap nibbles
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8)); // Swap bytes
    return (x >> 16) | (x << 16);                            // Swap pairs of bytes
#endif
}

UINT16 sc_bit_reverse_16(UINT16 x)
{
#ifdef __arm__
    UINT32 y;
    __asm__("rbit %0, %1\n" : "=r"(y) : "r"(x));
    return y >> 16;
#else
    x = (((x & 0xaaaa) >> 1) | ((x & 0x5555) << 1)); // Swap odd and even
    x = (((x & 0xcccc) >> 2) | ((x & 0x3333) << 2)); // Swap pairs
    x = (((x & 0xf0f0) >> 4) | ((x & 0x0f0f) << 4)); // Swap nibbles
    return (x >> 8) | (x << 8);                      // Swap bytes
#endif
}

UINT8 sc_bit_reverse_8(UINT8 x)
{
#ifdef __arm__
    UINT32 y;
    __asm__("rbit %0, %1\n" : "=r"(y) : "r"(x));
    return y >> 24;
#else
    UINT8 b = x;
#ifdef HAVE_64_BIT
    return ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
#else
    return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
#endif
#endif
}

size_t sc_bit_reverse(size_t x)
{
#ifdef __x86_64
    return sc_bit_reverse_64(x);
#else
    return sc_bit_reverse_32(x);
#endif
}


//------------------------------- BIT ROTATION ------------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT128 sc_rotl_128(UINT128 w, SINT32 n)
{
    SINT32 bits = n & 0x7F;
    return (w << bits) | (w >> (128 - bits));
}
#endif

#ifdef HAVE_64BIT
UINT64 sc_rotl_64(UINT64 w, SINT32 n)
{
    SINT32 bits = n & 0x3F;
    return (w << bits) | (w >> (64 - bits));
}
#endif

UINT32 sc_rotl_32(UINT32 w, SINT32 n)
{
    SINT32 bits = n & 0x1F;
    return (w << bits) | (w >> (32 - bits));
}

UINT16 sc_rotl_16(UINT16 w, SINT32 n)
{
    SINT32 bits = n & 0xF;
    return (w << bits) | (w >> (16 - bits));
}

UINT8 sc_rotl_8(UINT8 w, SINT32 n)
{
    SINT32 bits = n & 0x7;
    return (w << bits) | (w >> (8 - bits));
}

SINT32 sc_arr_rotl_32(UINT32 *w, size_t n, SINT32 m)
{
    size_t i;
    UINT32 temp, temp2;
    SINT32 bits  = m & 0x1F;

    if (m <= -32 || m >= 32) {
        return SC_FUNC_FAILURE;
    }

    if (m < 0) {
        temp = w[n-1];
        for (i=0; i<n; i++) {
            temp2  = (temp << bits);
            temp2 |= (w[i] >> (32 - bits));
            temp = w[i];
            w[i] = temp2;
        }
    }
    else {
        temp = w[0];
        for (i=n; i--;) {
            temp2  = (w[i] << bits);
            temp2 |= (temp >> (32 - bits));
            temp = w[i];
            w[i] = temp2;
        }
    }

    return SC_FUNC_SUCCESS;
}


//---------------------- UNSIGNED INTEGER SQUARE ROOT -----------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT128 sqrt_u128(UINT128 x)
{
    register UINT128 op, res, one;

    op  = x;
    res = 0;

    // "one" starts at the highest power of four <= than the argument
    one = (UINT128)1 << 126;  // second-to-top bit set
    while (one > op) one >>= 2;

    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;
        }
        res >>= 1;
        one >>= 2;
    }
    return res;
}
#endif

#ifdef HAVE_64BIT
UINT64 sqrt_u64(UINT64 x)
{
    register UINT64 op, res, one;

    op  = x;
    res = 0;

    // "one" starts at the highest power of four <= than the argument
    one = (UINT64)1 << 62;  // second-to-top bit set
    while (one > op) one >>= 2;

    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;
        }
        res >>= 1;
        one >>= 2;
    }
    return res;
}
#endif

UINT32 sqrt_u32(UINT32 x)
{
    register UINT32 op, res, one;

    op  = x;
    res = 0;

    // "one" starts at the highest power of four <= than the argument
    one = 1 << 30;  // second-to-top bit set
    while (one > op) one >>= 2;

    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;
        }
        res >>= 1;
        one >>= 2;
    }
    return res;
}

UINT16 sqrt_u16(UINT16 x)
{
    register UINT16 op, res, one;

    op  = x;
    res = 0;

    // "one" starts at the highest power of four <= than the argument
    one = 1 << 14;  // second-to-top bit set
    while (one > op) one >>= 2;

    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;
        }
        res >>= 1;
        one >>= 2;
    }
    return res;
}

UINT8 sqrt_u8(UINT8 x)
{
    register UINT8 op, res, one;

    op  = x;
    res = 0;

    // "one" starts at the highest power of four <= than the argument
    one = 1 << 6;  // second-to-top bit set
    while (one > op) one >>= 2;

    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;
        }
        res >>= 1;
        one >>= 2;
    }
    return res;
}


//----------------------- BINARY FRACTION EXPANSION -------------------------//

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT128 get_binary_expansion_fraction_128(DOUBLE x)
{
    size_t i;
    DOUBLE val = 0;
    UINT128 res = 0;
    DOUBLE temp = 0.5f;
    for (i=1; i<129; i++) {
        res <<= 1;
        if ((val + temp) < x) {
            val  += temp;
            res  |= 1;
        }
        temp = temp / 2;
    }
    return res;
}
#endif

#ifdef HAVE_64BIT
UINT64 get_binary_expansion_fraction_64(DOUBLE x)
{
    size_t i;
    DOUBLE val = 0;
    UINT64 res = 0;
    DOUBLE temp = 0.5f;
    for (i=1; i<65; i++) {
        res <<= 1;
        if ((val + temp) < x) {
            val  += temp;
            res  |= 1;
        }
        temp = temp / 2;
    }
    return res;
}
#endif

UINT32 get_binary_expansion_fraction_32(DOUBLE x)
{
    size_t i;
    DOUBLE val = 0;
    UINT32 res = 0;
    DOUBLE temp = 0.5f;
    for (i=1; i<33; i++) {
        res <<= 1;
        if ((val + temp) < x) {
            val  += temp;
            res  |= 1;
        }
        temp = temp / 2;
    }
    return res;
}

