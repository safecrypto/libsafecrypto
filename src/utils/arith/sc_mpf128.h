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

#pragma once

#include "safecrypto_types.h"


// There will be three options for MP floating-point arithmetic
//  1. GNU Extensions (non-portable, maybe works on Intel compiler)
//  2. GNU GMP (will use this if it is present, which it currently is by default)
//  3. Custom multiple-precision floating-point arithmetic
//
// Whatever the case, all of these options will use the same interface as defined here
// so that the code where it's used is readable, debuggable, ...
//
// Functionality will be added in the order listed above (GNU MPF is already used
// in the now deprecated poly_mpf.c functions).


#if defined(USE_SAFECRYPTO_FLOAT_MP) || !defined(USE_MPFR_MULTIPLE_PRECISION)
#include <limits.h>
#define NATIVE_WORD_SIZE   __WORDSIZE
#else
#if defined(USE_MPFR_MULTIPLE_PRECISION)
#include <gmp.h>
#define NATIVE_WORD_SIZE   GMP_LIMB_BITS
#endif
#endif

//#define SC_USE_GNU_MPF


#if defined(SC_USE_GNU_MPF)

#include <quadmath.h>

#define SC_2_SQRTPI_QUAD   M_2_SQRTPIq
#define SC_SQRT1_2_QUAD    M_SQRT1_2q

#define SC_2_SQRTPI_DOUBLE M_2_SQRTPIl
#define SC_SQRT1_2_DOUBLE  M_SQRT1_2l

#define SC_2_SQRTPI_FLOAT  M_2_SQRTPI
#define SC_SQRT1_2_FLOAT   M_SQRT1_2

#define FLOAT128           __float128
#define SC_FLT_2_FLOAT128(x)

#else
// Custom functions for arbitrary precision floating-point arithmetic
// and some optimised stuff specifically for 128-bit

struct sc_mpf128 {
};

typedef struct sc_mpf128* sc_mpf128_t;

extern sc_mpf128_t sc_2_sqrtpi_quad;
extern sc_mpf128_t sc_sqrt1_2_quad;

#define SC_2_SQRTPI_QUAD   sc_2_sqrtpi_quad
#define SC_SQRT1_2_QUAD    sc_sqrt1_2_quad

#define SC_2_SQRTPI_DOUBLE M_2_SQRTPIl
#define SC_SQRT1_2_DOUBLE  M_SQRT1_2l

#define SC_2_SQRTPI_FLOAT  M_2_SQRTPI
#define SC_SQRT1_2_FLOAT   M_SQRT1_2

#define FLOAT128           sc_mpf128_t

#endif


// Thus far, these are the functions needed for CDT (and possibly Ziggurat) ...

extern FLOAT128 sc_mpf128_mul(FLOAT128 a, FLOAT128 b);
extern FLOAT128 sc_mpf128_div(FLOAT128 a, FLOAT128 b);
extern FLOAT128 sc_mpf128_add(FLOAT128 a, FLOAT128 b);
extern FLOAT128 sc_mpf128_sub(FLOAT128 a, FLOAT128 b);
extern FLOAT128 sc_mpf128_exp(FLOAT128 x);
extern FLOAT128 sc_mpf128_floor(FLOAT128 x);
extern FLOAT128 sc_mpf128_abs(FLOAT128 x);
extern FLOAT128 sc_mpf128_pow(FLOAT128 x, FLOAT128 y);
extern FLOAT128 sc_mpf128_log(FLOAT128 x);
extern FLOAT128 sc_mpf128_sqrt(FLOAT128 x);
extern FLOAT128 sc_mpf128_neg(FLOAT128 x);
extern SINT32 sc_mpf128_cmp(FLOAT128 a, FLOAT128 b);
extern FLOAT128 sc_mpf128_convert_f32_to_f128(FLOAT x);
#if defined (HAVE_128BIT)
extern UINT128 sc_mpf128_convert_f128_to_ui128(FLOAT128 x);
#endif
extern FLOAT128 sc_mpf128_convert_ui32_to_f128(UINT32 x);

