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
#include "safecrypto_private.h"
#include "utils/arith/limb.h"
#include "utils/arith/sc_mp.h"
#include <string.h>


#if defined(USE_MPFR_MULTIPLE_PRECISION)
#include <mpfr.h>
#endif

#ifdef USE_SAFECRYPTO_FLOAT_MP
#define SC_MPF_DEFAULT_PRECISION   128
#endif


#if defined(USE_SAFECRYPTO_FLOAT_MP) || !defined(USE_MPFR_MULTIPLE_PRECISION)
/// A struct used to store a signed multiple-precision floating-point variable
typedef struct _sc_mpf_t
{
   SINT32 precision;     ///< The precision of the mantissa, a multiple of SC_LIMB_BITS
   SINT32 sign;          ///< The sign of the mantissa
   SINT32 alloc;         ///< Number of limbs allocated to the mantissa
   sc_ulimb_t *mantissa; ///< Pointer to the mantissa limbs
   sc_slimb_t exponent;  ///< Exponent
} sc_mpf_t;
#else
#if defined(USE_MPFR_MULTIPLE_PRECISION)
typedef __mpfr_struct sc_mpf_t;
#endif
#endif


/// Set/get the precision in bits of the floating-point mantissa
/// @{
SINT32 sc_mpf_set_precision(size_t prec);
size_t sc_mpf_get_precision(void);
/// @}

/// Initialise/clear a variable
/// @{
void sc_mpf_init(sc_mpf_t *inout);
void sc_mpf_clear(sc_mpf_t *inout);
/// @}

/// Constants
/// @{

/// Retrieve a pointer to PI, allocating memory resources in the process
void sc_mpf_get_pi(sc_mpf_t *out);

/// Release all memory resources associated with constants
void sc_mpf_clear_constants(void);

/// @}

/// Return the specified variable as a formatted stream with the specified base and
/// number of significant digits
size_t sc_mpf_out_str(FILE *stream, SINT32 base, size_t digits, const sc_mpf_t *in);

/// Get/set functions
/// @{}
sc_ulimb_t sc_mpf_get_ui(const sc_mpf_t *in);
sc_slimb_t sc_mpf_get_si(const sc_mpf_t *in);
DOUBLE sc_mpf_get_d(const sc_mpf_t *in);
sc_ulimb_t * sc_mpf_get_limbs(const sc_mpf_t *in);
sc_slimb_t sc_mpf_get_exp(const sc_mpf_t *in);
void sc_mpf_set(sc_mpf_t *out, const sc_mpf_t *in);
void sc_mpf_set_ui(sc_mpf_t *inout, sc_ulimb_t value);
void sc_mpf_set_si(sc_mpf_t *inout, sc_slimb_t value);
void sc_mpf_set_d(sc_mpf_t *inout, DOUBLE value);
/// @}

/// Comparison functions
/// @{
SINT32 sc_mpf_cmp(const sc_mpf_t *a, const sc_mpf_t *b);
SINT32 sc_mpf_cmp_d(const sc_mpf_t *a, DOUBLE b);
SINT32 sc_mpf_cmp_ui(const sc_mpf_t *a, sc_ulimb_t b);
SINT32 sc_mpf_cmp_si(const sc_mpf_t *a, sc_slimb_t b);
/// @}

/// Determine if a MP floating-point variable can fit in a limb type
/// @{
SINT32 sc_mpf_fits_slimb(const sc_mpf_t *in);
SINT32 sc_mpf_fits_ulimb(const sc_mpf_t *in);
/// @}

/// Singular and sign query functions
/// @{
void sc_mpf_abs(sc_mpf_t *out, const sc_mpf_t *in);
void sc_mpf_negate(sc_mpf_t *out, const sc_mpf_t *in);
SINT32 sc_mpf_is_zero(const sc_mpf_t *in);
SINT32 sc_mpf_is_nan(const sc_mpf_t *in);
SINT32 sc_mpf_is_inf(const sc_mpf_t *in);
SINT32 sc_mpf_is_neg(const sc_mpf_t *in);
SINT32 sc_mpf_sign(const sc_mpf_t *in);
/// @}

/// Additive and multiplicative
/// @{
void sc_mpf_add(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2);
void sc_mpf_add_ui(sc_mpf_t *out, const sc_mpf_t *in1, sc_ulimb_t in2);
void sc_mpf_add_si(sc_mpf_t *out, const sc_mpf_t *in1, sc_slimb_t in2);
void sc_mpf_sub(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2);
void sc_mpf_sub_ui(sc_mpf_t *out, const sc_mpf_t *in1, sc_ulimb_t in2);
void sc_mpf_sub_si(sc_mpf_t *out, const sc_mpf_t *in1, sc_slimb_t in2);
void sc_mpf_mul(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2);
void sc_mpf_mul_2exp(sc_mpf_t *out, const sc_mpf_t *in, sc_ulimb_t exp);
void sc_mpf_mul_ui(sc_mpf_t *out, const sc_mpf_t *in1, const sc_ulimb_t in2);
void sc_mpf_mul_si(sc_mpf_t *out, const sc_mpf_t *in1, const sc_slimb_t in2);
void sc_mpf_div(sc_mpf_t *out, const sc_mpf_t *n, const sc_mpf_t *d);
void sc_mpf_div_2exp(sc_mpf_t *out, const sc_mpf_t *n, sc_ulimb_t exp);
void sc_mpf_div_ui(sc_mpf_t *out, const sc_mpf_t *n, sc_ulimb_t d);
void sc_mpf_div_si(sc_mpf_t *out, const sc_mpf_t *n, sc_slimb_t d);
void sc_mpf_sqrt(sc_mpf_t *out, const sc_mpf_t *in);
void sc_mpf_sqrt_ui(sc_mpf_t *out, sc_ulimb_t in);
void sc_mpf_pow_ui(sc_mpf_t *out, const sc_mpf_t *in, sc_ulimb_t exp);
void sc_mpf_pow_si(sc_mpf_t *out, const sc_mpf_t *in, sc_slimb_t exp);
/// @}

/// Rounding
/// @{
void sc_mpf_ceil(sc_mpf_t *out, const sc_mpf_t *in);
void sc_mpf_floor(sc_mpf_t *out, const sc_mpf_t *in);
void sc_mpf_trunc(sc_mpf_t *out, const sc_mpf_t *in);
/// @}

/// Transcendental functions
/// @{
SINT32 sc_mpf_exp(sc_mpf_t *out, const sc_mpf_t *in);
SINT32 sc_mpf_log(sc_mpf_t *out, const sc_mpf_t *in);
/// @}
