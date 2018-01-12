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
#include "utils/arith/limb.h"
#include <string.h>


/// Initialise an MP integer
void sc_mpz_init(sc_mpz_t *inout);

/// Initialise an MP integer with storage for "bits" sized numbers and initialised to zero
void sc_mpz_init2(sc_mpz_t *inout, size_t bits);

/// Free memory resources associated with an MP integer
void sc_mpz_clear(sc_mpz_t *inout);

/// Return the given MP integer as an unsigned limb word modulo m
sc_ulimb_t sc_mpz_to_limb_mod(const sc_mpz_t *in, sc_ulimb_t m);

/// Copy one MP integer to another
void sc_mpz_copy(sc_mpz_t *out, const sc_mpz_t *in);

/// Return the given MP integer as a C-string in the specified base
size_t sc_mpz_out_str(FILE *stream, SINT32 base, const sc_mpz_t *in);

/// Get and set functions
/// @{
sc_ulimb_t sc_mpz_get_ui(const sc_mpz_t *in);
sc_slimb_t sc_mpz_get_si(const sc_mpz_t *in);
DOUBLE sc_mpz_get_d(const sc_mpz_t *in);
sc_ulimb_t sc_mpz_get_ui_mod(const sc_mpz_t *a, const sc_mod_t *mod);
SINT32 sc_mpz_get_bytes(UINT8 *out, const sc_mpz_t *in);
sc_ulimb_t * sc_mpz_get_limbs(const sc_mpz_t *in);
SINT32 sc_mpz_get_size(const sc_mpz_t *in);
void sc_mpz_set_ui(sc_mpz_t *inout, sc_ulimb_t value);
void sc_mpz_set_si(sc_mpz_t *inout, sc_slimb_t value);
void sc_mpz_set_d(sc_mpz_t *inout, DOUBLE value);
void sc_mpz_set_size(sc_mpz_t *inout, SINT32 size);
void sc_mpz_set_bytes(sc_mpz_t *out, const UINT8 *bytes, size_t n);
void sc_mpz_set_limbs(sc_mpz_t *out, const sc_ulimb_t *limbs, size_t n);
SINT32 sc_mpz_set_str(sc_mpz_t *out, SINT32 base, const char *str);
/// @}

/// Comparison functions
/// @{
SINT32 sc_mpz_cmp(sc_mpz_t *a, const sc_mpz_t *b);
SINT32 sc_mpz_cmp_d(sc_mpz_t *a, DOUBLE b);
SINT32 sc_mpz_cmp_ui(sc_mpz_t *a, sc_ulimb_t b);
SINT32 sc_mpz_cmp_si(sc_mpz_t *a, sc_slimb_t b);
SINT32 sc_mpz_cmpabs(sc_mpz_t *a, const sc_mpz_t *b);
SINT32 sc_mpz_cmpabs_d(sc_mpz_t *a, DOUBLE b);
SINT32 sc_mpz_cmpabs_ui(sc_mpz_t *a, sc_ulimb_t b);
/// @}

/// Sign manipulation and comparison
/// @{
void sc_mpz_negate(sc_mpz_t *out, const sc_mpz_t *in);
SINT32 sc_mpz_is_zero(const sc_mpz_t *in);
SINT32 sc_mpz_is_one(const sc_mpz_t *in);
SINT32 sc_mpz_is_neg(const sc_mpz_t *in);
SINT32 sc_mpz_sign(const sc_mpz_t *in);
/// @}

/// Update the max_limbs variable and mask if the input MP integer is greater than or equal ma_limbs in length
void sc_mpz_max_bits(const sc_mpz_t *in, sc_ulimb_t *mask, size_t *max_limbs);

/// Return the size of the MP integer in the number of digits in the given base
SINT32 sc_mpz_sizeinbase(const sc_mpz_t *in, SINT32 base);

/// Compute the bitwise complement of a specified array of limbs
void sc_mpz_com_to_poly_limb(sc_ulimb_t *out, const sc_ulimb_t *in, size_t size);

/// Return the modular multiplicative inverse using modulus m
SINT32 sc_mpz_invmod(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *m);

/// Additive and multiplicative functions
/// @{
void sc_mpz_add(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);
void sc_mpz_add_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2);
void sc_mpz_sub(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);
void sc_mpz_sub_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2);
void sc_mpz_mul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);
void sc_mpz_mul_scalar(sc_mpz_t *inout, const sc_mpz_t *in);
void sc_mpz_mul_ui(sc_mpz_t *out, const sc_mpz_t *in1, const sc_ulimb_t in2);
void sc_mpz_mul_si(sc_mpz_t *out, const sc_mpz_t *in1, const sc_slimb_t in2);
void sc_mpz_mul_2exp(sc_mpz_t *out, const sc_mpz_t *in, size_t exp);
void sc_mpz_addmul(sc_mpz_t *inout, const sc_mpz_t *in1, const sc_mpz_t *in2);
void sc_mpz_submul(sc_mpz_t *inout, const sc_mpz_t *in1, const sc_mpz_t *in2);
void sc_mpz_addmul_ui(sc_mpz_t *inout, const sc_mpz_t *in1, sc_ulimb_t in2);
void sc_mpz_submul_ui(sc_mpz_t *inout, const sc_mpz_t *in1, sc_ulimb_t in2);
void sc_mpz_addsqr(sc_mpz_t *inout, const sc_mpz_t *in);
void sc_mpz_subsqr(sc_mpz_t *inout, const sc_mpz_t *in);
void sc_mpz_div(sc_mpz_t *q, sc_mpz_t *r, const sc_mpz_t *n, const sc_mpz_t *d);
void sc_mpz_divrem(sc_mpz_t *r, const sc_mpz_t *n, const sc_mpz_t *d);
void sc_mpz_divquo(sc_mpz_t *q, const sc_mpz_t *n, const sc_mpz_t *d);
void sc_mpz_divquo_2exp(sc_mpz_t *q, const sc_mpz_t *n, size_t exp);
/// @}

/// Compute the square root
void sc_mpz_sqrt(sc_mpz_t *out, const sc_mpz_t *in);

/// Compute 'in' to the power of the unsigned limb exp
void sc_mpz_pow_ui(sc_mpz_t *out, const sc_mpz_t *in, sc_ulimb_t exp);

/// Truncate the 
void sc_mpz_trunc_limbs(sc_mpz_t *out, const sc_mpz_t *in, size_t n);

/// Compute 'in' modulo m using Barrett Reduction
void sc_mpz_mod_barrett(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *m,
	size_t k, const sc_mpz_t *mu);

/// Compute 'in' modulo m
void sc_mpz_mod(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *m);

/// Compute 'in' modulo the unsigned integer m
void sc_mpz_mod_ui(sc_mpz_t *out, const sc_mpz_t *in, sc_ulimb_t m);

/// Return ceil(in/m) as an unsigned integer
sc_ulimb_t sc_mpz_ceil_div_ui(sc_mpz_t *in, sc_ulimb_t m);

/// Return floor(in/m) as an unsigned integer
sc_ulimb_t sc_mpz_floor_div_ui(sc_mpz_t *in, sc_ulimb_t m);

/// Chinese remainder theorem
void sc_mpz_crt(sc_mpz_t *result, const sc_mpz_t *a, const sc_mpz_t *a_m,
    sc_ulimb_t b, sc_mod_t *b_m, sc_ulimb_t m, const sc_mpz_t *ab_m,
    sc_mpz_t *temp);

/// Return the GCD(a, b)
SINT32 sc_mpz_gcd(const sc_mpz_t *a, const sc_mpz_t *b, sc_mpz_t *gcd);

/// Return the GCD(a, b) and the Bezout coefficients
SINT32 sc_mpz_xgcd(const sc_mpz_t *a, const sc_mpz_t *b, sc_mpz_t *gcd,
    sc_mpz_t *x, sc_mpz_t *y);
