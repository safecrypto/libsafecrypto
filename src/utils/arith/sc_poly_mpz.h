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
#include "utils/arith/sc_mpz.h"
#include "utils/arith/limb.h"
#include "utils/arith/poly_limb.h"

/// A struct used to define a multiple-precision polynomial
SC_STRUCT_PACK_START
typedef struct sc_poly_mpz_t {
    sc_mpz_t *p;    ///< The polynomial coefficients
    size_t len;     ///< The length of the array of polynomial coefficients
} SC_STRUCT_PACKED sc_poly_mpz_t;
SC_STRUCT_PACK_END


/// Convert a multiple-precision polynomial to an array of single-precision floats
size_t sc_poly_mpz_to_flt(FLOAT *out, const sc_poly_mpz_t *in);

/// Convert a multiple-precision polynomial to an array of double-precision floats
size_t sc_poly_mpz_to_dbl(DOUBLE *out, const sc_poly_mpz_t *in);

/// Convert a multiple-precision polynomial to an array of limbs
/// reduced modulo m
size_t sc_poly_mpz_to_limb_mod(sc_ulimb_t *out, const sc_poly_mpz_t *in,
    const sc_mod_t *mod);

/// Convert a multiple-precision polynomial to an array of limbs
size_t sc_poly_mpz_to_ui(sc_ulimb_t *out, const sc_poly_mpz_t *in);

/// Convert a multiple-precision polynomial to an array of signed limbs
size_t sc_poly_mpz_to_si(sc_slimb_t *out, const sc_poly_mpz_t *in);

/// Convert a multiple-precision polynomial to an array of unsigned 32-bit integers
size_t sc_poly_mpz_to_ui32(UINT32 *out, const sc_poly_mpz_t *in);

/// Convert a multiple-precision polynomial to an array of signed 32-bit integers
size_t sc_poly_mpz_to_si32(SINT32 *out, const sc_poly_mpz_t *in);

/// Convert an array of limbs to a multiple-precision polynomial
/// reduced modulo m
void poly_limb_to_mpi_mod(sc_poly_mpz_t *out, const sc_ulimb_t *in,
    size_t n, const sc_mod_t *mod);

/// Convert an array of double-precision floats to a multiple-precision polynomial
void poly_dbl_to_mpi(sc_poly_mpz_t *out, size_t n, const DOUBLE *in);

/// Convert an array of limbs to a multiple-precision polynomial
void poly_ui_to_mpi(sc_poly_mpz_t *out, size_t n, const sc_ulimb_t *in);

/// Convert an array of signed limbs to a multiple-precision polynomial
void poly_si_to_mpi(sc_poly_mpz_t *out, size_t n, const sc_slimb_t *in);

/// Convert an array of unsigned 32-bit integers to a multiple-precision polynomial
void poly_ui32_to_mpi(sc_poly_mpz_t *out, size_t n, const UINT32 *in);

/// Convert an array of signed 32-bit integers to a multiple-precision polynomial
void poly_si32_to_mpi(sc_poly_mpz_t *out, size_t n, const SINT32 *in);

/// Initialise a polynomial of length n
void sc_poly_mpz_init(sc_poly_mpz_t *inout, size_t n);


void sc_poly_mpz_clear(sc_poly_mpz_t *inout);
void sc_poly_mpz_resize(sc_poly_mpz_t *inout, size_t n);
void sc_poly_mpz_negate(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in);
void sc_poly_mpz_reverse(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in);
void sc_poly_mpz_mod_ring(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in);
SINT32 sc_poly_mpz_is_zero(const sc_poly_mpz_t *in);
SINT32 sc_poly_mpz_compare(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b);


/// Copy n coefficients from polynomial in to polynomial out, reducing n as
/// appropriate such that it does not exceed the length of in or out
void sc_poly_mpz_copy(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in);

/// Copy n coefficients from array in to polynomial out, reducing n as
/// appropriate such that it does not exceed the length of out
void sc_poly_mpz_copy_si32(sc_poly_mpz_t *out, size_t n, const SINT32 *in);

/// Copy n coefficients from array in to polynomial out, reducing n as
/// appropriate such that it does not exceed the length of out
void sc_poly_mpz_copy_ui32(sc_poly_mpz_t *out, size_t n, const UINT32 *in);

/// Reset the coefficients to zero, satrting from the offset index
void sc_poly_mpz_reset(sc_poly_mpz_t *inout, size_t offset);

/// Return a pointer to the sc_mpz_t object at index i
sc_mpz_t * sc_poly_mpz_get_mpi(sc_poly_mpz_t *in, size_t i);

/// Return the limb at index i
sc_ulimb_t sc_poly_mpz_get_ui(const sc_poly_mpz_t *in, size_t index);

/// Return the signed limb at index i
sc_slimb_t sc_poly_mpz_get_si(const sc_poly_mpz_t *in, size_t index);

/// Return the double at index i
DOUBLE sc_poly_mpz_get_d(const sc_poly_mpz_t *in, size_t index);

/// Return the limb at index i with reduction
sc_ulimb_t * sc_poly_mpz_get_limbs(const sc_poly_mpz_t *in, size_t index);

/// Return the limb at index i with reduction
sc_ulimb_t sc_poly_mpz_get_limb_mod(sc_poly_mpz_t *a, size_t index, const sc_mod_t *mod);

/// Set the polynomial coefficient at the specified index to the given sc_mpz_t value
SINT32 sc_poly_mpz_set_mpi(sc_poly_mpz_t *inout, size_t index, const sc_mpz_t *value);

/// Set the polynomial coefficient at the specified index to the given limb value
SINT32 sc_poly_mpz_set_si(sc_poly_mpz_t *inout, size_t index, sc_slimb_t value);

/// Set the polynomial coefficient at the specified index to the given signed limb value
SINT32 sc_poly_mpz_set_ui(sc_poly_mpz_t *inout, size_t index, sc_ulimb_t value);

/// Set the polynomial coefficient at the specified index to the given double value
SINT32 sc_poly_mpz_set_d(sc_poly_mpz_t *inout, size_t index, DOUBLE value);

/// Perform modular reduction on the input polynomial
void sc_poly_mpz_mod(sc_poly_mpz_t *out, const sc_poly_mpz_t *in, const sc_mod_t *mod);

/// Add the given multiple-precision value to all coefficients of the polynomial
void sc_poly_mpz_add_scalar(sc_poly_mpz_t *poly, const sc_mpz_t *in);

/// Subtract the given multiple-precision value from all coefficients of the polynomial
void sc_poly_mpz_sub_scalar(sc_poly_mpz_t *poly, const sc_mpz_t *in);

/// Multiply the given multiple-precision value with the MP polymomial
void sc_poly_mpz_mul_scalar(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_mpz_t *in2);

/// Multiply the given multiple-precision value with the MP polymomial
void sc_poly_mpz_mul_scalar_ui(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, sc_ulimb_t in2);

/// Add the multiple-precision polymomials
void sc_poly_mpz_add(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2);

/// Add the multiple-precision polymomials with offsets for indexing
void sc_poly_mpz_add_offset(sc_poly_mpz_t *out, size_t out_idx,
    const sc_poly_mpz_t *in1, size_t in1_idx, const sc_poly_mpz_t *in2, size_t in2_idx, size_t m);

/// Subtract the multiple-precision polymomials
void sc_poly_mpz_sub(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2);

/// Subtract the multiple-precision polymomials with offsets for indexing
void sc_poly_mpz_sub_offset(sc_poly_mpz_t *out, size_t out_idx,
    const sc_poly_mpz_t *in1, size_t in1_idx, const sc_poly_mpz_t *in2, size_t in2_idx, size_t m);

/// Add the multiple-precision polymomial to the inout
void sc_poly_mpz_add_single(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in);

/// Subtract the multiple-precision polymomial from the inout
void sc_poly_mpz_sub_single(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in);

/// Multiply the two input multiple-precision polynomials
void sc_poly_mpz_mul(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2);

/// Add the product of the two input multiple-precision polynomials to inout
void sc_poly_mpz_addmul(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2);

/// Subtract the product of the two input multiple-precision polynomials from inout
void sc_poly_mpz_submul(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2);

/// Add the product of the input multiple-precision polynomial and the MP value to inout
void sc_poly_mpz_addmul_scalar(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in1, const sc_mpz_t *in2);

/// Subtract the product of the input multiple-precision polynomial and the MP value from inout
void sc_poly_mpz_submul_scalar(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in1, const sc_mpz_t *in2);

/// Divide the numerator by the denominator creating the quotient and remainder
SINT32 sc_poly_mpz_div(const sc_poly_mpz_t *num, const sc_poly_mpz_t *den, sc_poly_mpz_t *q, sc_poly_mpz_t *r);

/// Pointwise division of all coefficients of the numerator polynomial by the MP denominator,
/// generating only the floored quotient
void sc_poly_mpz_div_pointwise(sc_poly_mpz_t *q, const sc_poly_mpz_t *num, const sc_mpz_t *den);

/// Divide the numerator by the denominator creating the quotient only
SINT32 sc_poly_mpz_divquo(const sc_poly_mpz_t *num, const sc_poly_mpz_t *den, sc_poly_mpz_t *q);

/// Compute the content of the input polynomial
SINT32 sc_poly_mpz_content(sc_mpz_t *res, const sc_poly_mpz_t *poly);

/// Scale the input polynomial using the content
SINT32 sc_poly_mpz_content_scale(const sc_poly_mpz_t *in, const sc_mpz_t *content, sc_poly_mpz_t *out);

/// Generate a multiple precision polynomial using a uniform random number distribution
/// with a specified number of coefficients of each value
void sc_poly_mpz_uniform_rand(prng_ctx_t *ctx, sc_poly_mpz_t *v, const UINT16 *c, size_t c_len);

/// Calculate the maximum number of bits required to represent the given MP polynomial
SINT32 sc_poly_mpz_max_bits(const sc_poly_mpz_t *x);

/// Return the degree of the given MP polynomial
SINT32 sc_poly_mpz_degree(const sc_poly_mpz_t *h);

/// Use CRT to obtain the remainder of the products of a_m and b_m using
/// a mod a_m and b mod b_m, where b is an array of limbs
SINT32 sc_poly_mpz_crt(sc_poly_mpz_t *result, const sc_poly_mpz_t *a, SINT32 deg_a, const sc_mpz_t *a_m,
    sc_ulimb_t *b, SINT32 deg_b, sc_mod_t *b_m);

/// Compute the resultant of a and b
SINT32 sc_poly_mpz_resultant(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b,
    sc_mpz_t *resultant);

/// Compute the GCD(a,b)
SINT32 sc_poly_mpz_gcd(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b, sc_poly_mpz_t *gcd);

/// Compute the Extended GCD(a,b) such that a*x + b*y = GCD(a,b)
SINT32 sc_poly_mpz_xgcd(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b, sc_mpz_t *gcd,
    sc_poly_mpz_t *x, sc_poly_mpz_t *y);
