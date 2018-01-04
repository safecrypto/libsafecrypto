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
#include "utils/arith/limb.h"
#include <string.h>


/// Copy the in polynomial of length n to the out polynomial
SINT32 poly_limb_copy(sc_ulimb_t *SC_RESTRICT out, size_t n,
    const sc_ulimb_t *SC_RESTRICT in);

/// Swap the coefficients of the two input polynomials
SINT32 poly_limb_swap(sc_ulimb_t *SC_RESTRICT a, size_t *len_a,
    sc_ulimb_t *SC_RESTRICT b, size_t *len_b);

/// Return the degree of the given polynomial if its maximum length is n
SINT32 poly_limb_degree(const sc_ulimb_t *h, size_t n);

/// Return 0 if the polynomial is zero, otherwise non-zero
SINT32 poly_limb_is_zero(const sc_ulimb_t *h, size_t n);

/// Reset the contents of the polynomial of length n
void poly_limb_reset(sc_ulimb_t *inout, size_t n);

/// Modular negation of the coefficients of the polynomial
void poly_limb_negate_mod(sc_ulimb_t *out, const sc_ulimb_t *in,
    size_t n, const sc_mod_t *mod);

/// Return the modular reduction of the input polynomial coefficients
void poly_limb_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_mod_t *mod);

/// Add the two input polynomials and perform modular reduction
void poly_limb_add_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod);

/// Subtract the two input polynomials and perform modular reduction
void poly_limb_sub_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod);

/// Modular multiplication of the two input polynomials
void poly_limb_mul_mod(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, const sc_mod_t *mod);

/// Modular multiplication of the two input polynomials with the product
/// truncated to n coefficients
void poly_limb_mul_mod_trunc(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b, size_t n, const sc_mod_t *mod);

/// Scalar multiplication of the input polynomial with a constant followed by
/// addition with the inout polynomial and modular reduction
void poly_limb_addmul_mod_scalar(sc_ulimb_t *inout, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b, const sc_mod_t *mod);

/// Scalar multiplication of the input polynomial with a constant followed by
/// subtraction with the inout polynomial and modular reductionvoid poly_limb_submul_mod(sc_ulimb_t *SC_RESTRICT inout, const sc_ulimb_t *SC_RESTRICT a, size_t len_a,
void poly_limb_submul_mod_scalar(sc_ulimb_t *inout, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b, const sc_mod_t *mod);

/// Scalar multiplication of the input polynomial with a constant with reduction
void poly_limb_mul_mod_scalar(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n,
    sc_ulimb_t scalar, const sc_mod_t *mod);

/// Return the resultant of the input polynomials a and b (modulo m)
sc_ulimb_t poly_limb_resultant(const sc_ulimb_t *a, size_t len_a, const sc_ulimb_t *b, size_t len_b,
    sc_ulimb_t *scratch, const sc_mod_t *modulus);

/// Divide a by b and return the quotient and remainder
void poly_limb_divrem_mod(sc_ulimb_t *q, size_t *len_q,
    sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus);

/// Divide a by b and return the quotient only
void poly_limb_div_mod(sc_ulimb_t *q, size_t *len_q,
    const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus);

/// Divide a by b and return the remainder only
void poly_limb_rem_mod(sc_ulimb_t *r, size_t *len_r,
    const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus);

/// Calculate the GCD of a and b
SINT32 poly_limb_gcd_mod(sc_ulimb_t *g,
    const sc_ulimb_t *a, size_t len_a, 
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus);

/// Calculate the GCD of a and b and return the Bezout polynomials
SINT32 poly_limb_xgcd_mod(sc_ulimb_t *g, sc_ulimb_t *x, sc_ulimb_t *y,
    const sc_ulimb_t *a, size_t len_a, 
    const sc_ulimb_t *b, size_t len_b,
    const sc_mod_t *modulus);

/// Left-shift the input polynomial by shift bits and write the output to the
/// out polynomial address.
/// @param shift Must be in the range 1 to n-1 on an n-bit machine
/// @return Returns the bits shifted out to the left
sc_ulimb_t limb_mp_lshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t len, size_t shift);

/// Right-shift the input polynomial by shift bits and write the output to the
/// out polynomial address.
/// @param shift Must be in the range 1 to n-1 on an n-bit machine
/// @return Returns the bits shifted out to the right
sc_ulimb_t limb_mp_rshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t len, size_t shift);

/// Compare the two polynomials of length n
SINT32 limb_mp_cmp(const sc_ulimb_t *a, const sc_ulimb_t *b, size_t len);

/// Add the input integer to the limb
sc_ulimb_t limb_mp_add_1(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t b);

/// Add the two input integers of the same length
sc_ulimb_t limb_mp_add_n(sc_ulimb_t *out, const sc_ulimb_t *a, const sc_ulimb_t *b, size_t len);

/// Subtract the input polynomial from the limb
sc_ulimb_t limb_mp_sub_1(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t b);

/// Subtract the two input integers of the same length
sc_ulimb_t limb_mp_sub_n(sc_ulimb_t *out, const sc_ulimb_t *a, const sc_ulimb_t *b, size_t len);

/// Multiplication of two input integers
sc_ulimb_t limb_mp_mul(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    const sc_ulimb_t *b, size_t len_b);

/// Multiplication of an MP integer with a limb
sc_ulimb_t limb_mp_mul_1(sc_ulimb_t *out, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b);

/// Multiplication of an MP integer with a limb, with addition of the product to the inout.
sc_ulimb_t limb_mp_addmul_1(sc_ulimb_t *inout, const sc_ulimb_t *a, size_t len_a,
    sc_ulimb_t b);

/// Multiplication of two input integers of equal length
void limb_mp_mul_n(sc_ulimb_t *out, const sc_ulimb_t *a,
    const sc_ulimb_t *b, size_t len);

