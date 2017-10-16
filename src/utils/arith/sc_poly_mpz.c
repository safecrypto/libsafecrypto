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

#include "utils/arith/sc_poly_mpz.h"
#include "utils/arith/sc_mpz.h"
#include "utils/crypto/prng.h"
#include "utils/arith/sc_math.h"
#include "utils/arith/arith.h"
#include "utils/sampling/sampling.h"
#include "safecrypto_types.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"
#include "poly_fft.h"
#include "utils/arith/next_prime.h"

#ifdef ENABLE_CALLGRIND_PROFILING
#include <valgrind/callgrind.h>
#endif

#include <math.h>
#include <assert.h>


/// A coefficient bit size threshold after which the XGCD function will fail
#define POLY_XGCD_STABLE_BOUND    32768


typedef struct sc_mpz_comb_t {
    const sc_ulimb_t *primes;
    size_t            num_primes;
    size_t            n;
    sc_poly_mpz_t    *comb;
    sc_poly_mpz_t    *res;
    sc_mod_t         *mod;
} sc_mpz_comb_t;

typedef struct sc_mpz_comb_buf_t {
    size_t         n;
    sc_poly_mpz_t *comb_temp;
    sc_mpz_t       temp;
    sc_mpz_t       temp2;
} sc_mpz_comb_buf_t;

/// A typedef for a function pointer to move data
typedef void (*func_move_ptr)(sc_mpz_t *, const sc_mpz_t *);


size_t sc_poly_mpz_to_flt(FLOAT *out, const sc_poly_mpz_t *in)
{
    size_t i;
    for (i=in->len; i--;) {
        out[i] = (FLOAT) sc_mpz_get_d(&in->p[i]);
    }
    return in->len;
}

size_t sc_poly_mpz_to_dbl(DOUBLE *out, const sc_poly_mpz_t *in)
{
    size_t i;
    for (i=in->len; i--;) {
        out[i] = (DOUBLE) sc_mpz_get_d(&in->p[i]);
    }
    return in->len;
}

size_t sc_poly_mpz_to_limb_mod(sc_ulimb_t *out, const sc_poly_mpz_t *in,
    const sc_mod_t *mod)
{
    size_t i;
    sc_mpz_t temp;
    sc_mpz_init(&temp);
    for (i=in->len; i--;) {
        sc_mpz_mod_ui(&temp, &in->p[i], mod->m);
        out[i] = sc_mpz_get_ui(&temp);
    }
    sc_mpz_clear(&temp);
    return in->len;
}

size_t sc_poly_mpz_to_ui(sc_ulimb_t *out, const sc_poly_mpz_t *in)
{
    size_t i;
    for (i=in->len; i--;) {
        out[i] = sc_mpz_get_ui(&in->p[i]);
    }
    return in->len;
}

size_t sc_poly_mpz_to_si(sc_slimb_t *out, const sc_poly_mpz_t *in)
{
    size_t i;
    for (i=in->len; i--;) {
        out[i] = sc_mpz_get_si(&in->p[i]);
    }
    return in->len;
}

size_t sc_poly_mpz_to_ui32(UINT32 *out, const sc_poly_mpz_t *in)
{
    size_t i;
    for (i=in->len; i--;) {
        out[i] = (UINT32) sc_mpz_get_ui(&in->p[i]);
    }
    return in->len;
}

size_t sc_poly_mpz_to_si32(SINT32 *out, const sc_poly_mpz_t *in)
{
    size_t i;
    for (i=in->len; i--;) {
        out[i] = (SINT32) sc_mpz_get_si(&in->p[i]);
    }
    return in->len;
}

void poly_limb_to_mpi_mod(sc_poly_mpz_t *out, const sc_ulimb_t *in,
    size_t n, const sc_mod_t *mod)
{
    size_t i;
    for (i=n; i--;) {
        sc_ulimb_t temp = limb_mod_l(in[i], mod->m, mod->m_inv, mod->norm);
        sc_mpz_set_si(&out->p[i], temp);
    }
}

void poly_dbl_to_mpi(sc_poly_mpz_t *out, size_t n, const DOUBLE *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_set_d(&out->p[i], in[i]);
    }
    out->len = n;
}

void poly_ui_to_mpi(sc_poly_mpz_t *out, size_t n, const sc_ulimb_t *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_set_ui(&out->p[i], in[i]);
    }
    out->len = n;
}

void poly_si_to_mpi(sc_poly_mpz_t *out, size_t n, const sc_slimb_t *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_set_si(&out->p[i], in[i]);
    }
    out->len = n;
}

void poly_ui32_to_mpi(sc_poly_mpz_t *out, size_t n, const UINT32 *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_set_ui(&out->p[i], in[i]);
    }
    out->len = n;
}

void poly_si32_to_mpi(sc_poly_mpz_t *out, size_t n, const SINT32 *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_set_si(&out->p[i], in[i]);
    }
    out->len = n;
}

void sc_poly_mpz_init(sc_poly_mpz_t *inout, size_t n)
{
    size_t i;
    inout->p = SC_MALLOC(n * sizeof(sc_mpz_t));
    inout->len = n;
    for (i=n; i--;) {
        sc_mpz_init(&inout->p[i]);
    }
}

void sc_poly_mpz_clear(sc_poly_mpz_t *inout)
{
    size_t i;
    for (i=inout->len; i--;) {
        sc_mpz_clear(&inout->p[i]);
    }
    SC_FREE(inout->p, inout->len * sizeof(sc_mpz_t));
}

void sc_poly_mpz_resize(sc_poly_mpz_t *inout, size_t n)
{
    size_t i;
    sc_poly_mpz_t temp;
    sc_poly_mpz_init(&temp, n);
    n = (n > inout->len)? inout->len : n;
    for (i=n; i--;) {
        temp.p[i] = inout->p[i];
    }
    sc_poly_mpz_clear(inout);
    inout->p = temp.p;
    inout->len = temp.len;
}

void sc_poly_mpz_negate(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in)
{
    size_t i;
    out->len = in->len;
    for (i=n; i--;) {
        sc_mpz_negate(out->p + i, in->p + i);
    }
}

void sc_poly_mpz_reverse(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in)
{
    size_t i;
    SINT32 deg_in = sc_poly_mpz_degree(in);

    out->len = in->len;
    sc_mpz_copy(&out->p[0], &in->p[0]);
    for (i=n-deg_in; i<n; i++) {
        sc_mpz_negate(out->p + i, in->p + n - i);
    }
    sc_mpz_copy(&out->p[0], &in->p[0]);
}

void sc_poly_mpz_mod_ring(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_sub(out->p + i, in->p + i, in->p + n + i);
    }
    for (i=out->len-n; i--;) {
        sc_mpz_set_ui(out->p + i + n, 0);
    }
}

SINT32 sc_poly_mpz_is_zero(const sc_poly_mpz_t *in)
{
    size_t i;
    SINT32 deg_in = sc_poly_mpz_degree(in);
    if (deg_in < 0) {
        return 0;
    }

    for (i=0; i<in->len; i++) {
        if (0 != sc_mpz_is_zero(in->p + i)) {
            return 0;
        }
    }
    return 1;
}

SINT32 sc_poly_mpz_compare(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b)
{
    SINT32 deg_a, deg_b;
    deg_a = sc_poly_mpz_degree(a);
    deg_b = sc_poly_mpz_degree(b);

    if (deg_a < 0) {
        if (deg_b < 0) {
            return 0;
        }
        else { // deg_b >= 0
            return -1;
        }
    }
    else { // deg_a >= 0
        if (deg_b < 0) {
            return 1;
        }
        else if (deg_a == deg_b) {
            return sc_mpz_cmp(&a->p[deg_a], &b->p[deg_b]);
        }
        else if (deg_a < deg_b) {
            return -1;
        }
        else { // deg_a > deg_b
            return 1;
        }
    }
}

SINT32 sc_poly_mpz_max_bits(const sc_poly_mpz_t *x)
{
    size_t i, max_limbs = 1;
    sc_ulimb_t limb_mask = 0;

    for (i=x->len; i--;) {
        sc_mpz_max_bits(&x->p[i], &limb_mask, &max_limbs);
    }

    return ((max_limbs-1) * SC_LIMB_BITS + SC_LIMB_BITS - limb_clz(limb_mask));
}

SINT32 sc_poly_mpz_is_neg(const sc_poly_mpz_t *x)
{
    size_t i;

    for (i=x->len; i--;) {
        if (sc_mpz_is_neg(&x->p[i])) {
            return 1;
        }
    }

    return 0;
}

void sc_poly_mpz_copy(sc_poly_mpz_t *out, size_t n, const sc_poly_mpz_t *in)
{
    size_t i;
    n = SC_MIN(SC_MIN(n, in->len), out->len);
    for (i=n; i--;) {
        sc_mpz_copy(&out->p[i], &in->p[i]);
    }
}

void sc_poly_mpz_copy_si32(sc_poly_mpz_t *out, size_t n, const SINT32 *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_set_si(&out->p[i], in[i]);
    }
}

void sc_poly_mpz_copy_ui32(sc_poly_mpz_t *out, size_t n, const UINT32 *in)
{
    size_t i;
    for (i=n; i--;) {
        sc_mpz_set_ui(&out->p[i], in[i]);
    }
}

void sc_poly_mpz_reset(sc_poly_mpz_t *inout, size_t offset)
{
    size_t i;
    for (i=offset; i<inout->len; i++) {
        sc_mpz_set_si(&inout->p[i], 0);
    }
}

sc_mpz_t * sc_poly_mpz_get_mpi(sc_poly_mpz_t *in, size_t i)
{
    if (i > in->len) {
        return NULL;
    }
    return &in->p[i];
}

sc_ulimb_t sc_poly_mpz_get_ui(const sc_poly_mpz_t *in, size_t index)
{
    if (index >= in->len) {
        return 0;
    }
    return sc_mpz_get_ui(&in->p[index]);
}

sc_slimb_t sc_poly_mpz_get_si(const sc_poly_mpz_t *in, size_t index)
{
    if (index >= in->len) {
        return 0;
    }
    return sc_mpz_get_si(&in->p[index]);
}

DOUBLE sc_poly_mpz_get_d(const sc_poly_mpz_t *in, size_t index)
{
    if (index >= in->len) {
        return 0;
    }
    return sc_mpz_get_d(&in->p[index]);
}

SINT32 sc_poly_mpz_set_mpi(sc_poly_mpz_t *inout, size_t index, const sc_mpz_t *value)
{
    
    if (index >= inout->len) {
        return SC_FUNC_FAILURE;
    }
    sc_mpz_copy(&inout->p[index], value);
    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpz_set_si(sc_poly_mpz_t *inout, size_t index, sc_slimb_t value)
{
    if (index >= inout->len) {
        return SC_FUNC_FAILURE;
    }
    sc_mpz_set_si(&inout->p[index], value);
    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpz_set_ui(sc_poly_mpz_t *inout, size_t index, sc_ulimb_t value)
{
    if (index >= inout->len) {
        return SC_FUNC_FAILURE;
    }
    sc_mpz_set_ui(&inout->p[index], value);
    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpz_set_d(sc_poly_mpz_t *inout, size_t index, DOUBLE value)
{
    if (index >= inout->len) {
        return SC_FUNC_FAILURE;
    }
    sc_mpz_set_d(&inout->p[index], value);
    return SC_FUNC_SUCCESS;
}

void sc_poly_mpz_mod(sc_poly_mpz_t *out, const sc_poly_mpz_t *in, const sc_mod_t *mod)
{
#if 1
    SINT32 i, len_a, len_b;
    len_a = (out->len < in->len)? out->len : in->len;
    len_b = (out->len < in->len)? 0 : out->len;

    for (i=0; i<len_a; i++) {
        sc_mpz_mod_ui(&out->p[i], &in->p[i], mod->m);
    }
    for (i=len_a; i<len_b; i++) {
        sc_mpz_set_si(&out->p[i], 0);
    }
#else
    size_t i;
    for (i=0; i<in->len; i++) {
        sc_mpz_mod_limb(&out->p[i], &in->p[i], mod->m);
    }
#endif
}

void sc_poly_mpz_add_scalar(sc_poly_mpz_t *poly, const sc_mpz_t *in)
{
    size_t i;
    for (i=0; i<poly->len; i++) {
        sc_mpz_add(&poly->p[i], &poly->p[i], in);
    }
}

void sc_poly_mpz_sub_scalar(sc_poly_mpz_t *poly, const sc_mpz_t *in)
{
    size_t i;
    for (i=0; i<poly->len; i++) {
        sc_mpz_sub(&poly->p[i], &poly->p[i], in);
    }
}

void sc_poly_mpz_mul_scalar(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_mpz_t *in2)
{
    size_t i;
    SINT32 deg = sc_poly_mpz_degree(in1);

    for (i=deg + 1; i--;) {
        sc_mpz_mul(&out->p[i], &in1->p[i], in2);
    }
}

void sc_poly_mpz_mul_scalar_ui(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, sc_ulimb_t in2)
{
    size_t i;
    SINT32 deg = sc_poly_mpz_degree(in1);

    for (i=deg + 1; i--;) {
        sc_mpz_mul_ui(&out->p[i], &in1->p[i], in2);
    }
}

void sc_poly_mpz_add(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
    size_t i, min_len;
    min_len = SC_MIN(SC_MIN(in1->len, in2->len), out->len);

    for (i=min_len; i--;) {
        sc_mpz_add(&out->p[i], &in1->p[i], &in2->p[i]);
    }
}

void sc_poly_mpz_add_offset(sc_poly_mpz_t *out, size_t out_idx,
    const sc_poly_mpz_t *in1, size_t in1_idx, const sc_poly_mpz_t *in2, size_t in2_idx, size_t m)
{
    size_t i;
    for (i=m; i--;) {
        sc_mpz_add(&out->p[i + out_idx], &in1->p[i + in1_idx], &in2->p[i + in2_idx]);
    }
}

void sc_poly_mpz_sub(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
    size_t i, min_len;
    min_len = SC_MIN(SC_MIN(in1->len, in2->len), out->len);

    for (i=min_len; i--;) {
        sc_mpz_sub(out->p + i, in1->p + i, in2->p + i);
    }

    func_move_ptr move = (in1->len < in2->len)? sc_mpz_negate : sc_mpz_copy;
    for (i=in2->len - min_len; i--;) {
        move(out->p + i + min_len, in2->p + i + min_len);
    }
}

void sc_poly_mpz_sub_offset(sc_poly_mpz_t *out, size_t out_idx,
    const sc_poly_mpz_t *in1, size_t in1_idx, const sc_poly_mpz_t *in2, size_t in2_idx, size_t m)
{
    size_t i, min_len;
    min_len = SC_MIN(SC_MIN(SC_MIN(in1->len - in1_idx, in2->len - in2_idx), out->len - out_idx), m);

    for (i=min_len; i--;) {
        sc_mpz_sub(&out->p[i+out_idx], &in1->p[i+in1_idx], &in2->p[i+in2_idx]);
    }

    func_move_ptr move = ((min_len - in1_idx) < (min_len - in2_idx))? sc_mpz_negate : sc_mpz_copy;
    for (i=min_len; i<m; i++) {
        move(out->p + i + out_idx, in2->p + i + in2_idx);
    }
}

void sc_poly_mpz_add_single(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in)
{
    size_t i;

    size_t min_len;
    min_len = (in->len < inout->len)? in->len : inout->len;

    for (i=min_len; i--;) {
        sc_mpz_add(&inout->p[i], &inout->p[i], &in->p[i]);
    }
}

void sc_poly_mpz_sub_single(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in)
{
    size_t i;

    size_t min_len;
    min_len = (in->len < inout->len)? in->len : inout->len;

    for (i=min_len; i--;) {
        sc_mpz_sub(&inout->p[i], &inout->p[i], &in->p[i]);
    }
}

static void sc_poly_mpz_mul_gradeschool(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
    size_t i, j;

    // Ensure that the output polynomial is in1->len + in2->len in length
    if ((in1->len + in2->len - 1) > out->len) {
        abort();
    }

#if 1
    // This version provides an opportunity for early termination and avoids any initial zeroing

    for (j=in1->len; j--;) {
        sc_mpz_mul(&out->p[j], &in1->p[j], &in2->p[0]);
    }
    if (1 == in2->len) {
        return;
    }

    for (j=in2->len-1; j--;) {
        sc_mpz_mul(&out->p[j+in1->len], &in2->p[j+1], &in1->p[in1->len-1]);
    }
    
    for (i=in1->len-1; i--;) {
        for (j=in2->len-1; j--;) {
            sc_mpz_addmul(&out->p[j+i+1], &in2->p[j+1], &in1->p[i]);
        }
    }
#else
    sc_mpz_t product, sum;
    sc_mpz_init(&product);
    sc_mpz_init(&sum);

    // Clear the output polynomial from 0 to len
    sc_poly_mpz_reset(out, 0);

    // Multiply-accumulate over a window
    for (i=0; i<in1->len; i++) {
        for (j=0; j<in2->len; j++) {
            sc_mpz_mul(&product, &in1->p[i], &in2->p[j]);
            sc_mpz_add(&sum, &out->p[i+j], &product);
            sc_mpz_copy(&out->p[i+j], &sum);
        }
    }

    sc_mpz_clear(&product);
    sc_mpz_clear(&sum);
#endif
}

// Generate the reverse binary ordering of the input value for the given bit width
const size_t revbin(size_t in, size_t bits)
{
    size_t out;
    out = sc_bit_reverse(in);
    out >>= SC_LIMB_BITS - bits;
    return out;
}

// Reorder the output polynomial coefficients to reverse binary ordering
static void revbin_fwd(sc_poly_mpz_t *out, const sc_poly_mpz_t *in, size_t bits)
{
    size_t i, j;
    for (i=in->len; i--;) {
        j = revbin(i, bits);
        sc_mpz_copy(&out->p[j], &in->p[i]);
    }
}

// Restore the output polynomial coefficients from reverse binary ordering
static void revbin_inv(sc_poly_mpz_t *out, const sc_poly_mpz_t *in, size_t len, size_t bits)
{
    size_t i, j;
    for (i=len; i--;) {
        j = revbin(i, bits);
        sc_mpz_copy(&out->p[i], &in->p[j]);
    }
}

// Add polynomial in2 to in1, reversing the order of in1 in the process
static void sc_poly_mpz_add_rev(sc_poly_mpz_t *in1, size_t in1_idx, sc_poly_mpz_t *in2, size_t in2_idx, size_t bits)
{
    size_t i;
    for (i=(SC_LIMB_WORD(1) << bits) - 1; i--;) {
        size_t j = revbin(revbin(i, bits) + 1, bits);
        sc_mpz_add(in1->p + j + in1_idx, in1->p + j + in1_idx, in2->p + i + in2_idx);
    }
}

static void sc_poly_mpz_mul_karatsuba_recursive(sc_poly_mpz_t *out, size_t out_idx,
    sc_poly_mpz_t *rev1, size_t rev1_idx,
    sc_poly_mpz_t *rev2, size_t rev2_idx,
    sc_poly_mpz_t *temp, size_t temp_idx, size_t log_len)
{
    size_t length = SC_LIMB_WORD(1) << log_len;
    size_t m = length >> 1;

    // At the cutoff point return a product
    if (1 == length) {
        sc_mpz_mul(&out->p[out_idx], &rev1->p[rev1_idx], &rev2->p[rev2_idx]);
        sc_mpz_set_ui(&out->p[out_idx+1], 0);
        return;
    }

    // The following splits the inputs and applies Karatsuba:
    //     x  = x1.B^m + x0, y = y1.B^m + y0
    //     xy = (x1.B^m + x0)(y1.B^m + y0)
    //        = z2.B^2 + z1.B^m + z2
    //   where z2 = x1y1, z0 = x0y0 and z1 = (x1 + x0)(y1 + y0) - z1 - z0

    // Calculate the sum of the input coefficients
    sc_poly_mpz_add_offset(temp, temp_idx, rev1, rev1_idx, rev1, rev1_idx + m, m);
    sc_poly_mpz_add_offset(temp, temp_idx + m, rev2, rev2_idx, rev2, rev2_idx + m, m);

    // Calculate the three products
    sc_poly_mpz_mul_karatsuba_recursive(out, out_idx, rev1, rev1_idx, rev2, rev2_idx, temp, temp_idx + 2 * m, log_len - 1);
    sc_poly_mpz_mul_karatsuba_recursive(out, out_idx + length, temp, temp_idx, temp, temp_idx + m, temp, temp_idx + 2 * m, log_len - 1);
    sc_poly_mpz_mul_karatsuba_recursive(temp, temp_idx, rev1, rev1_idx + m, rev2, rev2_idx + m, temp, temp_idx + 2 * m, log_len - 1);

    // Perform addition of the products
    sc_poly_mpz_sub_offset(out, out_idx + length, out, out_idx + length, out, out_idx, length);
    sc_poly_mpz_sub_offset(out, out_idx + length, out, out_idx + length, temp, temp_idx, length);
    sc_poly_mpz_add_rev(out, out_idx, temp, temp_idx, log_len);
}

static void sc_poly_mpz_mul_karatsuba(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
    sc_poly_mpz_t rev1, rev2, out2, intermediate;
    size_t length, log_len = 0;

    // NOTE: in1->len >= in2->len by convention, so single-precision multiply
    // to avoid unnecessary computation here
    if (in1->len == 1) {
        sc_mpz_mul(&out->p[0], &in1->p[0], &in2->p[0]);
        return;
    }

    // Obtain the ceiling log base 2 of the length of the largest
    // of the two multiplicands (by convention of this implementation)
    log_len = sc_ceil_log2(in1->len);
    length  = SC_LIMB_WORD(1) << log_len;

    // Initialise all of the temporary polynomials
    sc_poly_mpz_init(&rev1, length);
    sc_poly_mpz_init(&rev2, length);
    sc_poly_mpz_init(&out2, 2*length);
    sc_poly_mpz_init(&intermediate, 2*length);

    // Reverse the input multiplicands
    revbin_fwd(&rev1, in1, log_len);
    revbin_fwd(&rev2, in2, log_len);

    // Make the initial call to the recursive Karatsuba algorithm
    sc_poly_mpz_mul_karatsuba_recursive(&out2, 0, &rev1, 0, &rev2, 0,
        &intermediate, 0, log_len);

    // Reset the most significant words of the intermediate output and
    // copy the reversed polynomial to the output
    sc_poly_mpz_reset(out, in1->len + in2->len);
    revbin_inv(out, &out2, in1->len + in2->len - 1, log_len + 1);

    // Free resources for all of the temporary polynomials
    sc_poly_mpz_clear(&rev1);
    sc_poly_mpz_clear(&rev2);
    sc_poly_mpz_clear(&out2);
    sc_poly_mpz_clear(&intermediate);
}

static void sc_poly_mpz_ks_bit_pack(sc_ulimb_t *out, const sc_poly_mpz_t *in, size_t len,
    SINT32 bit_size, SINT32 sign)
{
    size_t i, j, limbs = 0, bits = 0;
    SINT32 borrow = 0;

    // Determine the number of limbs per output coefficient
    size_t l = bit_size / SC_LIMB_BITS;
    size_t b = bit_size % SC_LIMB_BITS;

    for (i=0; i<len; i++) {
        SINT32 coeff_sign = sc_mpz_sign(&in->p[i]);
        size_t coeff_limbs = (bit_size + bits) / SC_LIMB_BITS;
        size_t rem_bits    = (bit_size + bits) % SC_LIMB_BITS;

        // Save the least significant word
        sc_ulimb_t save = out[limbs];

        // Zero coefficients ...
        if (0 == coeff_sign) {
            if (borrow) {
                // store -1 shifted and add save back in
                out[limbs] = ((~(sc_ulimb_t) 0) << bits) + save;

                // Bitwise complement remaining limbs
                if (coeff_limbs > 1) {
                    for (j=1; j<coeff_limbs; j++) {
                        out[limbs + j] = ~(sc_ulimb_t) 0;
                    }
                }

                // Bitwise complement of remaining bits
                if (coeff_limbs) {
                    if (rem_bits) {
                        out[limbs+coeff_limbs] = (((sc_ulimb_t) 1) << rem_bits) - (sc_ulimb_t) 1;
                    }
                }
                else {
                    // mask off final limb
                    sc_ulimb_t mask = (((sc_ulimb_t) 1) << rem_bits) - (sc_ulimb_t) 1;
                    out[limbs+coeff_limbs] &= mask;
                }
            }

            goto update_position;
        }

        SINT32 in_size = sc_mpz_get_size(in->p + i);
        size_t size = (in_size < 0)? -in_size : in_size;

        if ((coeff_sign ^ sign) < 0) {
            // Coeff is negative and sign is zero, or coeff is positive and sign is negative,
            // then copy the bitwise complement of the data to the Kronecker big integer
            // and add 1
            sc_mpz_com_to_poly_limb(out + limbs, sc_mpz_get_limbs(&in->p[i]), size);
            if (!borrow) {
                limb_mp_add_1(out + limbs, out + limbs, size, 1);
            }

            if (bits) {
                sc_ulimb_t cy = limb_mp_lshift(out + limbs, out + limbs, size, bits);
                if (coeff_limbs + (rem_bits != 0) > size) {
                    out[limbs + size++] = ((~(sc_ulimb_t) 0) << bits) + cy;
                }
            }
            out[limbs] += save;

            if (coeff_limbs >= size) {
                if (coeff_limbs > size) {
                    for (j=size; j<coeff_limbs; j++) {
                        out[limbs + j] = ~(sc_ulimb_t) 0;
                    }
                }

                if (rem_bits) {
                    out[limbs + coeff_limbs] = (((sc_ulimb_t) 1) << rem_bits) - (sc_ulimb_t) 1;
                }
            }
            else {
                sc_ulimb_t mask = (((sc_ulimb_t) 1) << rem_bits) - (sc_ulimb_t) 1;
                out[limbs + coeff_limbs] &= mask;
            }

            borrow = 1;
        }
        else {
            // Copy the limbs to the output polynomial
            sc_ulimb_t *in_limbs = sc_poly_mpz_get_limbs(in, i);
            if (bits) {
                sc_ulimb_t cy = limb_mp_lshift(out + limbs, in_limbs, size, bits);
                if (cy) {
                    out[limbs + size++] = cy;
                }
            }
            else {
                poly_limb_copy(out + limbs, size, in_limbs);
            }

            if (borrow) {
                limb_mp_sub_1(out + limbs, out + limbs, size, ((sc_ulimb_t) 1) << bits);
            }

            out[limbs] += save;

            borrow = 0;
        }

update_position:
        limbs += l;
        bits += b;
        if (bits >= SC_LIMB_BITS)
        {
            bits -= SC_LIMB_BITS;
            limbs++;
        }
    }
}

static void sc_poly_mpz_ks_bit_unpack(sc_poly_mpz_t *out, size_t len,
    const sc_ulimb_t *in, SINT32 bit_size, SINT32 sign)
{
    size_t i, limbs = 0, bits = 0, size;
    sc_ulimb_t coeff_sign;
    SINT32 borrow = 0;

    size_t l = bit_size >> SC_LIMB_BITS_SHIFT;
    size_t b = bit_size & SC_LIMB_BITS_MASK;

    for (i=0; i<len; i++) {
        //borrow = fmpz_bit_unpack(poly + i, arr + limbs, bits, bit_size, negate, borrow);

        size_t coeff_limbs = (bit_size + bits) >> SC_LIMB_BITS_SHIFT;
        size_t rem_bits    = (bit_size + bits) & SC_LIMB_BITS_MASK;
        size_t b2          = bit_size & SC_LIMB_BITS_MASK;

        sc_ulimb_t *out_limbs = mpz_realloc(out->p + i, b2);
        //sc_ulimb_t *out_limbs = sc_poly_mpz_get_limbs(out, i);

        // Determine if the output coefficient is negative
        if (rem_bits) {
            coeff_sign = SC_LIMB_LSHIFT(1, rem_bits - 1) & in[limbs + coeff_limbs];
        }
        else {
            coeff_sign = SC_LIMB_LSHIFT(1, SC_LIMB_BITS - 1) & in[limbs + coeff_limbs - 1];
        }

        // Obtain the shifted input at limb granularity
        size  = (bit_size - 1) / SC_LIMB_BITS + 1;
        if (bits) {
            limb_mp_rshift(out_limbs, in + limbs, size, bits);
        }
        else {
            poly_limb_copy(out_limbs, size, in + limbs);
        }

        // Obtain any remaining data at bit granularity
        if (coeff_limbs + (rem_bits != 0) > size) {
            out_limbs[size - 1] += SC_LIMB_LSHIFT(in[limbs + coeff_limbs], SC_LIMB_BITS - bits);
        }

        if (b2) {
            sc_ulimb_t mask = SC_LIMB_LSHIFT(1, b2) - 1;
            out_limbs[size - 1] &= mask;
        }

        if (coeff_sign) {
            // Sign extension of the MSW of the multiple precision coefficient
            if (b2) {
                out_limbs[size - 1] += (SC_LIMB_LSHIFT(SC_LIMB_MASK, b2));
            }

            // Copy the bitwise complement of the data to the Kronecker
            // big integer and add 1
            sc_mpz_com_to_poly_limb(sc_mpz_get_limbs(&out->p[i]), sc_mpz_get_limbs(&out->p[i]), size);
            if (!borrow) {
                limb_mp_add_1(out_limbs, out_limbs, size, 1);
            }

            while (size && 0 == (out_limbs[size - 1])) {
                size--;
            }
            sc_mpz_set_size(out->p + i, -size);

            borrow = 1;
        }
        else {
            if (borrow) {
                limb_mp_add_1(out_limbs, out_limbs, size, 1);
            }

            while (size && (0 == out_limbs[size - 1])) {
                size--;
            }
            sc_mpz_set_size(out->p + i, size);

            borrow = 0;
        }

        if (sign) {
            sc_mpz_negate(&out->p[i], &out->p[i]);
        }

        limbs += l;
        bits += b;
        if (bits >= SC_LIMB_BITS) {
            bits -= SC_LIMB_BITS;
            limbs++;
        }
    }
}

static void sc_poly_mpz_mul_kronecker(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
    SINT32 deg_in1, deg_in2, sign_in1, sign_in2,
           bits_in1, bits_in2, bits, sign;
    size_t len_in1 = 0, len_in2 = 0, log_len, limbs_in1, limbs_in2,
           depth;

    if (NULL == out || NULL == in1 || NULL == in2) {
        goto return_zero;
    }

    // Determine the degree and length of the multiplicands
    deg_in1 = sc_poly_mpz_degree(in1);
    if (deg_in1 < 0) {
        return;
    }
    deg_in2 = sc_poly_mpz_degree(in2);
    if (deg_in2 < 0) {
        return;
    }
    len_in1 = (0 == deg_in1 && sc_mpz_is_zero(&in1->p[0]))? 0 : (size_t)deg_in1 + 1;
    len_in2 = (0 == deg_in2 && sc_mpz_is_zero(&in2->p[0]))? 0 : (size_t)deg_in2 + 1;

    if (0 == len_in1 || 0 == len_in2) {
        goto return_zero;
    }

    // Calculate the maximum number of bits in a product coefficient
    sign_in1 = (sc_mpz_sign(&in1->p[deg_in1]) >= 0)? 0 : -1;
    sign_in2 = (sc_mpz_sign(&in2->p[deg_in2]) >= 0)? 0 : -1;
    sign     = sc_poly_mpz_is_neg(in1);
    sign    |= sc_poly_mpz_is_neg(in2);
    bits_in1 = sc_poly_mpz_max_bits(in1);
    bits_in2 = 0;
    if (in1 != in2) {
        bits_in2 = sc_poly_mpz_max_bits(in2);
    }
    log_len  = SC_LIMB_BITS - limb_clz((len_in1 < len_in2)? len_in1 : len_in2);
    bits     = bits_in1 + bits_in2 + log_len + sign;

    // Compute the maximum total number of limbs in each polynomial
    limbs_in1 = ((bits * len_in1 - 1) >> SC_LIMB_BITS_SHIFT) + 1;
    limbs_in2 = ((bits * len_in2 - 1) >> SC_LIMB_BITS_SHIFT) + 1;

    // Compute the required memory
    depth = 2*(limbs_in1 + limbs_in2);
    if (in1 == in2) {
        depth -= limbs_in2;
    }

    // Obtain temporary memory for the output packed result
    sc_ulimb_t *packed, *packed_in1, *packed_in2;
    packed = SC_MALLOC(sizeof(sc_ulimb_t) * depth);

    // If we're squaring pack the first polynomial only
    packed_in1 = packed + limbs_in1 + limbs_in2;
    if (in1 == in2) {
        packed_in2 = packed_in1;
        sc_poly_mpz_ks_bit_pack(packed_in1, in1, len_in1, bits, sign_in1);
    }
    else {
        packed_in2 = packed_in1 + limbs_in1;
        sc_poly_mpz_ks_bit_pack(packed_in1, in1, len_in1, bits, sign_in1);
        sc_poly_mpz_ks_bit_pack(packed_in2, in2, len_in2, bits, sign_in2);
    }

    // Perform the computation using GMPs natural multi-precision
    // low-level functions designed for speed
    if (limbs_in1 == limbs_in2)
        limb_mp_mul_n(packed, packed_in1, packed_in2, limbs_in1);
    else if (limbs_in1 > limbs_in2)
        limb_mp_mul(packed, packed_in1, limbs_in1, packed_in2, limbs_in2);
    else
        limb_mp_mul(packed, packed_in2, limbs_in2, packed_in1, limbs_in1);

    // Unpack the result
    sc_poly_mpz_ks_bit_unpack(out, len_in1 + len_in2 - 1, packed, bits, sign_in1 ^ sign_in2);

    // Free memory resources
    SC_FREE(packed, sizeof(sc_ulimb_t) * depth);

    return;

return_zero:
    // Return a zero output product of length (len_in1+len_in2-1)
    if ((len_in1 + len_in2 - 1) > 0) {
        sc_poly_mpz_reset(out, 0);
    }
}

void sc_poly_mpz_mul(sc_poly_mpz_t *out, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
    if (in1->len < in2->len) {
        sc_poly_mpz_mul(out, in2, in1);
        return;
    }

    // Check for squaring
    /// @todo Need a poly MPZ square function
    //if (in1 == in2 && in1->len == in2->len) {
    //}

    if (in2->len < 7)
    {
        sc_poly_mpz_mul_gradeschool(out, in1, in2);
        return;
    }

    SINT32 bits1  = sc_poly_mpz_max_bits(in1);
    SINT32 bits2  = sc_poly_mpz_max_bits(in2);
    size_t limbs1 = (bits1 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
    size_t limbs2 = (bits2 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;

    if (in1->len < 16 && (limbs1 > 12 || limbs2 > 12)) {
        sc_poly_mpz_mul_karatsuba(out, in1, in2);
    }
    else if (limbs1 + limbs2 <= 8) {
        sc_poly_mpz_mul_kronecker(out, in1, in2);
    }
    else if ((limbs1+limbs2)/2048 > in1->len + in2->len) {
        sc_poly_mpz_mul_kronecker(out, in1, in2);
    }
    else if ((limbs1 + limbs2)*SC_LIMB_BITS*4 < in1->len + in2->len) {
        sc_poly_mpz_mul_kronecker(out, in1, in2);
    }
    else {
        sc_poly_mpz_mul_karatsuba(out, in1, in2);
    }
}

void sc_poly_mpz_addmul(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
    // Multiply-accumulate over a window
#if 1
    sc_poly_mpz_t product;
    sc_poly_mpz_init(&product, in1->len + in2->len - 1);
    sc_poly_mpz_mul(&product, in1, in2);
    sc_poly_mpz_add(inout, inout, &product);
    sc_poly_mpz_clear(&product);
#else
    size_t i, j;
#if 1
    for (j=in1->len; j--;) {
        sc_mpz_addmul(&inout->p[j], &in1->p[j], &in2->p[0]);
    }

    if (1 == in2->len) {
        return;
    }

    for (j=in2->len-1; j--;) {
        sc_mpz_addmul(&inout->p[j+in1->len], &in1->p[in1->len-1], &in2->p[j+1]);
    }

    for (i=in1->len-1; i--;) {
        for (j=in2->len-1; j--;) {
            sc_mpz_addmul(&inout->p[1+j+i], &in1->p[i], &in2->p[j+1]);
        }
    }
#else
    for (i=in1->len; i--;) {
        for (j=in2->len; j--;) {
            sc_mpz_addmul(&inout->p[i+j], &in1->p[i], &in2->p[j]);
        }
    }
#endif
#endif
}

void sc_poly_mpz_submul(sc_poly_mpz_t *inout, const sc_poly_mpz_t *in1, const sc_poly_mpz_t *in2)
{
#if 0
    sc_poly_mpz_t product, sub;
    sc_poly_mpz_init(&product, in1->len + in2->len - 1);
    sc_poly_mpz_init(&sub, in1->len + in2->len - 1);
    sc_poly_mpz_mul(&product, in1, in2);
    sc_poly_mpz_sub(&sub, inout, &product);
    sc_poly_mpz_copy(inout, &sub, in1->len + in2->len - 1);
    sc_poly_mpz_clear(&product);
    sc_poly_mpz_clear(&sub);
#else
    size_t i, j;
    sc_mpz_t product, sum;
    sc_mpz_init(&product);
    sc_mpz_init(&sum);

    // Ensure that the output polynomial is in1->len + in2->len in length
    if ((in1->len + in2->len) > inout->len) {
        abort();
    }

    // Multiply-accumulate over a window
    for (i=in1->len; i--;) {
        for (j=in2->len; j--;) {
            sc_mpz_mul(&product, &in1->p[i], &in2->p[j]);
            sc_mpz_sub(&sum, &inout->p[i+j], &product);
            sc_mpz_copy(&inout->p[i+j], &sum);
        }
    }

    sc_mpz_clear(&product);
    sc_mpz_clear(&sum);
#endif
}

void sc_poly_mpz_addmul_scalar(sc_poly_mpz_t *inout,
    const sc_poly_mpz_t *in1, const sc_mpz_t *in2)
{
#if 0
    sc_poly_mpz_t product;
    sc_poly_mpz_t temp;
    sc_poly_mpz_init(&product, in1->len);
    sc_poly_mpz_init(&temp, 1);
    sc_poly_mpz_set_mpi(&temp, 0, in2);
    sc_poly_mpz_mul(&product, in1, &temp);
    sc_poly_mpz_add(inout, inout, &product);
    sc_poly_mpz_clear(&product);
    sc_poly_mpz_clear(&temp);
#else
    size_t i;
    for (i=in1->len; i--;) {
        sc_mpz_addmul(&inout->p[i], &in1->p[i], in2);
    }
#endif
}

void sc_poly_mpz_submul_scalar(sc_poly_mpz_t *inout,
    const sc_poly_mpz_t *in1, const sc_mpz_t *in2)
{
    size_t i;
    for (i=in1->len; i--;) {
        sc_mpz_submul(&inout->p[i], &in1->p[i], in2);
    }
}

void sc_poly_mpz_uniform_rand(prng_ctx_t *ctx, sc_poly_mpz_t *v, const UINT16 *c, size_t c_len)
{
    size_t i, j;
    UINT32 mask = v->len - 1;

    // Reset the output polynomial to all zeros
    sc_poly_mpz_reset(v, 0);

    // Given the list of coefficient occurences c (in descending order of value),
    // randomly place the correct number of signed coefficients within the
    // polynomial of dimension n.
    for (j=0; j<c_len; j++) {
        i = 0;
        while (i < c[j]) {
            UINT32 rand = prng_32(ctx);
            size_t index = (rand >> 1) & mask;
            if (0 == sc_mpz_cmp_si(&v->p[index], 0)) {
                sc_mpz_set_d(&v->p[index], (DOUBLE)((rand & 1)? j-c_len : c_len-j));
                i++;
            }
        }
    }
}

SINT32 sc_poly_mpz_degree(const sc_poly_mpz_t *h)
{
    SINT32 deg = -1;
    if (NULL != h && h->len > 0) {
        size_t j = h->len - 1;
        while (0 == sc_mpz_cmp_si(&h->p[j], 0)) {
            if (0 == j) break;
            j--;
        }
        deg = j;
    }
    return deg;
}

void sc_poly_mpz_div_pointwise(sc_poly_mpz_t *q, const sc_poly_mpz_t *num, const sc_mpz_t *den)
{
    size_t i;

    if (num->len != q->len) {
        abort();
    }

    for (i=num->len; i--;) {
        sc_mpz_divquo(&q->p[i], &num->p[i], den);
    }
}

SINT32 sc_poly_mpz_divquo(const sc_poly_mpz_t *num, const sc_poly_mpz_t *den, sc_poly_mpz_t *q)
{
    SINT32 j, k;
    SINT32 deg_num, deg_den;
    sc_poly_mpz_t r;

    deg_num = sc_poly_mpz_degree(num);
    if (deg_num < 0) {
        return SC_FUNC_FAILURE;
    }

    deg_den = sc_poly_mpz_degree(den);
    if (deg_den < 0) {
        return SC_FUNC_FAILURE;
    }

    if (q->len < (deg_num - deg_den + 1)) {
        abort();
    }

    sc_poly_mpz_init(&r, num->len);

    // r = num, q = 0
    sc_poly_mpz_copy(&r, num->len, num);
    sc_poly_mpz_reset(q, 0);

    if (deg_num < deg_den) {
        return SC_FUNC_SUCCESS;
    }

    for (k=deg_num-deg_den; k>=0; k--) {
        sc_mpz_divquo(&q->p[k], &r.p[deg_den+k], &den->p[deg_den]);
        for (j=deg_den+k-1; j>=k; j--) {
            sc_mpz_submul(&r.p[j], &q->p[k], &den->p[j-k]);
        }
    }

    sc_poly_mpz_clear(&r);

    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpz_div(const sc_poly_mpz_t *num, const sc_poly_mpz_t *den, sc_poly_mpz_t *q, sc_poly_mpz_t *r)
{
    SINT32 j, k;
    SINT32 deg_num, deg_den, abs_deg_diff;

    deg_num = sc_poly_mpz_degree(num);
    if (deg_num < 0) {
        return SC_FUNC_FAILURE;
    }

    deg_den = sc_poly_mpz_degree(den);
    if (deg_den < 0) {
        return SC_FUNC_FAILURE;
    }

    abs_deg_diff = deg_num - deg_den;
    if (abs_deg_diff < 0) {
        abs_deg_diff = -abs_deg_diff;
    }
    if (num->len > r->len || q->len < (abs_deg_diff + 1)) {
        abort();
    }

    // r = num, q = 0
    sc_poly_mpz_copy(r, num->len, num);
    sc_poly_mpz_reset(q, 0);

    if (deg_num >= deg_den) {
        for (k=deg_num-deg_den; k>=0; k--) {
            sc_mpz_divquo(&q->p[k], &r->p[deg_den+k], &den->p[deg_den]);
            for (j=deg_den+k; j>=k; j--) {
                sc_mpz_submul(&r->p[j], &q->p[k], &den->p[j-k]);
            }
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpz_content(sc_mpz_t *res, const sc_poly_mpz_t *poly)
{
    SINT32 deg = sc_poly_mpz_degree(poly);
    if (deg < 0) {
        return SC_FUNC_FAILURE;
    }
    deg++;

    sc_mpz_set_si(res, 0);
    while (deg--) {
        sc_mpz_gcd(res, &poly->p[deg], res);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpz_content_scale(const sc_poly_mpz_t *in, const sc_mpz_t *content, sc_poly_mpz_t *out)
{
    size_t k;
    SINT32 deg_in = sc_poly_mpz_degree(in);
    if (deg_in < 0) {
        return SC_FUNC_FAILURE;
    }

    for (k=deg_in+1; k--;) {
        sc_mpz_divquo(&out->p[k], &in->p[k], content);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpz_crt(sc_poly_mpz_t *result, const sc_poly_mpz_t *a, SINT32 deg_a, const sc_mpz_t *a_m,
    sc_ulimb_t *b, SINT32 deg_b, sc_mod_t *b_m)
{
    size_t i;
    sc_mpz_t m, temp;
    sc_ulimb_t a_m_32;
    SINT32 min_deg = (deg_a < deg_b)? deg_a : deg_b;

    // Ensure that a_m is invertible modulo b_m->m
    a_m_32 = sc_mpz_get_ui_mod(a_m, b_m);
    a_m_32 = limb_inv_mod(a_m_32, b_m->m);
    if (0 == a_m_32) {
        return SC_FUNC_FAILURE;
    }

    // Precompute the product of a_m and b_m->m
    sc_mpz_init(&m);
    sc_mpz_init(&temp);
    sc_mpz_set_ui(&m, b_m->m);
    sc_mpz_mul_scalar(&m, a_m);

    // Calculate the CRT
    for (i=min_deg+1; i--;) {
        sc_mpz_crt(&result->p[i], &a->p[i], a_m, b[i], b_m, a_m_32, &m, &temp);
    }
    if (deg_b > deg_a) {
        sc_mpz_t zero;
        sc_mpz_init(&zero);
        for (i=deg_a+1; i<=deg_b; i++) {
            sc_mpz_crt(&result->p[i], &zero, a_m, b[i], b_m, a_m_32, &m, &temp);
        }
        sc_mpz_clear(&zero);
    }
    else {
        for (i=deg_b+1; i<=deg_a; i++) {
            sc_mpz_crt(&result->p[i], &a->p[i], a_m, 0, b_m, a_m_32, &m, &temp);
        }
    }
    sc_mpz_clear(&m);
    sc_mpz_clear(&temp);

    return SC_FUNC_SUCCESS;
}

sc_ulimb_t * sc_poly_mpz_get_limbs(const sc_poly_mpz_t *in, size_t index)
{
    return sc_mpz_get_limbs(in->p + index);
}

sc_ulimb_t sc_poly_mpz_get_limb_mod(sc_poly_mpz_t *a, size_t index, const sc_mod_t *mod)
{
    if (index >= a->len) {
        abort();
    }
    return sc_mpz_get_ui_mod(a->p + index, mod);
}

SINT32 sc_poly_mpz_gcd(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b, sc_poly_mpz_t *gcd)
{
    size_t i, n;
    SINT32 deg_a, deg_b, min_deg;
    sc_ulimb_t gp[n], p_a[n], p_b[n];
    sc_mpz_t gcd_ab, m, ac, bc, p, gamma, l, prime_check, tmp, hc;
    sc_poly_mpz_t gm, a_c, b_c, quo, rem, h;
    sc_mod_t modulus;
    
    deg_a = sc_poly_mpz_degree(a);
    if (deg_a < 0) {
        return SC_FUNC_FAILURE;
    }

    deg_b = sc_poly_mpz_degree(b);
    if (deg_b < 0) {
        return SC_FUNC_FAILURE;
    }

    n = (deg_a > deg_b)? deg_a + 1 : deg_b + 1;

    sc_mpz_init(&gcd_ab);
    sc_mpz_init(&m);
    sc_mpz_init(&ac);
    sc_mpz_init(&bc);
    sc_mpz_init(&p);
    sc_mpz_init(&gamma);
    sc_mpz_init(&l);
    sc_mpz_init(&prime_check);
    sc_mpz_init(&tmp);
    sc_mpz_init(&hc);
    sc_poly_mpz_init(&gm, n);
    sc_poly_mpz_init(&a_c, n);
    sc_poly_mpz_init(&b_c, n);
    sc_poly_mpz_init(&quo, n);
    sc_poly_mpz_init(&rem, n);
    sc_poly_mpz_init(&h, n);

    // Obtain the GCD of the content's of a and b
    sc_poly_mpz_content(&ac, a);
    sc_poly_mpz_content(&bc, b);
    sc_mpz_gcd(&ac, &bc, &gcd_ab);

    // Obtain minimal scaled versions of a and b
    if (0 == sc_mpz_cmp_si(&gcd_ab, 1)) {
        sc_poly_mpz_copy(&a_c, a->len, a);
        sc_poly_mpz_copy(&b_c, b->len, b);
    }
    else if (0 == sc_mpz_cmp_si(&gcd_ab, -1)) {
        sc_poly_mpz_negate(&a_c, deg_a+1, a);
        sc_poly_mpz_negate(&b_c, deg_b+1, b);
    }
    else {
        sc_poly_mpz_div_pointwise(&a_c, a, &gcd_ab);
        sc_poly_mpz_div_pointwise(&b_c, b, &gcd_ab);
    }

    // Determine the GCD of the leading coefficients
    sc_mpz_gcd(&a_c.p[deg_a], &b_c.p[deg_b], &gamma);
    sc_mpz_mul(&l, &a_c.p[deg_a], &b_c.p[deg_b]);

    // d := min( deg(f), deg(g) )
    min_deg = (deg_a < deg_b)? deg_a : deg_b;

    sc_mpz_set_ui(&m, SC_LIMB_WORD(1));
    limb_mod_init(&modulus, SC_LIMB_HIGHBIT);

    while (1) {
        SINT32 deg_gp, deg_gm;
        sc_ulimb_t gp_inv, gp_mod;

        // Find a prime p that is not divisble by m.gamma
        modulus.m     = next_prime(modulus.m);
        sc_mpz_set_ui(&p, modulus.m);
        sc_mpz_divrem(&prime_check, &l, &p);
        if (0 == sc_mpz_cmp_si(&prime_check, 0)) {
            continue;
        }

        // The modulus is acceptable, so compute the norm and
        // multiplicative inverse
        limb_mod_init(&modulus, modulus.m);

        // Reduce the polynomials modulo p
        for (i=deg_a+1; i--;) {
            p_a[i] = sc_poly_mpz_get_limb_mod(&a_c, i, &modulus);
        }

        // Compute the GCD over Z/pZ
        deg_gp = poly_limb_gcd_mod(gp, p_a, deg_a+1, p_b, deg_b+1, &modulus);
        deg_gp--;

        if (0 == deg_gp) {
            sc_poly_mpz_set_si(gcd, 0, 1);
            sc_poly_mpz_reset(gcd, 1);
            break;
        }
        if (deg_gp > min_deg) {
            continue;
        }

        // Scale the GCD over Z/pZ
        gp_inv = limb_inv_mod(gp[deg_gp], modulus.m);
        gp_mod = sc_mpz_floor_div_ui(&gcd_ab, modulus.m);
        gp_inv = limb_mul_mod(gp_inv, gp_mod, modulus.m, modulus.m_inv);
        poly_limb_mul_mod_scalar(gp, gp, deg_gp, gp_inv, &modulus);

        deg_gm = 0;
        if (deg_gp < min_deg) {
            sc_mpz_set_ui(&m, 1);
            sc_poly_mpz_reset(&gm, 0);
            min_deg = deg_gp;
        }

        // Use CRT to obtain h
        deg_gm = sc_poly_mpz_degree(&gm);
        sc_poly_mpz_crt(&h, &gm, deg_gm, &m, gp, deg_gp, &modulus);

        // Termination test if h == g_m
        if (0 == sc_poly_mpz_compare(&h, &gm)) {
            sc_poly_mpz_content(&hc, &h);
            sc_poly_mpz_div_pointwise(&h, &h, &hc);

            // Check if h is divisible by a and b
            sc_poly_mpz_div(&h, a, &quo, &rem);
            if (sc_poly_mpz_is_zero(&rem)) {
                sc_poly_mpz_div(&h, b, &quo, &rem);
                if (sc_poly_mpz_is_zero(&rem)) {
                    sc_poly_mpz_mul_scalar(&h, &h, &gcd_ab);
                    goto finish;
                }
            }
        }

        sc_mpz_mul(&m, &p, &m);
        sc_poly_mpz_copy(&gm, h.len, &h);
    }

finish:
    sc_poly_mpz_mul_scalar(gcd, gcd, &gcd_ab);

    sc_mpz_clear(&gcd_ab);
    sc_mpz_clear(&m);
    sc_mpz_clear(&ac);
    sc_mpz_clear(&bc);
    sc_mpz_clear(&p);
    sc_mpz_clear(&gamma);
    sc_mpz_clear(&l);
    sc_mpz_clear(&prime_check);
    sc_mpz_clear(&tmp);
    sc_mpz_clear(&hc);
    sc_poly_mpz_clear(&gm);
    sc_poly_mpz_clear(&a_c);
    sc_poly_mpz_clear(&b_c);
    sc_poly_mpz_clear(&quo);
    sc_poly_mpz_clear(&rem);
    sc_poly_mpz_clear(&h);

    return SC_FUNC_SUCCESS;
}

static SINT32 sc_poly_mpz_pseudo_remainder(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b,
    sc_poly_mpz_t *rem)
{
    size_t i;
    sc_ulimb_t e;
    sc_mpz_t *lc_b, pow;
    SINT32 deg_a, deg_b;

    deg_a = sc_poly_mpz_degree(a);
    if (deg_a < 0) {
        return -1;
    }
    deg_b = sc_poly_mpz_degree(b);
    if (deg_b < 0) {
        return -1;
    }

    // If the degree of b is zero then return 0
    if (0 == deg_b) {
        sc_poly_mpz_reset(rem, 0);
        return 0;
    }

    // Find the leading coefficient of b
    lc_b = &b->p[deg_b];

    // Initially set the remainder to a
    if (a != rem) {
        sc_poly_mpz_copy(rem, a->len, a);
    }

    e = SC_LIMB_WORD(deg_a - deg_b + 1);

    while (deg_a >= deg_b) {
        // rem = LC(b) * rem
        for (i=0; i<deg_a; i++) {
            sc_mpz_mul(&rem->p[i], &rem->p[i], lc_b);
        }

        // rem -= LC(rem) * b
        for (i=0; i<deg_b; i++) {
            sc_mpz_submul(&rem->p[i + deg_a - deg_b], &b->p[i], &rem->p[deg_a]);
        }
        
        sc_poly_mpz_set_si(rem, deg_a, 0);

        deg_a = sc_poly_mpz_degree(rem);
        e--;
    }

    sc_mpz_init(&pow);
    sc_mpz_pow_ui(&pow, lc_b, e);   // i.e. LC(b) ^ e
    sc_poly_mpz_mul_scalar(rem, rem, &pow);
    sc_mpz_clear(&pow);

    return deg_a;
}

static void sc_poly_mpz_comb_buf_init(sc_mpz_comb_buf_t *temp, const sc_mpz_comb_t *comb)
{
    size_t n, i, j;

    // Allocate space for comb_temp
    temp->n = n = comb->n;
    temp->comb_temp = (sc_poly_mpz_t *) SC_MALLOC(n * sizeof(sc_poly_mpz_t));

    j = (SC_LIMB_WORD(1) << (n - 1));
    for (i=0; i<n; i++) {
        sc_poly_mpz_init(&temp->comb_temp[i], j);
        j >>= 1;
    }

    sc_mpz_init(&temp->temp);
    sc_mpz_init(&temp->temp2);
}
 
static void sc_poly_mpz_comb_buf_clear(sc_mpz_comb_buf_t *temp)
{
    sc_ulimb_t n, i;

    n = temp->n;

    for (i=0; i<n; i++) {
        sc_poly_mpz_clear(&temp->comb_temp[i]);
    }

    SC_FREE(temp->comb_temp, n * sizeof(sc_poly_mpz_t));

    sc_mpz_clear(&temp->temp);
    sc_mpz_clear(&temp->temp2);
}
 
static void sc_poly_mpz_comb_init(sc_mpz_comb_t *comb, sc_ulimb_t *primes, size_t num_primes)
{
    sc_ulimb_t i, j, log_comb, num, log_res;
    sc_mpz_t temp, temp2;

    SINT32 n = SC_LIMB_BITS - limb_clz(num_primes);

    comb->n          = n;
    comb->primes     = primes;
    comb->num_primes = num_primes;

    comb->mod  = (sc_mod_t *) SC_MALLOC(sizeof(sc_mod_t) * num_primes);
    comb->comb = NULL;
    comb->res  = NULL;
    for (i=0; i<num_primes; i++) {
        limb_mod_init(&comb->mod[i], primes[i]);
    }

    if (0 == n) {
        return;
    }

    comb->comb = (sc_poly_mpz_t *) SC_MALLOC(n * sizeof(sc_poly_mpz_t));
    comb->res  = (sc_poly_mpz_t *) SC_MALLOC(n * sizeof(sc_poly_mpz_t));

    j = (SC_LIMB_WORD(1) << (n - 1));
    for (i=0; i<n; i++) {
        sc_poly_mpz_init(&comb->comb[i], j);
        sc_poly_mpz_init(&comb->res[i], j);
        j >>= 1;
    }

    for (i=0, j=0; (i+2)<=num_primes; i+=2, j++) {
        sc_mpz_set_ui(&comb->comb[0].p[j], primes[i]);
        sc_mpz_mul_ui(&comb->comb[0].p[j], &comb->comb[0].p[j], primes[i+1]);
    }

    if (i < num_primes) {
        sc_mpz_set_ui(&comb->comb[0].p[j], primes[i]);
        i += 2;
        j++;
    }

    num = (SC_LIMB_WORD(1) << n);
    for (; i<num; i+=2, j++) {
         sc_mpz_set_ui(&comb->comb[0].p[j], 1);
    }

    log_comb = 1;
    num >>= 1;
    while (num >= 2) {
        for (i=0, j=0; i<num; i+=2, j++) {
            sc_mpz_mul(&comb->comb[log_comb].p[j], &comb->comb[log_comb-1].p[i],
                &comb->comb[log_comb-1].p[i + 1]);
        }
        log_comb++;
        num >>= 1;
    }

    sc_mpz_init(&temp);
    sc_mpz_init(&temp2);
 
    for (i=0, j=0; (i+2)<=num_primes; i+=2, j++) {
        sc_mpz_set_ui(&temp, primes[i]);
        sc_mpz_set_ui(&temp2, primes[i+1]);
        sc_mpz_invmod(&comb->res[0].p[j], &temp, &temp2);
    }
 
    sc_mpz_clear(&temp);
    sc_mpz_clear(&temp2);

    log_res = 1;
    num = SC_LIMB_WORD(1) << (n - 1);
 
    while (log_res < n) {
        for (i=0, j=0; i<num; i+=2, j++) {
            sc_mpz_invmod(&comb->res[log_res].p[j], &comb->comb[log_res-1].p[i],
                &comb->comb[log_res-1].p[i + 1]);
        }
        log_res++;
        num >>= 1;
    }
}

static void sc_poly_mpz_comb_clear(sc_mpz_comb_t *comb)
{
    sc_ulimb_t i, n;
    n = comb->n;

    // Clear arrays at each level
    for (i=n; i--;) {
        sc_poly_mpz_clear(&comb->comb[i]);
        sc_poly_mpz_clear(&comb->res[i]);
    }
    
    if (comb->comb) {
        SC_FREE(comb->comb, n * sizeof(sc_poly_mpz_t));
    }
    if (comb->res) {
        SC_FREE(comb->res, n * sizeof(sc_poly_mpz_t));
    }

    SC_FREE(comb->mod, sizeof(sc_mod_t) * comb->num_primes);
}

static void sc_poly_mpz_multi_crt_ui_sign(sc_mpz_t *out, const sc_mpz_t *in,
    const sc_mpz_comb_t *comb, sc_mpz_t *temp)
{
    sc_ulimb_t n = comb->n;
    sc_ulimb_t p;

    if (n == SC_LIMB_WORD(0)) {
        if (sc_mpz_is_zero(in)) {
            sc_mpz_set_ui(out, 0);
            return;
        }

        p = comb->primes[0];

        const sc_ulimb_t t = sc_mpz_get_ui(in);
        if ((p - t) < t) {
            sc_mpz_set_si(out, (sc_ulimb_t) (t - p));
        }
        else {
            sc_mpz_set_ui(out, t);
        }
        return;
    }

    sc_mpz_sub(temp, in, &comb->comb[comb->n - 1].p[0]);

    if (sc_mpz_cmpabs(temp, in) <= 0) {
        sc_mpz_copy(out, temp);
    }
    else {
        sc_mpz_copy(out, in);
    }

    return;
}

static void sc_poly_mpz_multi_crt_ui(sc_mpz_t *out, const sc_ulimb_t *residues, const sc_mpz_comb_t *comb, sc_mpz_comb_buf_t *comb_buf, SINT32 sign)
{
    sc_ulimb_t i, j, num, log_res, n = comb->n, num_primes = comb->num_primes;
 
    sc_poly_mpz_t *comb_temp = comb_buf->comb_temp;
    sc_mpz_t *temp  = &comb_buf->temp;
    sc_mpz_t *temp2 = &comb_buf->temp2;

    if (1 == num_primes) {
        if (sign) {
            sc_ulimb_t p = comb->primes[0];

            if ((p - residues[0]) < residues[0]) {
                sc_mpz_set_si(out, residues[0] - p);
            }
            else {
                sc_mpz_set_si(out, residues[0]);
            }
        }
        else {
            sc_mpz_set_si(out, residues[0]);
        }
        return;
    }

    num = SC_LIMB_WORD(1) << n;
 
    for (i=0, j=0; (i + 2)<=num_primes; i+=2, j++) {
        sc_mpz_set_ui(temp, residues[i]);
        sc_mpz_mod_ui(temp2, temp, comb->primes[i+1]);
        sc_mpz_sub_ui(temp2, temp2, residues[i + 1]);
        sc_mpz_negate(temp2, temp2);
        sc_mpz_mul(temp, temp2, &comb->res[0].p[j]);
        sc_mpz_mod_ui(temp2, temp, comb->primes[i+1]);
        sc_mpz_mul_ui(temp, temp2, comb->primes[i]); 
        sc_mpz_add_ui(&comb_temp[0].p[j], temp, residues[i]);
    }

    if (i < num_primes) {
        sc_mpz_set_ui(&comb_temp[0].p[j], residues[i]);
    }

    num >>= 1;
    log_res = 1;
    while (log_res < n) {
        for (i=0, j=0; i<num; i+=2, j++) {
            if (sc_mpz_is_one(&comb->comb[log_res-1].p[i + 1])) {
                if (!sc_mpz_is_one(&comb->comb[log_res-1].p[i])) {
                    sc_mpz_copy(&comb_temp[log_res].p[j], &comb_temp[log_res-1].p[i]);
                }
            }
            else {
                sc_mpz_mod(temp2, &comb_temp[log_res-1].p[i],
                    &comb->comb[log_res-1].p[i + 1]);
                sc_mpz_sub(temp, &comb_temp[log_res-1].p[i + 1], temp2);
                sc_mpz_mul(temp2, temp, &comb->res[log_res].p[j]);
                sc_mpz_mod(temp, temp2, &comb->comb[log_res-1].p[i + 1]);
                sc_mpz_mul(temp2, temp, &comb->comb[log_res-1].p[i]);
                sc_mpz_add(&comb_temp[log_res].p[j], temp2,
                    &comb_temp[log_res-1].p[i]);
            }
        }

        log_res++;
        num >>= 1; 
    }

    if (sign) {
        sc_poly_mpz_multi_crt_ui_sign(out, &comb_temp[log_res - 1].p[0], comb, temp);
    }
    else {
        sc_mpz_copy(out, &comb_temp[log_res - 1].p[0]);
    }
}

static SINT32 sc_poly_mpz_resultant_modular(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b,
    sc_mpz_t *resultant)
{
    size_t i;
    SINT32 deg_a, deg_b, retval = SC_FUNC_FAILURE;
    UINT32 a_bits, b_bits, bound, p_num, bits;
    sc_mpz_t cont_a, cont_b, temp, prime;
    sc_poly_mpz_t scaled_a, scaled_b;
    sc_ulimb_t *a_mod_p, *b_mod_p, *p_list, *r_list, *scratch;
    sc_mod_t modulus;

    deg_a = sc_poly_mpz_degree(a);
    if (deg_a < 0) {
        return SC_FUNC_FAILURE;
    }

    deg_b = sc_poly_mpz_degree(b);
    if (deg_b < 0) {
        return SC_FUNC_FAILURE;
    }

    if (0 == deg_b) {
        sc_mpz_pow_ui(resultant, &b->p[0], SC_LIMB_WORD(deg_b));
        return SC_FUNC_SUCCESS;
    }

    sc_mpz_init(&cont_a);
    sc_mpz_init(&cont_b);
    sc_mpz_init(&temp);
    sc_mpz_init(&prime);

    sc_poly_mpz_init(&scaled_a, a->len);
    sc_poly_mpz_init(&scaled_b, b->len);

    // Calculate the content of a and b, then scale the input polynomials
    if (SC_FUNC_FAILURE == (retval = sc_poly_mpz_content(&cont_a, a))) {
        goto finish_1;
    }
    if (SC_FUNC_FAILURE == (retval = sc_poly_mpz_content(&cont_b, b))) {
        goto finish_1;
    }
    sc_poly_mpz_content_scale(a, &cont_a, &scaled_a);
    sc_poly_mpz_content_scale(b, &cont_b, &scaled_b);

    // Product of the leading coefficients
    sc_mpz_mul(&temp, &scaled_a.p[deg_a], &scaled_b.p[deg_b]);

    // Obtain the maximum number of bits in both scaled input polynomials
    a_bits = sc_poly_mpz_max_bits(&scaled_a);
    b_bits = sc_poly_mpz_max_bits(&scaled_b);

    // Determine the bound on the size of the resultant
    bound  = (deg_a + deg_b + 1)*(SC_LIMB_BITS - limb_clz((10*(deg_a + deg_b + 1) + 26)/27)) + 3;
    bound += deg_a*b_bits + deg_b*a_bits;

    // Determine the size of the polynomial and resultant lists
    p_num = (bound + (SC_LIMB_BITS - 1) - 1) / (SC_LIMB_BITS - 1);
    sc_mpz_set_ui(&prime, 1);
    sc_mpz_set_ui(resultant, 0);

    // Allocate memory for the intermediate variables
    a_mod_p = SC_MALLOC(sizeof(sc_ulimb_t) * (6 * (deg_a + 1) + 2* p_num));
    if (NULL == a_mod_p) {
        goto finish;
    }
    b_mod_p = a_mod_p + deg_a + 1;
    p_list  = b_mod_p + deg_a + 1;
    r_list  = p_list + p_num;
    scratch = r_list + p_num;

    modulus.m = SC_LIMB_WORD(1) << (SC_LIMB_BITS - 1);
    bits = 0;
    i = 0;
    while (bits < bound) {
        modulus.m = next_prime(modulus.m);
        if (0 == sc_mpz_floor_div_ui(&temp, modulus.m)) {
            continue;
        }

        // Obtain the modular multiplicative inverse of the prime and its norm (0)
        modulus.m_inv  = limb_inverse(modulus.m);
        modulus.norm   = limb_clz(modulus.m);
        modulus.b_norm = SC_LIMB_BITS - modulus.norm;

        // Convert the scaled input polynomials to limb arrays modulo p
        sc_poly_mpz_to_limb_mod(a_mod_p, &scaled_a, &modulus);
        sc_poly_mpz_to_limb_mod(b_mod_p, &scaled_b, &modulus);

        // Increase our bit consumption
        bits += SC_LIMB_BITS - 1;

        // Store the prime number and resultant for future CRT usage
        p_list[i] = modulus.m;
        r_list[i] = poly_limb_resultant(a_mod_p, deg_a+1, b_mod_p, deg_b+1,
            scratch, &modulus);
        i++;
    }

    // Perform Chinese Remaindering to recover the resultant from the list
    // of prime numbers and associated resultant's
    sc_mpz_comb_t comb;
    sc_mpz_comb_buf_t comb_buf;
    sc_poly_mpz_comb_init(&comb, p_list, p_num);
    sc_poly_mpz_comb_buf_init(&comb_buf, &comb);
    sc_poly_mpz_multi_crt_ui(resultant, r_list, &comb, &comb_buf, 1);
    sc_poly_mpz_comb_buf_clear(&comb_buf);
    sc_poly_mpz_comb_clear(&comb);

    // If the content of a is NOT 1, multiply the resultant by cont(a)^deg_b
    if (0 == sc_mpz_is_one(&cont_a)) {
        sc_mpz_pow_ui(&temp, &cont_a, SC_LIMB_WORD(deg_b));
        sc_mpz_mul(resultant, resultant, &temp);
    }

    // If the content of b is NOT 1, multiply the resultant by cont(b)^deg_a
    if (0 == sc_mpz_is_one(&cont_b)) {
        sc_mpz_pow_ui(&temp, &cont_b, SC_LIMB_WORD(deg_a));
        sc_mpz_mul(resultant, resultant, &temp);
    }

    retval = SC_FUNC_SUCCESS;

finish_1:
    // Free memory associated with the intermediate variables
    sc_mpz_clear(&cont_a);
    sc_mpz_clear(&cont_b);
    sc_mpz_clear(&temp);
    sc_mpz_clear(&prime);
    sc_poly_mpz_clear(&scaled_a);
    sc_poly_mpz_clear(&scaled_b);
finish:
    SC_FREE(a_mod_p, sizeof(sc_ulimb_t) * (6 * (deg_a + 1) + 2* p_num));

    return retval;
}

static SINT32 sc_poly_mpz_resultant_euclidean(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b,
    sc_mpz_t *resultant)
{
    SINT32 deg_a, deg_b, sign, retval = SC_FUNC_SUCCESS;

    deg_a = sc_poly_mpz_degree(a);
    if (deg_a < 0) {
        return SC_FUNC_FAILURE;
    }

    deg_b = sc_poly_mpz_degree(b);
    if (deg_b < 0) {
        return SC_FUNC_FAILURE;
    }

    if (0 == deg_b) {
        sc_mpz_pow_ui(resultant, &b->p[0], SC_LIMB_WORD(deg_b));
        return SC_FUNC_SUCCESS;
    }

    sc_mpz_t cont_a, cont_b, g, h, temp;
    sc_mpz_init(&cont_a);
    sc_mpz_init(&cont_b);
    sc_mpz_init(&g);
    sc_mpz_init(&h);
    sc_mpz_init(&temp);

    // Initialise h and g to 1
    sc_mpz_set_ui(&h, 1);
    sc_mpz_set_ui(&g, 1);

    sc_poly_mpz_t scaled_a, scaled_b;
    sc_poly_mpz_init(&scaled_a, a->len);
    sc_poly_mpz_init(&scaled_b, b->len);
    sc_poly_mpz_t *ptr_a = &scaled_a;
    sc_poly_mpz_t *ptr_b = &scaled_b;

    // Calculate the content of a and b, then scale the input polynomials
    if (SC_FUNC_FAILURE == (retval = sc_poly_mpz_content(&cont_a, a))) {
        goto finish;
    }
    if (SC_FUNC_FAILURE == (retval = sc_poly_mpz_content(&cont_b, b))) {
        goto finish;
    }
    sc_poly_mpz_content_scale(a, &cont_a, &scaled_a);
    sc_poly_mpz_content_scale(b, &cont_b, &scaled_b);

    // Calculate the product of the two contents raised to the power
    // of the degree of the opposing input polynomial
    sc_mpz_pow_ui(&cont_a, &cont_a, SC_LIMB_WORD(deg_b));
    sc_mpz_pow_ui(&cont_b, &cont_b, SC_LIMB_WORD(deg_a));
    sc_mpz_mul(&temp, &cont_a, &cont_b);

    sign = 1;
    while (deg_b) {
        sc_poly_mpz_t *ptr_swap;
        SINT32 deg_diff, deg_swap;

        // If the degree of both intermediate polynomials
        // is odd then invert the sign
        if ((deg_a & 1) && (deg_b & 1)) {
            sign = -sign;
        }

        // Obtain the degree difference between a and b
        deg_diff = deg_a - deg_b;

        // Calculate the Cohen pseudo remainder
        deg_a = sc_poly_mpz_pseudo_remainder(ptr_a, ptr_b, ptr_a);
        if (deg_a < 0) {
            retval = SC_FUNC_FAILURE;
            goto finish;
        }

        // If scaled_a is zero prepare to return a 0 resultant
        if (0 == deg_a && sc_mpz_is_zero(&ptr_a->p[0])) {
            sc_mpz_set_ui(resultant, 0);
            goto finish;
        }

        // Swap scaled_a and scaled_b
        ptr_swap = ptr_a;
        ptr_a    = ptr_b;
        ptr_b    = ptr_swap;
        deg_swap = deg_a;
        deg_a    = deg_b;
        deg_b    = deg_swap;

        // Scale b as cont_b = g * h^d
        sc_mpz_pow_ui(&cont_a, &h, SC_LIMB_WORD(deg_diff));
        sc_mpz_mul(&cont_b, &g, &cont_a);
        sc_poly_mpz_content_scale(ptr_b, &cont_b, ptr_b);

        // Update g and h
        sc_mpz_pow_ui(&g, &ptr_a->p[deg_a], SC_LIMB_WORD(deg_diff));
        sc_mpz_mul(&cont_b, &h, &g);
        sc_mpz_divquo(&h, &cont_b, &cont_a);
        sc_mpz_copy(&g, &ptr_a->p[deg_a]);
    }

    // Finalise the resultant
    sc_mpz_pow_ui(&g, &h, SC_LIMB_WORD(deg_a));
    sc_mpz_pow_ui(&cont_b, &ptr_b->p[deg_b], SC_LIMB_WORD(deg_a));
    sc_mpz_mul(&cont_a, &h, &cont_b);
    sc_mpz_divquo(&h, &cont_a, &g);

    sc_mpz_mul(resultant, &temp, &h);
    if (sign < 0) {
        sc_mpz_negate(resultant, resultant);
    }

finish:
    sc_mpz_clear(&cont_a);
    sc_mpz_clear(&cont_b);
    sc_mpz_clear(&g);
    sc_mpz_clear(&h);
    sc_mpz_clear(&temp);
    sc_poly_mpz_clear(&scaled_a);
    sc_poly_mpz_clear(&scaled_b);

    return retval;
}

SINT32 sc_poly_mpz_resultant(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b,
    sc_mpz_t *resultant)
{
    if (b->len > 128) {
        return sc_poly_mpz_resultant_modular(a, b, resultant);
    }
    else {
        return sc_poly_mpz_resultant_euclidean(a, b, resultant);
    }
}

SINT32 sc_poly_mpz_xgcd(const sc_poly_mpz_t *a, const sc_poly_mpz_t *b,
    sc_mpz_t *gcd, sc_poly_mpz_t *x, sc_poly_mpz_t *y)
{
    SINT32 retval = SC_FUNC_SUCCESS;
    SINT32 deg_a, deg_b;
    UINT32 x_bits, y_bits;
    sc_mpz_t p, p_acc, prime_check;
    sc_mod_t modulus;
    sc_ulimb_t *mem;
    sc_ulimb_t *g, *s, *t, *ta, *tb, *temp1, *temp2;
    SINT32 unstable, init_flag;
    size_t iter;

    deg_a = sc_poly_mpz_degree(a);
    if (deg_a < 0) {
        return SC_FUNC_FAILURE;
    }
    deg_b = sc_poly_mpz_degree(b);
    if (deg_b < 0) {
        return SC_FUNC_FAILURE;
    }

    x_bits = 0;
    y_bits = 0;

    // If the degree of b is larger then swap the input polynomials
    if (deg_a < deg_b) {
        return sc_poly_mpz_xgcd(b, a, gcd, y, x);
    }

    // Compute the resultant of a and b
    if (SC_FUNC_FAILURE == sc_poly_mpz_resultant(a, b, gcd)) {
        return SC_FUNC_FAILURE;
    }
    if (sc_mpz_is_zero(gcd)) {
        return SC_FUNC_SUCCESS;
    }

    // Set the accumulated product of prime numbers to 1
    sc_mpz_init(&p_acc);
    sc_mpz_set_ui(&p_acc, 1);

    // Initialise the prime number to search from the MSB of the machine word
    sc_mpz_init(&p);
    modulus.m = SC_LIMB_WORD(1) << (SC_LIMB_BITS - 1);

    // A temporary variable used to check for divisibility
    sc_mpz_init(&prime_check);

    // Create intermediate variables
    mem = SC_MALLOC((4*(deg_a+1) + 3*(deg_b+1) + 2*deg_b) * sizeof(sc_ulimb_t));
    g     = mem;
    s     = g + deg_b + 1;
    t     = s + deg_b + 1;
    ta    = t + deg_a + 1;
    tb    = ta + deg_a + 1;
    temp1 = tb + deg_b + 1;
    temp2 = temp1 + deg_a + deg_b + 1;
    if (NULL == mem) {
        retval = SC_FUNC_FAILURE;
        goto finish;
    }

    unstable  = 1;
    init_flag = 1;
    iter      = 0;
    while (1) {
        sc_ulimb_t r;

        // Termination if the prime number's are exhausted
        iter++;
        if (NUM_MOD_PRIMES == iter) {
          retval = SC_FUNC_FAILURE;
          break;
        }
        // Create a prime number
        modulus.m = next_prime(modulus.m);
        sc_mpz_set_ui(&p, modulus.m);

        // Calculate the resultant modulo the prime number and check divisibility
        sc_mpz_divrem(&prime_check, gcd, &p);
        if (0 == sc_mpz_cmp_si(&prime_check, 0)) {
            continue;
        }

        // Calculate the LC(a) modulo the prime number and check divisibility
        sc_mpz_divrem(&prime_check, &a->p[deg_a], &p);
        if (0 == sc_mpz_cmp_si(&prime_check, 0)) {
            continue;
        }

        // Calculate the LC(b) modulo the prime number and check divisibility
        sc_mpz_divrem(&prime_check, &b->p[deg_b], &p);
        if (0 == sc_mpz_cmp_si(&prime_check, 0)) {
            continue;
        }

        // Calculate r = resultant % m
        r = sc_mpz_to_limb_mod(gcd, modulus.m);

        // The modulus is acceptable, so compute the norm and
        // modular multiplicative inverse
        limb_mod_init(&modulus, modulus.m);

        // Set the input polynomials modulo the prime number
        sc_poly_mpz_to_limb_mod(ta, a, &modulus);
        sc_poly_mpz_to_limb_mod(tb, b, &modulus);

        if (!unstable) {
            // Verify that s*x + t*y == resultant (modulo the prime number)
            SINT32 deg = deg_a + deg_b + 1;
            sc_poly_mpz_to_limb_mod(s, x, &modulus);
            sc_poly_mpz_to_limb_mod(t, y, &modulus);
            poly_limb_mul_mod(temp1, ta, deg_a+1, s, deg_b, &modulus);
            poly_limb_mul_mod(temp2, t, deg_a+1, tb, deg_b, &modulus);
            poly_limb_add_mod(temp1, temp1, deg, temp2, deg, &modulus);
            deg = poly_limb_degree(temp1, deg);
            if (0 == deg && temp1[0] == r) {
                sc_mpz_mul_ui(&p_acc, &p_acc, modulus.m);
            }
            else {
                unstable = 1;
            }
        }

        if (unstable) {
            sc_ulimb_t rg_inv;

            // Calculate the XGCD (modulo the prime number)
            poly_limb_xgcd_mod(g, s, t, ta, deg_a+1, tb, deg_b+1, &modulus);

            // Scale the Bezout polynomials
            rg_inv = limb_inv_mod(g[0], modulus.m);
            rg_inv = limb_mul_mod(r, rg_inv, modulus.m, modulus.m_inv);
            poly_limb_mul_mod_scalar(s, s, deg_b+1, rg_inv, &modulus);
            poly_limb_mul_mod_scalar(t, t, deg_a+1, rg_inv, &modulus);

            if (!init_flag) {
                UINT32 x_bits_2, y_bits_2;

                // CRT update
                sc_poly_mpz_crt(x, x, deg_b, &p_acc, s, deg_b, &modulus);
                sc_poly_mpz_crt(y, y, deg_a, &p_acc, t, deg_a, &modulus);
                sc_mpz_mul_ui(&p_acc, &p_acc, modulus.m);

                // CRT stabilisation check
                x_bits_2 = sc_poly_mpz_max_bits(x);
                y_bits_2 = sc_poly_mpz_max_bits(y);
                unstable = (x_bits != x_bits_2) || (y_bits != y_bits_2);
                if (x_bits_2 >= POLY_XGCD_STABLE_BOUND || y_bits_2 >= POLY_XGCD_STABLE_BOUND) {
                    retval = SC_FUNC_FAILURE;
                    goto finish;
                }
                x_bits = x_bits_2;
                y_bits = y_bits_2;
            }
            else {
                init_flag = 0;
                unstable  = 0;

                // Initialise the Bezout polynomials using s and t
                poly_limb_to_mpi_mod(x, s, deg_b+1, &modulus);
                poly_limb_to_mpi_mod(y, t, deg_a+1, &modulus);

                // Set the accumulated product prime to the initial prime number
                sc_mpz_set_ui(&p_acc, modulus.m);
            }
        }

        if (!unstable) {
            // If the CRT has stabilised we have obtained the GCD only
            // if the number of bits in the prime product exceeds the maximum
            // number of bits produced by multiplying out the Bezout polynomials and
            // the input polynomials OR the number of bits in the GCD
            SINT32 bound, bits_ax, bits_by, gcd_bits, p_bits;
            p_bits   = sc_mpz_sizeinbase(&p_acc, 2);
            gcd_bits = sc_mpz_sizeinbase(gcd, 2);
            bits_by  = SC_LIMB_BITS - limb_clz(deg_b+1);
            bits_ax  = bits_by + sc_poly_mpz_max_bits(a) + sc_poly_mpz_max_bits(x);
            bits_by += sc_poly_mpz_max_bits(b) + sc_poly_mpz_max_bits(y);
            bound    = (bits_ax > bits_by)? bits_ax : bits_by;
            bound    = (gcd_bits > bound)? gcd_bits : bound;
            bound   += 4;
            if (p_bits > bound) {
                break;
            }
        }
    }

finish:
    sc_mpz_clear(&p);
    sc_mpz_clear(&p_acc);
    sc_mpz_clear(&prime_check);
    SC_FREE(mem, (4*(deg_a+1) + 3*(deg_b+1) + 2*deg_b) * sizeof(sc_ulimb_t));

    return retval;
}

