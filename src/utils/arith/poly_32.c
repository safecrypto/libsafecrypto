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

#include "utils/arith/poly_32.h"
#include "utils/crypto/prng.h"
#include "utils/arith/sc_math.h"
#include "safecrypto_types.h"
#include "safecrypto_private.h"



void poly_32_copy(SINT32 *out, size_t n, const SINT32 *in)
{
    size_t i;
    for (i=n; i--;) {
        out[i] = in[i];
    }
}

void poly_32_reset(SINT32 *inout, size_t offset, size_t n)
{
    size_t i;
    for (i=offset; i<n; i++) {
        inout[i] = 0;
    }
}

void poly_32_add_scalar(SINT32 *poly, size_t n, SINT32 in)
{
    if (n > 0) {
        poly[0] = poly[0] + in;
    }
}

void poly_32_sub_scalar(SINT32 *poly, size_t n, SINT32 in)
{
    if (n > 0) {
        poly[0] = poly[0] - in;
    }
}

void poly_32_mul_scalar(SINT32 *poly, size_t n, SINT32 in)
{
    size_t i;
    for (i=n; i--;) {
        poly[i] *= in;
    }
}

void poly_32_add(SINT32 *out, size_t n, const SINT32 *in1, const SINT32 *in2)
{
    size_t i;
    // out = in1 + in2
    for (i=n; i--;) {
        out[i] = in1[i] + in2[i];
    }
}

void poly_32_sub(SINT32 *out, size_t n, const SINT32 *in1, const SINT32 *in2)
{
    size_t i;
    // out = in1 - in2
    for (i=n; i--;) {
        out[i] = in1[i] - in2[i];
    }
}

// NS: Use of restrict keyword here aids auto vectorisation
void poly_32_add_single(SINT32 *out, size_t n, const SINT32 *in)
{
    size_t i;
    // out = in1 + in2
    for (i=n; i--;) {
        out[i] += in[i];
    }
}

// NS: Use of restrict keyword here aids auto vectorisation
void poly_32_sub_single(SINT32 *out, size_t n, const SINT32 *in)
{
    size_t i;
    // out = in1 - in2
    for (i=n; i--;) {
        out[i] -= in[i];
    }
}

void poly_32_mul(SINT32 *out, size_t n, const SINT32 *in1, const SINT32 *in2)
{
    size_t i, j;
    // out = in1 * in2
#if 1
    for (i=0; i<n; i++) {
        out[i] = in1[i] * in2[0];
    }

    for (j=1; j<n; j++) {
        out[n-1+j] = in1[n-1] * in2[j];
    }

    for (i=0; i<n-1; i++) {
        for (j=1; j<n; j++) {
            out[i+j] += in1[i] * in2[j];
        }
    }
#else
    for (i=2*n-1; i--;)
        out[i] = 0;

    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            out[i+j] += in1[i] * in2[j];
        }
    }
#endif
}

void poly_32_uniform_rand(prng_ctx_t *ctx, SINT32 *v, size_t n, const UINT16 *c, size_t c_len)
{
    size_t i, j;
    UINT32 mask = n - 1;

    // Reset the output polynomial to all zeros
    for (i=n; i--;) {
        v[i] = 0;
    }

    // Given the list of coefficient occurences c (in descending order of value),
    // randomly place the correct number of signed coefficient within the
    // polynomial of dimension n.
    for (j=0; j<c_len; j++) {
        i = 0;
        while (i < c[j]) {
            UINT32 rand = prng_32(ctx);
            size_t index = (rand >> 1) & mask;
            if (0 == v[index]) {
                v[index] = (rand & 1)? j-c_len : c_len-j;
                i++;
            }
        }
    }
}

void poly_32_mod_negate(SINT32 *out, size_t n, SINT32 q, const SINT32 *in)
{
    size_t i;
    for (i=n; i--;) {
        out[i] = q - in[i];
    }
}

SINT32 poly_32_degree(const SINT32 *h, size_t n)
{
    SINT32 deg = -1;
    if (NULL != h) {
        size_t j = n - 1;
        while (0 == h[j]) {
            if (0 == j) break;
            j--;
        }
        deg = j;
    }
    return deg;
}



