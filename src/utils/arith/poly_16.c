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

#include "utils/arith/poly_16.h"
#include "utils/crypto/prng.h"
#include "safecrypto_types.h"


void poly_16_copy(SINT16 *out, size_t n, const SINT16 *in)
{
    size_t i;
    for (i=n; i--;) {
        out[i] = in[i];
    }
}

void poly_16_reset(SINT16 *inout, size_t offset, size_t n)
{
    size_t i;
    for (i=offset; i<n; i++) {
        inout[i] = 0;
    }
}

void poly_16_add_scalar(SINT16 *poly, size_t n, SINT16 in)
{
    if (n > 0)
        poly[0] = poly[0] + in;
}

void poly_16_sub_scalar(SINT16 *poly, size_t n, SINT16 in)
{
    if (n > 0)
        poly[0] = poly[0] - in;
}

void poly_16_mul_scalar(SINT16 *poly, size_t n, SINT16 in)
{
    size_t i;
    for (i=n; i--;)
        poly[i] *= in;
}

void poly_16_add(SINT16 *out, size_t n, const SINT16 *in1, const SINT16 *in2)
{
    size_t i;
    // out = in1 + in2
    for (i=n; i--;)
        out[i] = in1[i] + in2[i];
}

void poly_16_sub(SINT16 *out, size_t n, const SINT16 *in1, const SINT16 *in2)
{
    size_t i;
    // out = in1 - in2
    for (i=n; i--;)
        out[i] = in1[i] - in2[i];
}

// NS: Use of restrict keyword here aids auto vectorisation
void poly_16_add_single(SINT16 *out, size_t n, const SINT16 *in)
{
    size_t i;
    // out = in1 + in2
    for (i=n; i--;)
        out[i] += in[i];
}

// NS: Use of restrict keyword here aids auto vectorisation
void poly_16_sub_single(SINT16 *out, size_t n, const SINT16 *in)
{
    size_t i;
    // out = in1 - in2
    for (i=n; i--;)
        out[i] -= in[i];
}

void poly_16_mul(SINT16 *out, size_t n, const SINT16 *in1, const SINT16 *in2)
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

void poly_16_uniform_rand(prng_ctx_t *ctx, SINT16 *v, size_t n, const UINT16 *c, size_t c_len)
{
    size_t i, j;
    UINT32 mask = n - 1;

    // Reset the output polynomial to all zeros
    for (i=n; i--;)
        v[i] = 0;

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

SINT32 poly_16_degree(const SINT16 *h, size_t n)
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

