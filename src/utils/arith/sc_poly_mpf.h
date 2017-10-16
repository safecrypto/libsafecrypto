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
#include <string.h>

#if defined(USE_GMP_MULTIPLE_PRECISION)
#include <gmp.h>
#endif

SC_STRUCT_PACK_START
typedef struct sc_mpf_t {
    mpf_t data;
} SC_STRUCT_PACKED sc_mpf_t;
SC_STRUCT_PACK_END


void sc_poly_mpf_to_flt(FLOAT *out, size_t n, sc_mpf_t *in);
void sc_poly_mpf_to_dbl(DOUBLE *out, size_t n, sc_mpf_t *in);
void poly_dbl_to_mpf(sc_mpf_t *out, size_t n, DOUBLE *in);
void sc_poly_mpf_init(sc_mpf_t *inout, size_t n);
void sc_poly_mpf_copy(sc_mpf_t *out, size_t n, sc_mpf_t *in);
void sc_poly_mpf_reset(sc_mpf_t *inout, size_t offset, size_t n);
SINT32 sc_poly_mpf_set(sc_mpf_t *inout, size_t index, DOUBLE value);
void sc_poly_mpf_add_scalar(sc_mpf_t *poly, size_t n, sc_mpf_t in);
void sc_poly_mpf_sub_scalar(sc_mpf_t *poly, size_t n, sc_mpf_t in);
void sc_poly_mpf_mul_scalar(sc_mpf_t *poly, size_t n, sc_mpf_t in);
void sc_poly_mpf_add(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2);
void sc_poly_mpf_sub(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2);
void sc_poly_mpf_add_single(sc_mpf_t *out, size_t n, sc_mpf_t *in);
void sc_poly_mpf_sub_single(sc_mpf_t *out, size_t n, sc_mpf_t *in);
void sc_poly_mpf_mul(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2);
void sc_poly_mpf_mul_mod(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2);
void sc_poly_mpf_uniform_rand(prng_ctx_t *ctx, sc_mpf_t *v, size_t n, const UINT16 *c, size_t c_len);
sc_mpf_t sc_poly_mpf_dot_product(sc_mpf_t *x, size_t n);
sc_mpf_t sc_poly_mpf_modulus(sc_mpf_t *x, size_t n);
SINT32 sc_poly_mpf_degree(sc_mpf_t *h, size_t n);
SINT32 sc_poly_mpf_div(sc_mpf_t *num, sc_mpf_t *den, size_t n, sc_mpf_t *q, sc_mpf_t *r);
SINT32 sc_poly_mpf_gcd(sc_mpf_t *a, sc_mpf_t *b, sc_mpf_t *gcd, sc_mpf_t *temp, size_t n);
SINT32 sc_poly_mpf_gcd_single(sc_mpf_t a, sc_mpf_t b, sc_mpf_t *gcd);
SINT32 sc_poly_mpf_ext_euclidean(sc_mpf_t *a, sc_mpf_t *b, sc_mpf_t *gcd,
    sc_mpf_t *x, sc_mpf_t *y, sc_mpf_t *temp, size_t n);
SINT32 sc_poly_mpf_ext_euclidean_single(sc_mpf_t a, sc_mpf_t b, sc_mpf_t *gcd,
    sc_mpf_t *x, sc_mpf_t *y);
DOUBLE sc_poly_mpf_gram_schmidt_norm(DOUBLE *f, DOUBLE *g, size_t n,
    DOUBLE q, DOUBLE bd);


SINT32 sc_poly_mpf_gen_basis(safecrypto_t *sc, DOUBLE *f, DOUBLE *g, DOUBLE *h,
    size_t n, DOUBLE q,
    utils_sampling_t *sampling, prng_ctx_t *prng_ctx,
    DOUBLE *F, DOUBLE *G, DOUBLE *sq_norm);
