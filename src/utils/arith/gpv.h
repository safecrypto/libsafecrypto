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
#include "utils/sampling/sampling.h"
#include "utils/arith/sc_poly_mpz.h"
#include <string.h>


/// A struct used to store pointers to the private keys and the
/// expanded polynomial basis
SC_STRUCT_PACK_START
typedef struct _gpv_t {
    SINT32 *g;
    SINT32 *f;
    SINT32 *G;
    SINT32 *F;
    SINT32 *b;
    size_t  n;
} SC_STRUCT_PACKED gpv_t SC_DEFAULT_ALIGNED;
SC_STRUCT_PACK_END

#define GPV_GAUSSIAN_SAMPLE_EFFICIENT      0x00000001
#define GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP   0x00000002


/// Compute the Gram-Schmidt norm of f and g of length n, modulus q and
/// threshold bd
DOUBLE gram_schmidt_norm(SINT32 *f, SINT32 *g, size_t n,
    SINT32 q, DOUBLE bd);

/// MGS orthogonalisation - Classical
void modified_gram_schmidt_classical(const gpv_t *gpv, LONGDOUBLE *b_gs,
    SINT32 q);

/// MGS orthogonalisation - Fast, float output matrix
void modified_gram_schmidt_fast_flt(const gpv_t *gpv,
    FLOAT *b_gs, SINT32 q);

/// MGS orthogonalisation - Fast, double output matrix
void modified_gram_schmidt_fast_dbl(const gpv_t *gpv,
    DOUBLE *b_gs, SINT32 q);

/// MGS orthogonalisation - Fast, long double output matrix
void modified_gram_schmidt_fast_ldbl(const gpv_t *gpv,
    LONGDOUBLE *b_gs, SINT32 q);

/// Dot product - floats
FLOAT dot_flt(const FLOAT *x, const FLOAT *y,
    size_t n, size_t u, size_t v);

/// Dot products
/// @{
FLOAT dot_s32_flt(const SINT32 * SC_RESTRICT x, const FLOAT * SC_RESTRICT y, size_t n, size_t u, size_t v);
FLOAT dot_s64_flt(const SINT64 * SC_RESTRICT x, const FLOAT * SC_RESTRICT y, size_t n, size_t u, size_t v);
FLOAT dot_ldbl_flt(const LONGDOUBLE *x, const FLOAT *y, size_t n, size_t u, size_t v);

DOUBLE dot_s32_dbl(const SINT32 * SC_RESTRICT x, const DOUBLE * SC_RESTRICT y, size_t n, size_t u, size_t v);
DOUBLE dot_s64_dbl(const SINT64 * SC_RESTRICT x, const DOUBLE * SC_RESTRICT y, size_t n, size_t u, size_t v);
DOUBLE dot_dbl(const DOUBLE * SC_RESTRICT x, const DOUBLE * SC_RESTRICT  y,
    size_t n, size_t u, size_t v);
DOUBLE dot_sqr_dbl(const DOUBLE *x, size_t n, size_t u, size_t v);
DOUBLE dot_ldbl_dbl(const LONGDOUBLE *x, const DOUBLE *y, size_t n, size_t u, size_t v);

LONGDOUBLE dot_ldbl(const LONGDOUBLE *x, const LONGDOUBLE *y,
    size_t n, size_t u, size_t v);
LONGDOUBLE dot_s32_ldbl(const SINT32 *x, const LONGDOUBLE *y,
    size_t n, size_t u, size_t v);
LONGDOUBLE dot_s64_ldbl(const SINT64 *x, const LONGDOUBLE *y,
    size_t n, size_t u, size_t v);
///@}

/// Generate the polynomial basis B
SINT32 gpv_expand_basis(const gpv_t *gpv);

/// Read the value of the polynomial basis B at a specified matrix coordinate
SINT32 gpv_read_basis(const gpv_t *gpv, size_t row, size_t col);

/// Given the Gram Schmidt orthogonalisation of the the polynomial basis B
/// generate the inverse of the norms of the 2N rows
/// @{
void gpv_precompute_inv_ldbl(const LONGDOUBLE *b_gs, LONGDOUBLE *b_gs_inv, size_t n);
void gpv_precompute_inv_dbl(const DOUBLE *b_gs, DOUBLE *b_gs_inv_norm, size_t n);
void gpv_precompute_inv_flt(const FLOAT *b_gs, FLOAT *b_gs_inv_norm, size_t n);
/// @}

/// Generate a private key (f,g,F,G) and public key h using modulus q such that
/// f*G - g*F = q and h = g/f mod q
SINT32 gpv_gen_basis(safecrypto_t *sc, SINT32 *f, SINT32 *g, SINT32 *h,
    size_t n, SINT32 q,
    utils_sampling_t *sampling, prng_ctx_t *prng_ctx,
    SINT32 *F, SINT32 *G, SINT32 recreate_flag);

/// Gaussian sampling on-the-fly - polynomial basis matrix B is not stored in memory
/// @{
SINT32 gaussian_lattice_sample_on_the_fly_flt(safecrypto_t *sc,
    const gpv_t *gpv, const FLOAT *b_gs, const FLOAT *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v, UINT32 q, DOUBLE s_f);
SINT32 gaussian_lattice_sample_on_the_fly_dbl(safecrypto_t *sc,
    const gpv_t *gpv, const DOUBLE *b_gs, const DOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v, UINT32 q, DOUBLE s_f);
SINT32 gaussian_lattice_sample_on_the_fly_ldbl(safecrypto_t *sc,
    const gpv_t *gpv, const LONGDOUBLE *b_gs, const LONGDOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v, UINT32 q, DOUBLE s_f);
/// @}

/// Gaussian sampling
/// @{
SINT32 gaussian_lattice_sample_flt(safecrypto_t *sc,
    const gpv_t *gpv, const FLOAT *b_gs, const FLOAT *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v1, SINT32 *v2,
    UINT32 q, DOUBLE s_f, UINT32 flags);
SINT32 gaussian_lattice_sample_dbl(safecrypto_t *sc,
    const gpv_t *gpv, const DOUBLE *b_gs, const DOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v1, SINT32 *v2,
    UINT32 q, DOUBLE s_f, UINT32 flags);
SINT32 gaussian_lattice_sample_ldbl(safecrypto_t *sc,
    const gpv_t *gpv, const LONGDOUBLE *b_gs, const LONGDOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v1, SINT32 *v2,
    UINT32 q, DOUBLE s_f, UINT32 flags);
/// @}
