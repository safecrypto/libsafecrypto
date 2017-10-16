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

#include "utils/arith/gpv.h"
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

#include <math.h>

#define DEBUG_GPV    0


DOUBLE gram_schmidt_norm(SINT32 *f, SINT32 *g, size_t n,
    SINT32 q, DOUBLE bd)
{
    // FIRST NORM
    // Don't bother creating the arrays with the correct signs,
    // the values are being squared so directly multiply-accumulate
    // the input f, g
    DOUBLE modx = 0;
    for (size_t i=n; i--;) {
        modx += f[i] * f[i] + g[i] * g[i];
    }
    modx = sqrt(modx);
    //fprintf(stderr, "||(g, -f)|| = %3.3f\n", modx);

    // Early termination - if ||(g,-f)|| cannot satisfy the condition
    // threshold then there's no point continuing, output the bad
    // Gram Schmidt norm and try again.
    if (modx > bd) {
        return modx;
    }


    size_t i;
#if 0
    // SECOND NORM
    // Floating-point precision is required
    DOUBLE *f2, *g2;
    f2 = SC_MALLOC(sizeof(DOUBLE) * 2 * n);
    g2 = f2 + n;
    sc_fft_t *ctx_fft = create_fft(n);
    SINT32 fb[n], gb[n];
    sc_complex_t f_fft[n], g_fft[n];
    sc_complex_t fb_fft[n], gb_fft[n];
    sc_complex_t F[n], G[n];

    fb[0] = f[0];
    for (i=1; i<n; i++) {
        fb[i] = -f[n-i];
    }
    gb[0] = g[0];
    for (i=1; i<n; i++) {
        gb[i] = -g[n-i];
    }

    fwd_fft_int(ctx_fft, f_fft, f);
    fwd_fft_int(ctx_fft, g_fft, g);
    fwd_fft_int(ctx_fft, fb_fft, fb);
    fwd_fft_int(ctx_fft, gb_fft, gb);

    for (i=0; i<n; i++) {
        sc_complex_t temp = f_fft[i]*fb_fft[i] + g_fft[i]*gb_fft[i];
        temp = 1 / temp;
        F[i] = fb_fft[i] * temp;
        G[i] = gb_fft[i] * temp;
    }
#else
    // SECOND NORM
    // Floating-point precision is required
    DOUBLE *f2, *g2;
    f2 = SC_MALLOC(sizeof(DOUBLE) * 2 * n);
    g2 = f2 + n;
    sc_fft_t *ctx_fft = create_fft(n);
    sc_complex_t *f_fft, *g_fft, *F, *G;
    f_fft = SC_MALLOC(sizeof(sc_complex_t) * 4 * n);
    g_fft = f_fft + n;
    F = g_fft + n;
    G = F + n;
    fwd_fft_int(ctx_fft, f_fft, f);
    fwd_fft_int(ctx_fft, g_fft, g);

    // This is an approximation
    for(i=0; i<n; i++) {
        sc_complex_t temp = f_fft[i]*f_fft[n-1-i] + g_fft[i]*g_fft[n-1-i];
        F[i] = f_fft[i] / temp;
        G[i] = g_fft[i] / temp;
    }
#endif

    inv_fft_dbl(ctx_fft, f2, F);
    inv_fft_dbl(ctx_fft, g2, G);
    destroy_fft(ctx_fft);

    DOUBLE b_N1 = 0;
    for(i=n; i--;) {
        b_N1 += f2[i] * f2[i] + g2[i] * g2[i];
    }
    b_N1 = (DOUBLE) q * sqrt(b_N1);

    SC_FREE(f2, sizeof(DOUBLE) * 2 * n);
    SC_FREE(f_fft, sizeof(sc_complex_t) * 4 * n);

    //fprintf(stderr, "||(qfb/(ggb + ffb), qgb/(ggb + ffb))|| = %3.9f\n", b_N1);
    if (modx > b_N1) {
        return modx;
    }
    else {
        return b_N1;
    }
}

static SINT32 poly_limb_anticirculant(const SINT32 *f, size_t n, SINT32 *mat_A)
{
    size_t i, j;

    SINT32 deg_f = poly_32_degree(f, n);
    if (-1 == deg_f || n <= (size_t)deg_f) {
        return SC_FUNC_FAILURE;
    }

    for (i=0; i<n; i++) {
        for (j=i; (j<=deg_f+i) && (j<n); j++) {
            mat_A[i*n+j] = f[j-i];
        }
        for (j=0; (j+n)<=(deg_f+i); j++) {
            mat_A[i*n+j] = -f[j-i+n];
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 gpv_expand_basis(const gpv_t *gpv)
{
    size_t i, j;
    size_t n = gpv->n;
    SINT32 *mat_A = SC_MALLOC(sizeof(SINT32) * n * n);
    if (NULL == mat_A) {
        return SC_FUNC_FAILURE;
    }

    /// @todo Modify the anticirculant function to avoid intermediate storage
    /// and data copying

    if (SC_FUNC_FAILURE == poly_limb_anticirculant(gpv->g, n, mat_A)) {
        return SC_FUNC_FAILURE;
    }
    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            gpv->b[i*2*n+j] = mat_A[i*n+j];
        }
    }

    if (SC_FUNC_FAILURE == poly_limb_anticirculant(gpv->f, n, mat_A)) {
        return SC_FUNC_FAILURE;
    }
    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            gpv->b[i*2*n+j+n] = -mat_A[i*n+j];
        }
    }

    if (SC_FUNC_FAILURE == poly_limb_anticirculant(gpv->G, n, mat_A)) {
        return SC_FUNC_FAILURE;
    }
    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            gpv->b[(i+n)*2*n+j] = mat_A[i*n+j];
        }
    }

    if (SC_FUNC_FAILURE == poly_limb_anticirculant(gpv->F, n, mat_A)) {
        return SC_FUNC_FAILURE;
    }
    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            gpv->b[(i+n)*2*n+j+n] = -mat_A[i*n+j];
        }
    }

    SC_FREE(mat_A, sizeof(SINT32) * n * n);

    return SC_FUNC_SUCCESS;
}

SINT32 gpv_read_basis(const gpv_t *gpv, size_t row, size_t col)
{
    size_t n = gpv->n;
    SINT32 i = (SINT32)col - (SINT32)row;
    SINT32 p;
    size_t first = col < n;
    while (i < 0) i += n;
    while (i >= n) i -= n;
    p = (row < n)? (first)? gpv->g[i] : -gpv->f[i] :
                   (first)? gpv->G[i] : -gpv->F[i];
    if (col >= n) col -= n;
    if (row >= n) row -= n;
    return (col < row)? -p : p;
}

FLOAT dot(const SINT32 *x, const SINT32 *y, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    FLOAT dot = 0;

    for (k=0; k<n; k++) {
        dot += x[u*n + k] * y[v*n + k];
    }

    return dot;
}

FLOAT dot_flt(const FLOAT *x, const FLOAT *y, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    FLOAT dot = 0;

    for (k=0; k<n; k++) {
        dot += x[u*n + k] * y[v*n + k];
    }

    return dot;
}

DOUBLE dot_s32_dbl(const SINT32 * SC_RESTRICT x, const DOUBLE * SC_RESTRICT y, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    DOUBLE dot = 0;
    const SINT32 *a = x + u*n;
    const DOUBLE *b = y + v*n;

    for (k=n; k--;) {
        dot += *a++ * *b++;
    }

    return dot;
}

DOUBLE dot_s64_dbl(const SINT64 * SC_RESTRICT x, const DOUBLE * SC_RESTRICT y, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    DOUBLE dot = 0;
    const SINT64 *a = x + u*n;
    const DOUBLE *b = y + v*n;

    for (k=n; k--;) {
        dot += *a++ * *b++;
    }

    return dot;
}

FLOAT dot_s32_flt(const SINT32 * SC_RESTRICT x, const FLOAT * SC_RESTRICT y, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    FLOAT dot = 0;
    const SINT32 *a = x + u*n;
    const FLOAT *b = y + v*n;

    for (k=n; k--;) {
        dot += *a++ * *b++;
    }

    return dot;
}

FLOAT dot_s64_flt(const SINT64 * SC_RESTRICT x, const FLOAT * SC_RESTRICT y, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    FLOAT dot = 0;
    const SINT64 *a = x + u*n;
    const FLOAT *b = y + v*n;

    for (k=n; k--;) {
        dot += (FLOAT)(*a++) * *b++;
    }

    return dot;
}

DOUBLE dot_dbl(const DOUBLE * SC_RESTRICT x, const DOUBLE * SC_RESTRICT y, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    DOUBLE dot = 0;
    const DOUBLE *a = x + u*n;
    const DOUBLE *b = y + v*n;

    for (k=n; k--;) {
        dot += *a++ * *b++;
    }

    return dot;
}

DOUBLE dot_sqr_dbl(const DOUBLE *x, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    DOUBLE dot = 0;
    const DOUBLE *a = x + u*n;

    for (k=n; k--;) {
        dot += (*a) * (*a);
        a++;
    }

    return dot;
}

FLOAT dot_sqr_flt(const FLOAT *x, size_t n, size_t u, size_t v)                            //dot product of two vectors within 2D arrays----columns u and v, size=length of vectors
{
    size_t k;
    FLOAT dot = 0;
    const FLOAT *a = x + u*n;

    for (k=n; k--;) {
        dot += (*a) * (*a);
        a++;
    }

    return dot;
}

LONGDOUBLE dot_ldbl(const LONGDOUBLE *x, const LONGDOUBLE *y, size_t n, size_t u, size_t v)
{
    size_t k;
    LONGDOUBLE dot = 0.0L;

    for (k=0; k<n; k++) {
        dot += x[u*n + k] * y[v*n + k];
    }

    return dot;
}

DOUBLE dot_ldbl_dbl(const LONGDOUBLE *x, const DOUBLE *y, size_t n, size_t u, size_t v)
{
    size_t k;
    DOUBLE dot = 0;

    for (k=0; k<n; k++) {
        dot += (DOUBLE) x[u*n + k] * y[v*n + k];
    }

    return dot;
}

FLOAT dot_ldbl_flt(const LONGDOUBLE *x, const FLOAT *y, size_t n, size_t u, size_t v)
{
    size_t k;
    FLOAT dot = 0;

    for (k=0; k<n; k++) {
        dot += (FLOAT) x[u*n + k] * y[v*n + k];
    }

    return dot;
}

LONGDOUBLE dot_s32_ldbl(const SINT32 *x, const LONGDOUBLE *y, size_t n, size_t u, size_t v)
{
    size_t k;
    LONGDOUBLE dot = 0;

    for (k=0; k<n; k++) {
        dot += (LONGDOUBLE) x[u*n + k] * y[v*n + k];
    }

    return dot;
}

LONGDOUBLE dot_s64_ldbl(const SINT64 *x, const LONGDOUBLE *y, size_t n, size_t u, size_t v)
{
    size_t k;
    LONGDOUBLE dot = 0;

    for (k=0; k<n; k++) {
        dot += (LONGDOUBLE) x[u*n + k] * y[v*n + k];
    }

    return dot;
}

void gpv_precompute_inv_ldbl(const LONGDOUBLE *b_gs, LONGDOUBLE *b_gs_inv_norm, size_t n)
{
    size_t j;
    for (j=0; j<n; j++) {
        LONGDOUBLE sqr = dot_ldbl(b_gs, b_gs, n, j, j);
        b_gs_inv_norm[j] = 1.0 / sqrtl(sqr);
    }
}

void gpv_precompute_inv_dbl(const DOUBLE *b_gs, DOUBLE *b_gs_inv_norm, size_t n)
{
    size_t j;
    for (j=0; j<n; j++) {
        DOUBLE sqr = dot_dbl(b_gs, b_gs, n, j, j);
        b_gs_inv_norm[j] = 1.0 / sqrt(sqr);
    }
}

void gpv_precompute_inv_flt(const FLOAT *b_gs, FLOAT *b_gs_inv_norm, size_t n)
{
    size_t j;
    for (j=0; j<n; j++) {
        DOUBLE sqr = dot_flt(b_gs, b_gs, n, j, j);
        b_gs_inv_norm[j] = (FLOAT)(1.0 / sqrt(sqr));
    }
}

void modified_gram_schmidt_classical(const gpv_t *gpv, LONGDOUBLE *b_gs, SINT32 q)
{
    size_t i, j, k;
    size_t n = gpv->n;
    LONGDOUBLE inv_sq_norm[2*n], temp[2*n];

    inv_sq_norm[0] = 0;
    for (k=0; k<2*n; k++) {
        inv_sq_norm[0] += gpv->b[k] * gpv->b[k];
    }
    inv_sq_norm[0] = 1 / inv_sq_norm[0];

    for (j=0; j<2*n; j++) {
        b_gs[j] = gpv->b[j];
    }

    for (i=1; i<2*n; i++) {
        for (k=0; k<2*n; k++) {
            b_gs[i*2*n + k] = gpv->b[i*2*n + k];
        }

        for (j=0; j<i; j++) {
            temp[j] = dot_ldbl(b_gs, b_gs, 2*n, i, j) * inv_sq_norm[j];
        }

        for (k=0; k<2*n; k++) {
            for (j=0; j<i; j++) {
                b_gs[i*2*n + k] -= temp[j] * gpv->b[j*2*n + k];
            }
        }

        inv_sq_norm[i] = 1 / dot_ldbl(b_gs, b_gs, 2*n, i, i);
    }
}

void modified_gram_schmidt_fast_flt(const gpv_t *gpv,
    FLOAT *b_gs, SINT32 q)
{
    size_t i, j;
    size_t n = gpv->n;
    FLOAT v[2*n] SC_DEFAULT_ALIGNED, v1[2*n] SC_DEFAULT_ALIGNED;
    FLOAT C_k, D_k;

    // First half

    for (i=0; i<n; i++) {
        b_gs[i] = gpv->g[i];
        b_gs[n+i] = -gpv->f[i];
    }

    for (i=0; i<n-1; i++) {
        v[i] = b_gs[i+1];
        v[n+i] = b_gs[i+n+1];
    }
    v[n-1] = -b_gs[0];
    v[2*n-1] = -b_gs[n];

    for (i=0; i<2*n; i++) {
        v1[i] = v[i];
    }

    C_k = dot_flt(b_gs, v, 2*n, 0, 0);
    D_k = dot_sqr_flt(v, 2*n, 0, 0);

    for (i=1; i<n; i++) {
        FLOAT aux = C_k / D_k;
        b_gs[i*2*n]     = -b_gs[(i-1)*2*n + n - 1]   + aux*v[n-1];
        b_gs[i*2*n + n] = -b_gs[(i-1)*2*n + 2*n - 1] + aux*v[2*n-1];
        for (j=1; j<n; j++) {
            b_gs[i*2*n + j]     = b_gs[(i-1)*2*n + j - 1]     - aux*v[j-1];
            b_gs[i*2*n + n + j] = b_gs[(i-1)*2*n + n + j - 1] - aux*v[n+j-1];
        }

        for (j=0; j<2*n; j++) {
            v[j] -= aux * b_gs[(i-1)*2*n + j];
        }

        FLOAT C_ko = C_k;
        FLOAT D_ko = D_k;
        C_k = dot_flt(b_gs, v1, 2*n, i, 0);
        D_k = D_ko - C_ko * C_ko / D_ko;
    }

    // Second half

    for (i=0; i<n; i++) {
        b_gs[n*2*n + n + i] = b_gs[(n-1)*2*n + n - 1 - i] * (FLOAT)q / D_k;
        b_gs[n*2*n + i]     = -b_gs[(n-1)*2*n + 2*n - 1 - i] * (FLOAT)q / D_k;
    }

    for (i=0; i<n-1; i++) {
        v[i]   = b_gs[n*2*n+i+1];
        v[n+i] = b_gs[n*2*n+i+n+1];
    }
    v[n-1] = -b_gs[n*2*n];
    v[2*n-1] = -b_gs[n*2*n + n];

    for (i=0; i<2*n; i++) {
        v1[i] = v[i];
    }

    C_k = dot_flt(b_gs, v1, 2*n, n, 0);
    D_k = dot_sqr_flt(b_gs, 2*n, n, n);

    for (i=n+1; i<2*n; i++) {
        FLOAT aux = C_k / D_k;
        b_gs[i*2*n]     = -b_gs[(i-1)*2*n + n - 1]   + aux*v[n-1];
        b_gs[i*2*n + n] = -b_gs[(i-1)*2*n + 2*n - 1] + aux*v[2*n-1];
        for (j=1; j<n; j++) {
            b_gs[i*2*n + j]     = b_gs[(i-1)*2*n + j - 1]     - aux*v[j-1];
            b_gs[i*2*n + n + j] = b_gs[(i-1)*2*n + n + j - 1] - aux*v[n+j-1];
        }

        for (j=0; j<2*n; j++) {
            v[j] -= aux * b_gs[(i-1)*2*n + j];
        }

        FLOAT C_ko = C_k;
        FLOAT D_ko = D_k;
        C_k = dot_flt(b_gs, v1, 2*n, i, 0);
        D_k = D_ko - C_ko * C_ko / D_ko;
    }
}

void modified_gram_schmidt_fast_dbl(const gpv_t *gpv,
    DOUBLE *b_gs, SINT32 q)
{
    size_t i, j;
    size_t n = gpv->n;
    DOUBLE v[2*n] SC_DEFAULT_ALIGNED, v1[2*n] SC_DEFAULT_ALIGNED;
    DOUBLE C_k, D_k;

    // First half

    for (i=0; i<n; i++) {
        b_gs[i] = gpv->g[i];
        b_gs[n+i] = -gpv->f[i];
    }

    for (i=0; i<n-1; i++) {
        v[i] = b_gs[i+1];
        v[n+i] = b_gs[i+n+1];
    }
    v[n-1] = -b_gs[0];
    v[2*n-1] = -b_gs[n];

    for (i=0; i<2*n; i++) {
        v1[i] = v[i];
    }

    C_k = dot_dbl(b_gs, v, 2*n, 0, 0);
    D_k = dot_sqr_dbl(v, 2*n, 0, 0);

    for (i=1; i<n; i++) {
        DOUBLE aux = C_k / D_k;
        b_gs[i*2*n]     = -b_gs[(i-1)*2*n + n - 1]   + aux*v[n-1];
        b_gs[i*2*n + n] = -b_gs[(i-1)*2*n + 2*n - 1] + aux*v[2*n-1];
        for (j=1; j<n; j++) {
            b_gs[i*2*n + j]     = b_gs[(i-1)*2*n + j - 1]     - aux*v[j-1];
            b_gs[i*2*n + n + j] = b_gs[(i-1)*2*n + n + j - 1] - aux*v[n+j-1];
        }

        for (j=0; j<2*n; j++) {
            v[j] -= aux * b_gs[(i-1)*2*n + j];
        }

        DOUBLE C_ko = C_k;
        DOUBLE D_ko = D_k;
        C_k = dot_dbl(b_gs, v1, 2*n, i, 0);
        D_k = D_ko - C_ko * C_ko / D_ko;
    }

    // Second half

    DOUBLE inv_D_k = 1.0 / D_k;
    for (i=0; i<n; i++) {
        b_gs[n*2*n + n + i] = b_gs[(n-1)*2*n + n - 1 - i] * (DOUBLE)q * inv_D_k;// / D_k;
        b_gs[n*2*n + i]     = -b_gs[(n-1)*2*n + 2*n - 1 - i] * (DOUBLE)q * inv_D_k;/// D_k;
    }

    for (i=0; i<n-1; i++) {
        v[i]   = b_gs[n*2*n+i+1];
        v[n+i] = b_gs[n*2*n+i+n+1];
    }
    v[n-1] = -b_gs[n*2*n];
    v[2*n-1] = -b_gs[n*2*n + n];

    for (i=0; i<2*n; i++) {
        v1[i] = v[i];
    }

    C_k = dot_dbl(b_gs, v1, 2*n, n, 0);
    D_k = dot_sqr_dbl(b_gs, 2*n, n, n);

    for (i=n+1; i<2*n; i++) {
        DOUBLE aux = C_k / D_k;
        b_gs[i*2*n]     = -b_gs[(i-1)*2*n + n - 1]   + aux*v[n-1];
        b_gs[i*2*n + n] = -b_gs[(i-1)*2*n + 2*n - 1] + aux*v[2*n-1];
        for (j=1; j<n; j++) {
            b_gs[i*2*n + j]     = b_gs[(i-1)*2*n + j - 1]     - aux*v[j-1];
            b_gs[i*2*n + n + j] = b_gs[(i-1)*2*n + n + j - 1] - aux*v[n+j-1];
        }

        for (j=0; j<2*n; j++) {
            v[j] -= aux * b_gs[(i-1)*2*n + j];
        }

        DOUBLE C_ko = C_k;
        DOUBLE D_ko = D_k;
        C_k = dot_dbl(b_gs, v1, 2*n, i, 0);
        D_k = D_ko - C_ko * C_ko / D_ko;
    }
}

void modified_gram_schmidt_fast_ldbl(const gpv_t *gpv,
    LONGDOUBLE *b_gs, SINT32 q)
{
    size_t i, j;
    size_t n = gpv->n;
    LONGDOUBLE v[2*n] SC_DEFAULT_ALIGNED, v1[2*n] SC_DEFAULT_ALIGNED;
    LONGDOUBLE C_k, D_k;

    // First half

    for (i=0; i<n; i++) {
        b_gs[i] = gpv->g[i];
        b_gs[n+i] = -gpv->f[i];
    }

    for (i=0; i<n-1; i++) {
        v[i] = b_gs[i+1];
        v[n+i] = b_gs[i+n+1];
    }
    v[n-1] = -b_gs[0];
    v[2*n-1] = -b_gs[n];

    for (i=0; i<2*n; i++) {
        v1[i] = v[i];
    }

    C_k = dot_ldbl(b_gs, v, 2*n, 0, 0);
    D_k = dot_ldbl(v, v, 2*n, 0, 0);

    for (i=1; i<n; i++) {
        LONGDOUBLE aux = C_k / D_k;
        b_gs[i*2*n]     = -b_gs[(i-1)*2*n + n - 1]   + aux*v[n-1];
        b_gs[i*2*n + n] = -b_gs[(i-1)*2*n + 2*n - 1] + aux*v[2*n-1];
        for (j=1; j<n; j++) {
            b_gs[i*2*n + j]     = b_gs[(i-1)*2*n + j - 1]     - aux*v[j-1];
            b_gs[i*2*n + n + j] = b_gs[(i-1)*2*n + n + j - 1] - aux*v[n+j-1];
        }

        for (j=0; j<2*n; j++) {
            v[j] -= aux * b_gs[(i-1)*2*n + j];
        }

        LONGDOUBLE C_ko = C_k;
        LONGDOUBLE D_ko = D_k;
        C_k = dot_ldbl(b_gs, v1, 2*n, i, 0);
        D_k = D_ko - C_ko * C_ko / D_ko;
    }

    // Second half

    for (i=0; i<n; i++) {
        b_gs[n*2*n + n + i] = b_gs[(n-1)*2*n + n - 1 - i] * (LONGDOUBLE)q / D_k;
        b_gs[n*2*n + i]     = -b_gs[(n-1)*2*n + 2*n - 1 - i] * (LONGDOUBLE)q / D_k;
    }

    for (i=0; i<n-1; i++) {
        v[i]   = b_gs[n*2*n+i+1];
        v[n+i] = b_gs[n*2*n+i+n+1];
    }
    v[n-1] = -b_gs[n*2*n];
    v[2*n-1] = -b_gs[n*2*n + n];

    for (i=0; i<2*n; i++) {
        v1[i] = v[i];
    }

    C_k = dot_ldbl(b_gs, v1, 2*n, n, 0);
    D_k = dot_ldbl(b_gs, b_gs, 2*n, n, n);

    for (i=n+1; i<2*n; i++) {
        LONGDOUBLE aux = C_k / D_k;
        b_gs[i*2*n]     = -b_gs[(i-1)*2*n + n - 1]   + aux*v[n-1];
        b_gs[i*2*n + n] = -b_gs[(i-1)*2*n + 2*n - 1] + aux*v[2*n-1];
        for (j=1; j<n; j++) {
            b_gs[i*2*n + j]     = b_gs[(i-1)*2*n + j - 1]     - aux*v[j-1];
            b_gs[i*2*n + n + j] = b_gs[(i-1)*2*n + n + j - 1] - aux*v[n+j-1];
        }

        for (j=0; j<2*n; j++) {
            v[j] -= aux * b_gs[(i-1)*2*n + j];
        }

        LONGDOUBLE C_ko = C_k;
        LONGDOUBLE D_ko = D_k;
        C_k = dot_ldbl(b_gs, v1, 2*n, i, 0);
        D_k = D_ko - C_ko * C_ko / D_ko;
    }
}

SINT32 gpv_gen_basis(safecrypto_t *sc, SINT32 *f, SINT32 *g, SINT32 *h,
    size_t n, SINT32 q,
    utils_sampling_t *sampling, prng_ctx_t *prng_ctx,
    SINT32 *F, SINT32 *G, SINT32 recreate_flag)
{
    size_t i, j;
    DOUBLE sigma;
    DOUBLE gs_norm;
    sc_mpz_t Rf, Rg, gcd1, gcd2;
    sc_poly_mpz_t rho_f, rho_g, rho_dummy;
    sc_mpz_t alpha, beta, mp_q;
    sc_poly_mpz_t mp_f, mp_g;
    SINT32 retval = -1, num_retries = 0;

    SC_TIMER_INSTANCE(timer);
    SC_TIMER_CREATE(timer);
    SC_TIMER_RESET(timer);

    SC_TIMER_INSTANCE(total_timer);
    SC_TIMER_CREATE(total_timer);
    SC_TIMER_RESET(total_timer);

    sc_mpz_init(&Rf);
    sc_mpz_init(&Rg);
    sc_mpz_init(&gcd1);
    sc_mpz_init(&gcd2);
    sc_poly_mpz_init(&rho_f, n+1);
    sc_poly_mpz_init(&rho_g, n+1);
    sc_poly_mpz_init(&rho_dummy, n+1);
    sc_mpz_init(&alpha);
    sc_mpz_init(&beta);
    sc_poly_mpz_init(&mp_f, n);
    sc_poly_mpz_init(&mp_g, n);
    sc_mpz_init(&mp_q);
    sc_mpz_set_ui(&mp_q, q);

    SC_TIMER_START(timer);
    SC_TIMER_START(total_timer);


    // Computations are done mod x^N+1-----this defines this polynomial
    sc_poly_mpz_t polymod;
    sc_poly_mpz_init(&polymod, n+1);
    sc_poly_mpz_set_si(&polymod, 0, 1);
    sc_poly_mpz_set_si(&polymod, n, 1);

    sc_mpz_t qv, qu;
    sc_poly_mpz_t pF, pG;
    sc_poly_mpz_init(&pF, n);
    sc_poly_mpz_init(&pG, n);
    sc_mpz_init(&qv);
    sc_mpz_init(&qu);

    sc_poly_mpz_t pfbar, pgbar;
    sc_poly_mpz_init(&pfbar, n);
    sc_poly_mpz_init(&pgbar, n);

    sc_poly_mpz_t temp, num, den, k;
    sc_poly_mpz_init(&temp, 2*n);
    sc_poly_mpz_init(&num, n);
    sc_poly_mpz_init(&den, n);
    sc_poly_mpz_init(&k, n);

    sc_poly_mpz_t inv_f;
    sc_poly_mpz_init(&inv_f, n);

    sc_mpz_t scale;
    sc_mpz_init(&scale);

    // Step 1. set standard deviation of Gaussian distribution
    DOUBLE bd;
    bd  = 1.17*sqrt(q);

    // Step 2. Obtain f, g using Gaussian Samplers
    sigma  = sqrt((1.36 * q / 2) / n);
#if DEBUG_GPV == 1
    fprintf(stderr, "n=%zu, q=%d\n", n, q);
#endif
step2:
    // If f and g are already provided as inputs as we are recreating F and G
    // then do not sample new distributions
    if (0 == recreate_flag) {
        get_vector_32(sampling, f, n, 0);
        get_vector_32(sampling, g, n, 0);
    }
    else {
        // If we are recreating the private key and we require a restart then
        // there has been an error
        goto finish;
    }

    // Step 3. calculate the GramSchmidt norm
    gs_norm = gram_schmidt_norm(f, g, n, q, bd);
    if (isnan(gs_norm)) {
        num_retries++;
        goto step2;
    }

    // Step 4. check whether norm is small enough; if not, repeat
    if (gs_norm > bd) {
        num_retries++;
        goto step2;
    }
#if DEBUG_GPV == 1
    fprintf(stderr, "GS=%3.3f, threshold=%3.3f\n", gs_norm, bd);
#endif

    SC_TIMER_STOP(timer);
#if DEBUG_GPV == 1
    fprintf(stderr, "Time to compute GS Norm: %3.3f sec\n", SC_TIMER_GET_ELAPSED(timer));
#endif
    SC_TIMER_RESET(timer);
    SC_TIMER_START(timer);



    poly_si32_to_mpi(&mp_f, n, f);
    poly_si32_to_mpi(&mp_g, n, g);

    // Step 5, 6, 7. Polynomial Euclidean to find 4 unknowns
    //poly_mpi_reset(&rho_f, 0);
    sc_poly_mpz_xgcd(&mp_f, &polymod, &Rf, &rho_f, &rho_dummy);
    sc_mpz_gcd(&Rf, &mp_q, &gcd2);

#if DEBUG_GPV == 1
    fprintf(stderr, "GCD(Rf,q) = "); sc_mpz_out_str(stderr, 16, &gcd2); fprintf(stderr, "\n");
#endif

    SC_TIMER_STOP(timer);
#if DEBUG_GPV == 1
    fprintf(stderr, "Time to compute XGCD(f,phi): %3.3f sec\n", SC_TIMER_GET_ELAPSED(timer));
#endif
    SC_TIMER_RESET(timer);
    SC_TIMER_START(timer);

    if (0 != sc_mpz_cmp_ui(&gcd2, 1)) {
        // It is more efficient to check that gcd(Rf,q) == 1 early
        num_retries++;
        goto step2;
    }
    sc_poly_mpz_xgcd(&mp_g, &polymod, &Rg, &rho_g, &rho_dummy);
    SC_TIMER_STOP(timer);
#if DEBUG_GPV == 1
    fprintf(stderr, "Time to compute XGCD(g,phi): %3.3f sec\n", SC_TIMER_GET_ELAPSED(timer));
#endif
    SC_TIMER_RESET(timer);
    SC_TIMER_START(timer);

    sc_mpz_xgcd(&Rf, &Rg, &gcd1, &alpha, &beta);
    SC_TIMER_STOP(timer);
#if DEBUG_GPV == 1
    fprintf(stderr, "Time to compute GCD(Rf,Rg): %3.3f sec\n", SC_TIMER_GET_ELAPSED(timer));
#endif
    SC_TIMER_RESET(timer);
    SC_TIMER_START(timer);

    if (1 != sc_mpz_get_ui(&gcd1)) {
        // The gcd(Rf,Rg) and the computation of u and v are performed
        // together for efficiency
        num_retries++;
        goto step2;
    }
#if DEBUG_GPV == 1
    fprintf(stderr, "GCD(Rf,Rg) = 1\n");
#endif
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "f", f, n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "g", g, n);

    SC_TIMER_STOP(timer);
    SC_TIMER_STOP(total_timer);
#if DEBUG_GPV == 1
    fprintf(stderr, "Time to compute f and g: %3.3f sec\n", SC_TIMER_GET_ELAPSED(total_timer));
#endif

    SC_TIMER_RESET(timer);
    SC_TIMER_START(timer);
    SC_TIMER_START(total_timer);

    // Step 8. Calculate the polynomials F, G
    sc_mpz_mul_si(&qv, &beta, -q);
    sc_mpz_mul_si(&qu, &alpha, q);
    sc_poly_mpz_mul_scalar(&pF, &rho_g, &qv); // F = -q * rho_g * beta
    sc_poly_mpz_mul_scalar(&pG, &rho_f, &qu); // G = q * rho_f * alpha

    // Step 9. Calculate f-bar, g-bar and the reduction factor k
    sc_poly_mpz_reverse(&pfbar, n, &mp_f);
    sc_poly_mpz_reverse(&pgbar, n, &mp_g);

    // k = (F*fb + G*gb) / (f*fb + g*gb)
    sc_poly_mpz_mul(&temp, &mp_f, &pfbar);
    sc_poly_mpz_addmul(&temp, &mp_g, &pgbar);
    sc_poly_mpz_mod_ring(&den, n, &temp);

#if DEBUG_GPV == 1
    fprintf(stderr, "XGCD scale computation ...\n");
#endif
#ifdef ENABLE_CALLGRIND_PROFILING
    CALLGRIND_START_INSTRUMENTATION;
#endif
    SINT32 errcode = sc_poly_mpz_xgcd(&den, &polymod, &scale, &rho_g, &rho_dummy);
    if (SC_FUNC_FAILURE == errcode) {
        fprintf(stderr, "ERROR! sc_poly_mpz_xgcd() failed\n");
        goto finish;
    }
#ifdef ENABLE_CALLGRIND_PROFILING
    CALLGRIND_STOP_INSTRUMENTATION;
    CALLGRIND_DUMP_STATS;
#endif

    SC_TIMER_STOP(timer);
#if DEBUG_GPV == 1
    fprintf(stderr, "Time to scale: %3.3f sec\n", SC_TIMER_GET_ELAPSED(timer));
#endif
    SC_TIMER_RESET(timer);
    SC_TIMER_START(timer);

#if DEBUG_GPV == 1
    fprintf(stderr, "Computing reduction factor k ...\n");
#endif

    //poly_mpi_reset(&temp, 0);
    sc_poly_mpz_mul(&temp, &pF, &pfbar);
    sc_poly_mpz_addmul(&temp, &pG, &pgbar);
    sc_poly_mpz_mod_ring(&num, n, &temp);

    // den * rho_g + polymod * rho_dummy = gcd(den, polymod) = scale
    // => den * rho_g = scale
    // => 1/den = rho_g / scale
    // Therefore, k = num/den = num * rho_g / scale
    sc_poly_mpz_mul(&temp, &num, &rho_g);
    sc_poly_mpz_mod_ring(&k, n, &temp);
#if DEBUG_GPV == 1
    fprintf(stderr, "Scaling reduction factor k ...\n");
#endif
    for (size_t i=n; i--;) {
        sc_mpz_divquo(&k.p[i], &k.p[i], &scale);
    }

    // Step 10. Reduce F and G
#if DEBUG_GPV == 1
    fprintf(stderr, "Reducing F and G ...\n");
    fprintf(stderr, "k = \n");
    for (i=0; i<n; i++) {
        sc_mpz_out_str(stderr, 10, &k.p[i]);
        fprintf(stderr, " ");
        if (7 == (7&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
#endif
    SINT32 deg_k = sc_poly_mpz_degree(&k);
    for (j=0; j<16; j++) {
    //while (deg_k >= 0 && !mpi_is_zero(&k.p[0])) {
        sc_poly_mpz_mul(&temp, &k, &mp_f);
        sc_poly_mpz_sub(&temp, &pF, &temp);      // F = F - k*f
        sc_poly_mpz_mod_ring(&pF, n, &temp);
        sc_poly_mpz_mul(&temp, &k, &mp_g);
        sc_poly_mpz_sub(&temp, &pG, &temp);      // G = G - k*g
        sc_poly_mpz_mod_ring(&pG, n, &temp);

        sc_poly_mpz_mul(&temp, &pF, &pfbar);
        sc_poly_mpz_addmul(&temp, &pG, &pgbar);
        sc_poly_mpz_mod_ring(&num, n, &temp);

        sc_poly_mpz_mul(&temp, &num, &rho_g);
        sc_poly_mpz_mod_ring(&k, n, &temp);
        for (size_t i=n; i--;) {
            sc_mpz_divquo(&k.p[i], &k.p[i], &scale);
        }

        deg_k = sc_poly_mpz_degree(&k);
        if (0 == deg_k && sc_mpz_is_zero(&k.p[0])) {
            break;
        }
        if (15 == j) {
            num_retries++;
            goto finish;
        }
    }

    for (i=n; i--;) {
        F[i] = sc_poly_mpz_get_si(&pF, i);
        G[i] = sc_poly_mpz_get_si(&pG, i);
    }

#if DEBUG_GPV == 1
    fprintf(stderr, "\n");
    fprintf(stderr, "f = \n");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%6d ", f[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "g = \n");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%6d ", g[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
    SINT32 sum = 0;
    fprintf(stderr, "F = \n");
    for (i=0; i<n; i++) {
        sum += F[i] * F[i];
        fprintf(stderr, "%6d ", F[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n(SUM = %d)\n", sum);
    sum = 0;
    fprintf(stderr, "G = \n");
    for (i=0; i<n; i++) {
        sum += G[i] * G[i];
        fprintf(stderr, "%6d ", G[i]);
        if (15 == (15&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n(SUM = %d)\n", sum);

    fprintf(stderr, "Verifying master key ...\n");
#endif
    sc_poly_mpz_mul(&temp, &pG, &mp_f);
    sc_poly_mpz_submul(&temp, &pF, &mp_g);      // F = F - k*f
    sc_poly_mpz_mod_ring(&temp, n, &temp);
    UINT32 verify = sc_mpz_get_ui(&temp.p[0]);

#if DEBUG_GPV == 1
    fprintf(stderr, "    q = 0x%08X, f*G - g*F = 0x%08X :: %s\n",
        q, verify, (q == verify)? "VERIFIED" : "FAILED");
#endif
    if (q != verify) {
        num_retries++;
        goto step2;
    }

    // Step 11. Compute the public key h = g/f mod q

    sc_mod_t modulus;
    limb_mod_init(&modulus, q);

    // Don't need this as it's done above ...
    //poly_mpi_xgcd(&mp_f, &polymod, &Rg, &rho_dummy, &rho_f);




    sc_poly_mpz_xgcd(&mp_f, &polymod, &Rf, &rho_f, &rho_dummy);
    sc_mpz_invmod(&Rf, &Rf, &mp_q);
    //poly_mpi_mod(&rho_f, &rho_f, &modulus);
    sc_poly_mpz_mul_scalar(&inv_f, &rho_f, &Rf);

    sc_poly_mpz_mul(&temp, &inv_f, &mp_f);
    sc_poly_mpz_mod_ring(&temp, n, &temp);
    sc_poly_mpz_mod(&temp, &temp, &modulus);

    for (i=0; i<n; i++) {
        sc_slimb_t val = sc_poly_mpz_get_si(&temp, i);
        if (0 == i && 1 != val) {
            num_retries++;
            goto step2;
        }
        if (0 != i && 0 != val) {
            num_retries++;
            goto step2;
        }
    }

    //poly_mpi_mod(&mp_f, &mp_f, &modulus);
    sc_poly_mpz_mul(&temp, &mp_g, &inv_f);
    sc_poly_mpz_mod_ring(&temp, n, &temp);
    sc_poly_mpz_mod(&temp, &temp, &modulus);

    for (i=n; i--;) {
        h[i] = sc_poly_mpz_get_si(&temp, i);
    }

#if DEBUG_GPV == 1
    fprintf(stderr, "\nh = g/f mod q =\n");
    for (i=0; i<n; i++) {
        sc_mpz_out_str(stderr, 10, &temp.p[i]);
        fprintf(stderr, " ");
        if (7 == (7&i)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
#endif

    retval = num_retries;

finish:
    sc_poly_mpz_clear(&inv_f);
    sc_mpz_clear(&Rf);
    sc_mpz_clear(&Rg);
    sc_mpz_clear(&gcd1);
    sc_mpz_clear(&gcd2);
    sc_poly_mpz_clear(&polymod);
    sc_poly_mpz_clear(&rho_f);
    sc_poly_mpz_clear(&rho_g);
    sc_poly_mpz_clear(&rho_dummy);
    sc_mpz_clear(&alpha);
    sc_mpz_clear(&beta);
    sc_poly_mpz_clear(&mp_f);
    sc_poly_mpz_clear(&mp_g);
    sc_mpz_clear(&mp_q);
    sc_poly_mpz_clear(&pF);
    sc_poly_mpz_clear(&pG);
    sc_mpz_clear(&qv);
    sc_mpz_clear(&qu);
    sc_mpz_clear(&scale);
    sc_poly_mpz_clear(&pfbar);
    sc_poly_mpz_clear(&pgbar);
    sc_poly_mpz_clear(&temp);
    sc_poly_mpz_clear(&num);
    sc_poly_mpz_clear(&den);
    sc_poly_mpz_clear(&k);

    SC_TIMER_STOP(timer);
    SC_TIMER_STOP(total_timer);
#if DEBUG_GPV == 1
    fprintf(stderr, "Time to compute F, G and h: %3.3f sec\n", SC_TIMER_GET_ELAPSED(timer));
    fprintf(stderr, "Total time: %3.3f sec\n", SC_TIMER_GET_ELAPSED(total_timer));
#endif

    SC_TIMER_DESTROY(timer);
    SC_TIMER_DESTROY(total_timer);

#if DEBUG_GPV == 1
    fprintf(stderr, "Polynomial basis found\n");
#endif
    return retval;
}

SINT32 gaussian_lattice_sample_on_the_fly_flt(safecrypto_t *sc,
    const gpv_t *gpv, const FLOAT *b_gs, const FLOAT *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v, UINT32 q, DOUBLE s_f)
{
    size_t i, j;
    size_t n = gpv->n;

    SINT64 ci[2*n];
    for (j=n; j--;) {
        ci[j] = c[j];
        ci[n+j] = 0;
    }

    SC_PRINT_DEBUG(sc, "s_f = %3.6Lf\n", s_f);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "H(id)", c, n);

    // Adaptive Gaussian Sampling
    utils_sampling_t *gauss = NULL;
    FLOAT sig = 0L;
    for (j=2*n; j--;) {
        FLOAT d, dot_product;
        dot_product = dot_s64_flt(ci, b_gs, 2*n, 0, j);
        d   = dot_product * b_gs_inv_norm[j] * b_gs_inv_norm[j];

        if (0L == sig) {
            sig = s_f * b_gs_inv_norm[j];

            gauss = create_sampler(
                sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                sc->prng_ctx[0], 10, sig);
            if (NULL == gauss) {
                return SC_FUNC_FAILURE;
            }
        }

        SINT32 z;
        z = get_sample(gauss) + (SINT32) d;

        for (i=0; i<2*n; i++) {
            ci[i] -= z * gpv_read_basis(gpv, j, i);
        }

        if (j == n) {
            sig = 0L;
            destroy_sampler(&gauss);
        }
    }
    destroy_sampler(&gauss);

    // Output final vector - only the latter half of "c - ci" is needed where
    // c is actually 0 for n to 2n-1
    for (j=0; j<n; j++) {
        v[j] = ci[n+j];
    }

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "User Secret Key", v, n);

    return SC_FUNC_SUCCESS;
}

SINT32 gaussian_lattice_sample_on_the_fly_dbl(safecrypto_t *sc,
    const gpv_t *gpv, const DOUBLE *b_gs, const DOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v, UINT32 q, DOUBLE s_f)
{
    size_t i, j;
    size_t n = gpv->n;

    SINT64 ci[2*n];
    for (j=n; j--;) {
        ci[j] = c[j];
        ci[n+j] = 0;
    }

    SC_PRINT_DEBUG(sc, "s_f = %3.6Lf\n", s_f);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "H(id)", c, n);

    // Adaptive Gaussian Sampling
    utils_sampling_t *gauss = NULL;
    DOUBLE sig = 0L;
    for (j=2*n; j--;) {
        DOUBLE d, dot_product;
        dot_product = dot_s64_dbl(ci, b_gs, 2*n, 0, j);
        d   = dot_product * b_gs_inv_norm[j] * b_gs_inv_norm[j];

        if (0L == sig) {
            sig = s_f * b_gs_inv_norm[j];

            gauss = create_sampler(
                sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                sc->prng_ctx[0], 10, sig);
            if (NULL == gauss) {
                return SC_FUNC_FAILURE;
            }
        }

        SINT32 z;
        z = get_sample(gauss) + (SINT32) d;

        for (i=0; i<2*n; i++) {
            ci[i] -= z * gpv_read_basis(gpv, j, i);
        }

        if (j == n) {
            sig = 0L;
            destroy_sampler(&gauss);
        }
    }
    destroy_sampler(&gauss);

    // Output final vector - only the latter half of "c - ci" is needed where
    // c is actually 0 for n to 2n-1
    for (j=0; j<n; j++) {
        v[j] = ci[n+j];
    }

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "User Secret Key", v, n);

    return SC_FUNC_SUCCESS;
}

SINT32 gaussian_lattice_sample_on_the_fly_ldbl(safecrypto_t *sc,
    const gpv_t *gpv, const LONGDOUBLE *b_gs, const LONGDOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v, UINT32 q, DOUBLE s_f)
{
    size_t i, j;
    size_t n = gpv->n;

    LONGDOUBLE ci[2*n];
    for (j=n; j--;) {
        ci[j] = c[j];
        ci[n+j] = 0;
    }

    SC_PRINT_DEBUG(sc, "s_f = %3.6Lf\n", s_f);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "H(id)", c, n);

    // Adaptive Gaussian Sampling
    utils_sampling_t *gauss = NULL;
    LONGDOUBLE sig = 0L;
    for (j=2*n; j--;) {
        LONGDOUBLE d, dot_product;
        dot_product = dot_ldbl(ci, b_gs, 2*n, 0, j);
        d   = dot_product * b_gs_inv_norm[j] * b_gs_inv_norm[j];

        if (0L == sig) {
            sig = s_f * b_gs_inv_norm[j];

            gauss = create_sampler(
                sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                sc->prng_ctx[0], 10, sig);
            if (NULL == gauss) {
                return SC_FUNC_FAILURE;
            }
        }

        SINT32 z;
        z = get_sample(gauss) + (SINT32) d;

        for (i=0; i<2*n; i++) {
            ci[i] -= z * gpv_read_basis(gpv, j, i);
        }

        if (j == n) {
            sig = 0L;
            destroy_sampler(&gauss);
        }
    }
    destroy_sampler(&gauss);

    // Output final vector - only the latter half of "c - ci" is needed where
    // c is actually 0 for n to 2n-1
    for (j=0; j<n; j++) {
        v[j] = ci[n+j];
    }

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "User Secret Key", v, n);

    return SC_FUNC_SUCCESS;
}

SINT32 gaussian_lattice_sample_flt(safecrypto_t *sc,
    const gpv_t *gpv, const FLOAT *b_gs, const FLOAT *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v1, SINT32 *v2,
    UINT32 q, DOUBLE s_f, UINT32 flags)
{
    size_t i, j;
    size_t n = gpv->n;
    SINT64 z;

    SINT64 ci[2*n];
    for (j=n; j--;) {
        ci[j] = c[j];
        ci[n+j] = 0;
    }

    SC_PRINT_DEBUG(sc, "s_f = %3.6Lf\n", s_f);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "H(id)", c, n);

    // Adaptive Gaussian Sampling
    utils_sampling_t *gauss = NULL;
    if (flags & GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP) {
        gauss = sc->sc_gauss;
    }
    FLOAT sig = 0L;
    for (j=2*n; j--;) {
        FLOAT d, dot_product;
        dot_product = dot_s64_flt(ci, b_gs, 2*n, 0, j);
        d = dot_product * b_gs_inv_norm[j] * b_gs_inv_norm[j];

        if (flags & GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP) {
            sig = s_f * b_gs_inv_norm[j];
            z = get_bootstrap_sample(gauss, sig, d);
        }
        else {
            if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
                if (0L == sig) {
                    sig = s_f * b_gs_inv_norm[j];
    
                    gauss = create_sampler(
                      sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                        sc->prng_ctx[0], 10, sig);
                    if (NULL == gauss) {
                        return SC_FUNC_FAILURE;
                    }
                }
            }
            else {
                sig = s_f * b_gs_inv_norm[j];
    
                gauss = create_sampler(
                    sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                    sc->prng_ctx[0], 10, sig);
                if (NULL == gauss) {
                    return SC_FUNC_FAILURE;
                }
            }
    
            z = get_sample(gauss) + (SINT32) d;
        }

        for (i=2*n; i--;) {
            ci[i] -= z * gpv->b[j*2*n + i];
        }

        if (!(flags & GPV_GAUSSIAN_SAMPLE_MW_BOOTSTRAP)) {
            if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
                if (j == n) {
                    sig = 0L;
                    destroy_sampler(&gauss);
                }
            }
            else {
                destroy_sampler(&gauss);
            }
        }
    }
    if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
        destroy_sampler(&gauss);
    }

    // Output final vector - only the latter half of "c - ci" is needed where
    // c is actually 0 for n to 2n-1
    for (j=0; j<n; j++) {
        v1[j] = ci[n+j];
    }
    if (v2) {
        for (j=0; j<n; j++) {
           v2[j] = ci[j];
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 gaussian_lattice_sample_dbl(safecrypto_t *sc,
    const gpv_t *gpv, const DOUBLE *b_gs, const DOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v1, SINT32 *v2,
    UINT32 q, DOUBLE s_f, UINT32 flags)
{
    size_t i, j;
    size_t n = gpv->n;

    SINT64 ci[2*n];
    for (j=n; j--;) {
        ci[j] = c[j];
        ci[n+j] = 0;
    }

    SC_PRINT_DEBUG(sc, "s_f = %3.6Lf\n", s_f);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "H(id)", c, n);

    // Adaptive Gaussian Sampling
    utils_sampling_t *gauss = NULL;
    DOUBLE sig = 0L;
    for (j=2*n; j--;) {
        DOUBLE d, dot_product;
        dot_product = dot_s64_dbl(ci, b_gs, 2*n, 0, j);
        d = dot_product * b_gs_inv_norm[j] * b_gs_inv_norm[j];

        if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
            if (0L == sig) {
                sig = s_f * b_gs_inv_norm[j];

                gauss = create_sampler(
                    sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                    sc->prng_ctx[0], 10, sig);
                if (NULL == gauss) {
                   return SC_FUNC_FAILURE;
                }
            }
        }
        else {
            sig = s_f * b_gs_inv_norm[j];

            gauss = create_sampler(
                sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                sc->prng_ctx[0], 10, sig);
            if (NULL == gauss) {
                return SC_FUNC_FAILURE;
            }
        }

        SINT64 z;
        z = get_sample(gauss) + (SINT32) d;

        for (i=2*n; i--;) {
            ci[i] -= z * gpv->b[j*2*n + i];
        }

        if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
            if (j == n) {
                sig = 0L;
                destroy_sampler(&gauss);
            }
        }
        else {
            destroy_sampler(&gauss);
        }
    }
    if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
        destroy_sampler(&gauss);
    }

    // Output final vector - only the latter half of "c - ci" is needed where
    // c is actually 0 for n to 2n-1
    for (j=0; j<n; j++) {
        v1[j] = ci[n+j];
    }
    if (v2) {
        for (j=0; j<n; j++) {
           v2[j] = ci[j];
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 gaussian_lattice_sample_ldbl(safecrypto_t *sc,
    const gpv_t *gpv, const LONGDOUBLE *b_gs, const LONGDOUBLE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v1, SINT32 *v2,
    UINT32 q, DOUBLE s_f, UINT32 flags)
{
    size_t i, j;
    size_t n = gpv->n;

    LONGDOUBLE ci[2*n];
    for (j=n; j--;) {
        ci[j] = c[j];
        ci[n+j] = 0;
    }

    SC_PRINT_DEBUG(sc, "s_f = %3.6Lf\n", s_f);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "H(id)", c, n);

    // Adaptive Gaussian Sampling
    utils_sampling_t *gauss = NULL;
    LONGDOUBLE sig = 0L;
    for (j=2*n; j--;) {
        LONGDOUBLE d, dot_product;
        dot_product = dot_ldbl(ci, b_gs, 2*n, 0, j);
        d = dot_product * b_gs_inv_norm[j] * b_gs_inv_norm[j];

        if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
            if (0L == sig) {
                sig = s_f * b_gs_inv_norm[j];

                gauss = create_sampler(
                    sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                    sc->prng_ctx[0], 10, sig);
                if (NULL == gauss) {
                    return SC_FUNC_FAILURE;
                }
            }
        }
        else {
            sig = s_f * b_gs_inv_norm[j];

            gauss = create_sampler(
                sc->sampling, SAMPLING_64BIT, sc->blinding, 1, SAMPLING_DISABLE_BOOTSTRAP,
                sc->prng_ctx[0], 10, sig);
            if (NULL == gauss) {
                return SC_FUNC_FAILURE;
            }
        }

        SINT64 z;
        z = get_sample(gauss) + (SINT32) d;

        for (i=2*n; i--;) {
            ci[i] -= z * gpv->b[j*2*n + i];
        }

        if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
            if (j == n) {
                sig = 0L;
                destroy_sampler(&gauss);
            }
        }
        else {
            destroy_sampler(&gauss);
        }
    }
    if (flags & GPV_GAUSSIAN_SAMPLE_EFFICIENT) {
        destroy_sampler(&gauss);
    }

    // Output final vector - only the latter half of "c - ci" is needed where
    // c is actually 0 for n to 2n-1
    for (j=0; j<n; j++) {
        v1[j] = ci[n+j];
    }
    if (v2) {
        for (j=0; j<n; j++) {
           v2[j] = ci[j];
        }
    }

    return SC_FUNC_SUCCESS;
}

#ifdef DEBUG_ENCRYPTION
static SINT32 gaussian_lattice_sample_debug(safecrypto_t *sc,
    const gpv_t *gpv, const GSO_TYPE *b_gs, const GSO_TYPE *b_gs_inv_norm,
    const SINT32 *c, SINT32 *v,
    UINT32 q, DOUBLE s_f, UINT32 flags)
{
    size_t i, j;
    size_t n = gpv->n;

    const SINT32 *w        = sc->dlp_ibe->params->w;
    const SINT32 *r        = sc->dlp_ibe->params->r;
    ntt_params_t *ntt      = &sc->dlp_ibe->ntt;
    const utils_arith_ntt_t *sc_ntt = sc->dlp_ibe->sc_ntt;
    const utils_arith_poly_t *sc_poly  = sc->dlp_ibe->sc_poly;

    // Verification - prove that ((s1 - t)*f + g*s2) = 0
    SINT32 *t = SC_MALLOC(sizeof(SINT32) * 4 * n);
    SINT32 *s1, *s2, *f, *g;
    SINT32 deg;
    s1 = t;
    s2 = t + n;
    f = t + 2 * n;
    g = t + 3 * n;
    for (j=0; j<n; j++) {
        s1[j] = (SINT32) ci[j];
        s2[j] = v[j];
        f[j] = -gpv->b[n+j];
        g[j] = gpv->b[j];
    }

    sc_poly->sub_single_32(s1, n, c);

    // Verification without NTT
    sc_poly_mpz_t pf, pg;
    sc_poly_mpz_t mp_f, mp_g, mp_h;
    sc_poly_mpz_t temp;
    sc_poly_mpz_init(&temp, 2*n);
    sc_poly_mpz_init(&pf, n);
    sc_poly_mpz_init(&pg, n);
    sc_poly_mpz_init(&mp_f, n);
    sc_poly_mpz_init(&mp_g, n);
    sc_poly_mpz_init(&mp_h, n);

    poly_si32_to_mpi(&mp_f, n, f);
    poly_si32_to_mpi(&mp_g, n, g);
    poly_si32_to_mpi(&mp_h, n, sc->pubkey->key);
    poly_si32_to_mpi(&pf, n, s1);
    poly_si32_to_mpi(&pg, n, s2);

    sc_mod_t mod;
    limb_mod_init(&mod, sc->dlp_ibe->params->q);

    sc_poly_mpz_mul(&temp, &pf, &mp_f);
    sc_poly_mpz_addmul(&temp, &pg, &mp_g);      // (s1 - c)*f + s2*g
    sc_poly_mpz_mod_ring(&temp, n, &temp);
    sc_poly_mpz_mod(&temp, &temp, &mod);
    SINT32 deg_mpi_1 = sc_poly_mpz_degree(&temp);

    sc_poly_mpz_mul(&temp, &pg, &mp_h);
    sc_poly_mpz_add(&temp, &temp, &pf);      // (s1 - c) + s2*h
    sc_poly_mpz_mod_ring(&temp, n, &temp);
    sc_poly_mpz_mod(&temp, &temp, &mod);
    SINT32 deg_mpi_2 = sc_poly_mpz_degree(&temp);

    // Verification with NTT - (s1 - c)*f + s2*g
    sc_ntt->fwd_ntt_32_32_large(s1, ntt, s1, w);
    sc_ntt->fwd_ntt_32_32_large(s2, ntt, s2, w);
    sc_ntt->fwd_ntt_32_32_large(f, ntt, f, w);
    sc_ntt->fwd_ntt_32_32_large(g, ntt, g, w);

    sc->dlp_ibe->sc_ntt->mul_32_pointwise(s1, ntt, s1, f); // NTT(s1 - c) * NTT(f)
    sc->dlp_ibe->sc_ntt->mul_32_pointwise(s2, ntt, s2, g); // NTT(s2) * NTT(g)
    sc_ntt->inv_ntt_32_32_large(s1, ntt, s1, w, r);
    sc_ntt->inv_ntt_32_32_large(s2, ntt, s2, w, r);
    sc_poly->add_32(f, n, s1, s2);
    sc_ntt->normalize_32(f, n, ntt);
    deg = poly_32_degree(f, n);
    //fprintf(stderr, "  c. (s1-t)*f + g*s2 = %d, deg = %d\n", s1[deg], deg);

    if (!(0 == deg && 0 == f[deg])) {
        fprintf(stderr, "Restarting sampling\n");
        SC_FREE(t, sizeof(SINT32) * 4 * n);

        sc_poly_mpz_clear(&temp);
        sc_poly_mpz_clear(&pf);
        sc_poly_mpz_clear(&pg);
        sc_poly_mpz_clear(&mp_f);
        sc_poly_mpz_clear(&mp_g);
        sc_poly_mpz_clear(&mp_h);

        goto restart;
    }

    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "(s1-c)*f + s2*g", s1, n);

    SC_FREE(t, sizeof(SINT32) * 4 * n);

    sc_poly_mpz_clear(&temp);
    sc_poly_mpz_clear(&pf);
    sc_poly_mpz_clear(&pg);
    sc_poly_mpz_clear(&mp_f);
    sc_poly_mpz_clear(&mp_g);
    sc_poly_mpz_clear(&mp_h);

    return SC_FUNC_SUCCESS;
}
#endif

