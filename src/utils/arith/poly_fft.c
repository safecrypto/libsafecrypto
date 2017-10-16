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

#include "poly_fft.h"
#include "poly_32.h"
#include "safecrypto_private.h"
#include <math.h>


static const DOUBLE pi = 3.1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081L;


SINT32 poly_dbl_degree(const DOUBLE *h, size_t n)
{
    SINT32 deg = -1;
    if (NULL != h && n > 0) {
        size_t j = n - 1;
        while (0 == h[j]) {
            if (0 == j) break;
            j--;
        }
        deg = j;
    }
    return deg;
}

SINT32 poly_flt_degree(const FLOAT *h, size_t n)
{
    SINT32 deg = -1;
    if (NULL != h && n > 0) {
        size_t j = n - 1;
        while (0 == h[j]) {
            if (0 == j) break;
            j--;
        }
        deg = j;
    }
    return deg;
}

SINT32 poly_long_dbl_degree(const LONGDOUBLE *h, size_t n)
{
    SINT32 deg = -1;
    if (NULL != h && n > 0) {
        size_t j = n - 1;
        while (0 == h[j]) {
            if (0 == j) break;
            j--;
        }
        deg = j;
    }
    return deg;
}

static SINT32 fft_step_int(sc_fft_t *ctx, sc_complex_t * const f_fft,
    SINT32 const * const f, const size_t n, const sc_complex_t w0)
{
    if (1 == n) {
        f_fft[0] = f[0];
    }
    else {
        if (2 == n) {
            f_fft[0] = f[0] + ctx->ii*f[1];
            f_fft[1] = f[0] - ctx->ii*f[1];
        }
        else {
            if (1 == (n&1)) {
                return SC_FUNC_FAILURE;
            }

            SINT32 f0[ctx->n/2], f1[ctx->n/2];
            sc_complex_t f0_fft[ctx->n/2], f1_fft[ctx->n/2], wk, w02;

            size_t k;
            for (k=0; k<(n/2); k++) {
                f0[k] = f[2*k];
                f1[k] = f[2*k+1];
            }

            w02 = w0 * w0;
            wk  = w0;
            fft_step_int(ctx, f0_fft, f0, n/2, w02);
            fft_step_int(ctx, f1_fft, f1, n/2, w02);
            for (k=0; k<n; k++) {
                f_fft[k] = f0_fft[k%(n/2)] + wk*f1_fft[k%(n/2)];
                wk *= w02;
            }
        }
    }

    return SC_FUNC_SUCCESS;
}

static SINT32 fft_step(sc_fft_t *ctx, sc_complex_t * const f_fft,
    LONGDOUBLE const * const f, const size_t n, const sc_complex_t w0)
{
    if (1 == n) {
        f_fft[0] = f[0];
    }
    else {
        if (2 == n) {
            f_fft[0] = f[0] + ctx->ii*f[1];
            f_fft[1] = f[0] - ctx->ii*f[1];
        }
        else {
            if (1 == (n&1)) {
                return SC_FUNC_FAILURE;
            }

            LONGDOUBLE f0[ctx->n/2], f1[ctx->n/2];
            sc_complex_t f0_fft[ctx->n/2], f1_fft[ctx->n/2], wk, w02;

            size_t k;
            for (k=0; k<(n/2); k++) {
                f0[k] = f[2*k];
                f1[k] = f[2*k+1];
            }

            w02 = w0 * w0;
            wk  = w0;
            fft_step(ctx, f0_fft, f0, n/2, w02);
            fft_step(ctx, f1_fft, f1, n/2, w02);
            for (k=0; k<n; k++) {
                f_fft[k] = f0_fft[k%(n/2)] + wk*f1_fft[k%(n/2)];
                wk *= w02;
            }
        }
    }

    return SC_FUNC_SUCCESS;
}

static SINT32 reverse_fft_step(sc_fft_t *ctx, sc_complex_t * const f,
    sc_complex_t const * const f_fft, const size_t n,
    const sc_complex_t w0)
{
    if (2 != n) {
        if (1 == (n&1)) {
            return SC_FUNC_FAILURE;
        }

        sc_complex_t f0[ctx->n/2], f1[ctx->n/2];
        sc_complex_t f0_fft[ctx->n/2], f1_fft[ctx->n/2], w02, wk;

        size_t k;

        w02 = w0*w0;
        wk = w0;

        for (k=0; k<n/2; k++) {
            f0_fft[k] = (f_fft[k] + f_fft[k+(n/2)])*0.5l;
            f1_fft[k] = wk*(f_fft[k] - f_fft[k+(n/2)])*0.5l;
            wk *= w02;
        }
        reverse_fft_step(ctx, f0, f0_fft, (n/2), w02);
        reverse_fft_step(ctx, f1, f1_fft, (n/2), w02);

        for (k=0; k<n/2; k++) {
            f[2*k] = f0[k];
            f[2*k+1] = f1[k];
        }
    }
    else {
        f[0] = (f_fft[0] + f_fft[1]) * 0.5l;
        f[1] = (f_fft[0] - f_fft[1]) * (-0.5l*ctx->ii);
    }

    return SC_FUNC_SUCCESS;
}

sc_fft_t * create_fft(size_t n)
{
    sc_fft_t *ctx = SC_MALLOC(sizeof(sc_fft_t));
    if (NULL == ctx) {
        return NULL;
    }

    // If n is 0 or odd we cannot continue
    if (0 == n || 1 == (n&1)) {
        return NULL;
    }

    ctx->ii = 0 + 1*I;
    ctx->omega = cexp(ctx->ii * (pi / n));
    ctx->omega_1 = cexp(-ctx->ii * (pi / n));
    ctx->n = n;

    return ctx;
}

SINT32 destroy_fft(sc_fft_t *ctx)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    SC_FREE(ctx, sizeof(sc_fft_t));
    return SC_FUNC_SUCCESS;
}

SINT32 fwd_fft_int(sc_fft_t *ctx, sc_complex_t * f_fft,
    const SINT32 * const f)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    if ((ctx->n-1) != poly_32_degree(f, ctx->n)) {
        return SC_FUNC_FAILURE;
    }

    return fft_step_int(ctx, (sc_complex_t * const)f_fft, f, ctx->n, ctx->omega);
}

SINT32 inv_fft_int(sc_fft_t *ctx, SINT32 * const f,
    sc_complex_t const * const f_fft)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    SINT32 retval;
    sc_complex_t fprime[ctx->n];
    size_t i;
    retval = reverse_fft_step(ctx, fprime, f_fft, ctx->n, ctx->omega_1);

    for (i=0; i<ctx->n; i++) {
        f[i] = (SINT32) round(creal(fprime[i]));
    }

    return retval;
}

SINT32 fwd_fft_flt(sc_fft_t *ctx, sc_complex_t * f_fft,
    const FLOAT * const f)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    LONGDOUBLE f_dbl[ctx->n];
    size_t i;

    if ((ctx->n-1) != poly_flt_degree(f, ctx->n)) {
        return SC_FUNC_FAILURE;
    }

    for (i=0; i<ctx->n; i++) {
        f_dbl[i] = (LONGDOUBLE) f[i];
    }

    return fft_step(ctx, (sc_complex_t * const)f_fft, f_dbl, ctx->n, ctx->omega);
}

SINT32 inv_fft_flt(sc_fft_t *ctx, FLOAT * const f,
    sc_complex_t const * const f_fft)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    SINT32 retval;
    sc_complex_t fprime[ctx->n];
    size_t i;
    retval = reverse_fft_step(ctx, fprime, f_fft, ctx->n, ctx->omega_1);

    for (i=0; i<ctx->n; i++) {
        f[i] = (FLOAT) creal(fprime[i]);
    }

    return retval;
}

SINT32 fwd_fft_dbl(sc_fft_t *ctx, sc_complex_t * f_fft,
    const DOUBLE * const f)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    LONGDOUBLE f_dbl[ctx->n];
    size_t i;

    if ((ctx->n-1) != poly_dbl_degree(f, ctx->n)) {
        return SC_FUNC_FAILURE;
    }

    for (i=0; i<ctx->n; i++) {
        f_dbl[i] = (LONGDOUBLE) f[i];
    }

    return fft_step(ctx, (sc_complex_t * const)f_fft, f_dbl, ctx->n, ctx->omega);
}

SINT32 inv_fft_dbl(sc_fft_t *ctx, DOUBLE * const f,
    sc_complex_t const * const f_fft)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    SINT32 retval;
    sc_complex_t fprime[ctx->n];
    size_t i;
    retval = reverse_fft_step(ctx, fprime, f_fft, ctx->n, ctx->omega_1);

    for (i=0; i<ctx->n; i++) {
        f[i] = (DOUBLE) creal(fprime[i]);
    }

    return retval;
}

SINT32 fwd_fft_long_dbl(sc_fft_t *ctx, sc_complex_t * f_fft,
    const LONGDOUBLE * const f)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    if ((ctx->n-1) != poly_long_dbl_degree(f, ctx->n)) {
        return SC_FUNC_FAILURE;
    }

    return fft_step(ctx, (sc_complex_t * const)f_fft, f, ctx->n, ctx->omega);
}

SINT32 inv_fft_long_dbl(sc_fft_t *ctx, LONGDOUBLE * const f,
    sc_complex_t const * const f_fft)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    SINT32 retval;
    sc_complex_t fprime[ctx->n];
    size_t i;

    retval = reverse_fft_step(ctx, fprime, f_fft, ctx->n, ctx->omega_1);

    for (i=0; i<ctx->n; i++) {
        f[i] = creal(fprime[i]);
    }

    return retval;
}
