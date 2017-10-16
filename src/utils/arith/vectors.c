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

#include "vectors.h"
#include "safecrypto_private.h"
#include "sc_math.h"
#include <math.h>


// Absolute maximinum of a vector
SINT32 vecabsmax_32(const SINT32 *v, size_t n)
{
    size_t i;
    SINT32 max;

    if (NULL == v) {
        return 0;
    }

    max = 0;
    for (i=0; i<n; i++) {
        if (v[i] > max)
            max = v[i];
        if (-v[i] > max)
            max = -v[i];
    }

    return max;
}

// Scalar product (or norm if t=u)
SINT32 vecscalar_32(const SINT32 *t, const SINT32 *u, size_t n)
{
    size_t i;
    SINT32 sum;

    if (NULL == t || NULL == u) {
        return 0;
    }

    sum = 0;
    for (i=0; i<n; i++)
        sum += t[i] * u[i];

    return sum;
}

// Absolute maximinum of a vector
SINT32 vecabsmax_16(const SINT16 *v, size_t n)
{
    size_t i;
    SINT32 max;

    if (NULL == v) {
        return 0;
    }

    max = 0;
    for (i=0; i<n; i++) {
        if (v[i] > max)
            max = v[i];
        if (-v[i] > max)
            max = -v[i];
    }

    return max;
}

// Scalar product (or norm if t=u)
SINT32 vecscalar_16(const SINT16 *t, const SINT16 *u, size_t n)
{
    size_t i;
    SINT32 sum;

    if (NULL == t || NULL == u) {
        return 0;
    }

    sum = 0;
    for (i=0; i<n; i++)
        sum += t[i] * u[i];

    return sum;
}

static DOUBLE svd_sign(DOUBLE a, DOUBLE b)
{
    return (b >= 0.0)? fabs(a) : -fabs(a);
}

static DOUBLE pythag(DOUBLE a, DOUBLE b)
{
    DOUBLE at = fabs(a), bt = fabs(b), ct, result;

    if (at > bt)       { ct = bt / at; result = at * sqrt(1.0 + ct * ct); }
    else if (bt > 0.0) { ct = at / bt; result = bt * sqrt(1.0 + ct * ct); }
    else result = 0.0;
    return(result);
}

SINT32 svd(FLOAT *a, size_t m, size_t n, FLOAT *w)
{
    int flag, i, its, j, jj, k, l = 0, nm;
    DOUBLE c, f, h, s, x, y, z;
    DOUBLE anorm = 0.0, g = 0.0, scale = 0.0;
    DOUBLE *rv1;
    FLOAT *v;

    if (m < n) {
        return SC_FUNC_FAILURE;
    }

    v   = SC_MALLOC(n * n * sizeof(FLOAT));
    rv1 = SC_MALLOC(n * sizeof(DOUBLE));

    // Householder reduction to bidiagonal form
    for (i = 0; i < n; i++) {
        // left-hand reduction
        l = i + 1;
        rv1[i] = scale * g;
        g = s = scale = 0.0;
        if (i < m) {
            for (k = i; k < m; k++)
                scale += fabs((DOUBLE)a[k*n+i]);
            if (scale) {
                for (k = i; k < m; k++) {
                    a[k*n+i] = (FLOAT)((DOUBLE)a[k*n+i]/scale);
                    s += ((DOUBLE)a[k*n+i] * (DOUBLE)a[k*n+i]);
                }
                f = (DOUBLE)a[i*n+i];
                g = -svd_sign(sqrt(s), f);
                h = f * g - s;
                a[i*n+i] = (FLOAT)(f - g);
                if (i != n - 1) {
                    for (j = l; j < n; j++) {
                        for (s = 0.0, k = i; k < m; k++) {
                            s += ((DOUBLE)a[k*n+i] * (DOUBLE)a[k*n+j]);
                        }
                        f = s / h;
                        for (k = i; k < m; k++) {
                            a[k*n+j] += (FLOAT)(f * (DOUBLE)a[k*n+i]);
                        }
                    }
                }
                for (k = i; k < m; k++) {
                    a[k*n+i] = (FLOAT)((DOUBLE)a[k*n+i]*scale);
                }
            }
        }
        w[i] = (FLOAT)(scale * g);

        // right-hand reduction
        g = s = scale = 0.0;
        if (i < m && i != n - 1) {
            for (k = l; k < n; k++) {
                scale += fabs((DOUBLE)a[i*n+k]);
            }
            if (scale) {
                for (k = l; k < n; k++) {
                    a[i*n+k] = (FLOAT)((DOUBLE)a[i*n+k]/scale);
                    s += ((DOUBLE)a[i*n+k] * (DOUBLE)a[i*n+k]);
                }
                f = (DOUBLE)a[i*n+l];
                g = -svd_sign(sqrt(s), f);
                h = f * g - s;
                a[i*n+l] = (FLOAT)(f - g);
                for (k = l; k < n; k++) {
                    rv1[k] = (DOUBLE)a[i*n+k] / h;
                }
                if (i != m - 1) {
                    for (j = l; j < m; j++) {
                        for (s = 0.0, k = l; k < n; k++) {
                            s += ((DOUBLE)a[j*n+k] * (DOUBLE)a[i*n+k]);
                        }
                        for (k = l; k < n; k++) {
                            a[j*n+k] += (FLOAT)(s * rv1[k]);
                        }
                    }
                }
                for (k = l; k < n; k++) {
                    a[i*n+k] = (FLOAT)((DOUBLE)a[i*n+k]*scale);
                }
            }
        }
        anorm = SC_MAX(anorm, (fabs((DOUBLE)w[i]) + fabs(rv1[i])));
    }

    // accumulate the right-hand transformation
    for (i = n - 1; i >= 0; i--) {
        if (i < n - 1) {
            if (g) {
                for (j = l; j < n; j++) {
                    v[j*n+i] = (FLOAT)(((DOUBLE)a[i*n+j] / (DOUBLE)a[i*n+l]) / g);
                }

                // double division to avoid underflow
                for (j = l; j < n; j++) {
                    for (s = 0.0, k = l; k < n; k++) {
                        s += ((DOUBLE)a[i*n+k] * (DOUBLE)v[k*n+j]);
                    }
                    for (k = l; k < n; k++) {
                        v[k*n+j] += (FLOAT)(s * (DOUBLE)v[k*n+i]);
                    }
                }
            }
            for (j = l; j < n; j++) {
                v[i*n+j] = v[j*n+i] = 0.0;
            }
        }
        v[i*n+i] = 1.0;
        g = rv1[i];
        l = i;
    }

    // accumulate the left-hand transformation
    for (i = n - 1; i >= 0; i--) {
        l = i + 1;
        g = (DOUBLE)w[i];
        if (i < n - 1) {
            for (j = l; j < n; j++)
                a[i*n+j] = 0.0;
        }
        if (g) {
            g = 1.0 / g;
            if (i != n - 1) {
                for (j = l; j < n; j++) {
                    for (s = 0.0, k = l; k < m; k++) {
                        s += ((DOUBLE)a[k*n+i] * (DOUBLE)a[k*n+j]);
                    }
                    f = (s / (DOUBLE)a[i*n+i]) * g;
                    for (k = i; k < m; k++) {
                        a[k*n+j] += (FLOAT)(f * (DOUBLE)a[k*n+i]);
                    }
                }
            }
            for (j = i; j < m; j++) {
                a[j*n+i] = (FLOAT)((DOUBLE)a[j*n+i]*g);
            }
        }
        else {
            for (j = i; j < m; j++) {
                a[j*n+i] = 0.0;
            }
        }
        ++a[i*n+i];
    }

    // diagonalize the bidiagonal form
    for (k = n - 1; k >= 0; k--) {
        // loop over singular values
        for (its = 0; its < 30; its++) {
            // loop over allowed iterations
            flag = 1;
            for (l = k; l >= 0; l--) {
                // test for splitting
                nm = l - 1;
                if (fabs(rv1[l]) + anorm == anorm) {
                    flag = 0;
                    break;
                }
                if (fabs((DOUBLE)w[nm]) + anorm == anorm) {
                    break;
                }
            }
            if (flag) {
                c = 0.0;
                s = 1.0;
                for (i = l; i <= k; i++) {
                    f = s * rv1[i];
                    if (fabs(f) + anorm != anorm) {
                        g = (DOUBLE)w[i];
                        h = pythag(f, g);
                        w[i] = (FLOAT)h;
                        h = 1.0 / h;
                        c = g * h;
                        s = (- f * h);
                        for (j = 0; j < m; j++) {
                            y = (DOUBLE)a[j*n+nm];
                            z = (DOUBLE)a[j*n+i];
                            a[j*n+nm] = (FLOAT)(y * c + z * s);
                            a[j*n+i] = (FLOAT)(z * c - y * s);
                        }
                    }
                }
            }
            z = (DOUBLE)w[k];
            if (l == k) {
                // convergence
                if (z < 0.0) {
                    // make singular value nonnegative
                    w[k] = (FLOAT)(-z);
                    for (j = 0; j < n; j++)
                        v[j*n+k] = (-v[j*n+k]);
                }
                break;
            }
            if (its >= 30) {
                SC_FREE(rv1, n * sizeof(DOUBLE));
                SC_FREE(v, n * n * sizeof(FLOAT));
                return SC_FUNC_FAILURE;
            }

            // shift from bottom 2 x 2 minor
            x = (DOUBLE)w[l];
            nm = k - 1;
            y = (DOUBLE)w[nm];
            g = rv1[nm];
            h = rv1[k];
            f = ((y - z) * (y + z) + (g - h) * (g + h)) / (2.0 * h * y);
            g = pythag(f, 1.0);
            f = ((x - z) * (x + z) + h * ((y / (f + svd_sign(g, f))) - h)) / x;

            // next QR transformation
            c = s = 1.0;
            for (j = l; j <= nm; j++) {
                i = j + 1;
                g = rv1[i];
                y = (DOUBLE)w[i];
                h = s * g;
                g = c * g;
                z = pythag(f, h);
                rv1[j] = z;
                c = f / z;
                s = h / z;
                f = x * c + g * s;
                g = g * c - x * s;
                h = y * s;
                y = y * c;
                for (jj = 0; jj < n; jj++) {
                    x = (DOUBLE)v[jj*n+j];
                    z = (DOUBLE)v[jj*n+i];
                    v[jj*n+j] = (FLOAT)(x * c + z * s);
                    v[jj*n+i] = (FLOAT)(z * c - x * s);
                }
                z = pythag(f, h);
                w[j] = (FLOAT)z;
                if (z) {
                    z = 1.0 / z;
                    c = f * z;
                    s = h * z;
                }
                f = (c * g) + (s * y);
                x = (c * y) - (s * g);
                for (jj = 0; jj < m; jj++) {
                    y = (DOUBLE)a[jj*n+j];
                    z = (DOUBLE)a[jj*n+i];
                    a[jj*n+j] = (FLOAT)(y * c + z * s);
                    a[jj*n+i] = (FLOAT)(z * c - y * s);
                }
            }
            rv1[l] = 0.0;
            rv1[k] = f;
            w[k] = (FLOAT)x;
        }
    }
    SC_FREE(rv1, n * sizeof(DOUBLE));
    SC_FREE(v, n * n * sizeof(FLOAT));
    return SC_FUNC_SUCCESS;
}

