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

#include "utils/arith/sc_poly_mpf.h"
#include "utils/crypto/prng.h"
#include "utils/arith/sc_math.h"
#include "utils/sampling/sampling.h"
#include "safecrypto_types.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"
#include "poly_fft.h"

#include <math.h>
#include <assert.h>


static const DOUBLE epsilon = 0.0001;

static SINT32 dbl_equal(DOUBLE a, DOUBLE b)
{
    DOUBLE thresh = (a == 0 || b == 0)? epsilon :
                                        fmax(fabs(a),fabs(b)) * epsilon;
    return fabs(a-b) < thresh;
}

static SINT32 mpf_dbl_equal(sc_mpf_t mpf_a, DOUBLE b)
{
    DOUBLE a = mpf_get_d(mpf_a.data);
    return dbl_equal(a, b);
}

static SINT32 equal(sc_mpf_t mpf_a, sc_mpf_t mpf_b)
{
    DOUBLE a = mpf_get_d(mpf_a.data);
    DOUBLE b = mpf_get_d(mpf_b.data);
    return dbl_equal(a, b);
}



void sc_poly_mpf_to_flt(FLOAT *out, size_t n, sc_mpf_t *in)
{
    size_t i;
    for (i=n; i--;) {
        out[i] = (FLOAT) mpf_get_d(in[i].data);
    }
}

void sc_poly_mpf_to_dbl(DOUBLE *out, size_t n, sc_mpf_t *in)
{
    size_t i;
    for (i=n; i--;) {
        out[i] = mpf_get_d(in[i].data);
    }
}

void poly_dbl_to_mpf(sc_mpf_t *out, size_t n, DOUBLE *in)
{
    size_t i;
    for (i=n; i--;) {
        mpf_set_d(out[i].data, in[i]);
    }
}

void sc_poly_mpf_init(sc_mpf_t *inout, size_t n)
{
    size_t i;
    for (i=n; i--;) {
        mpf_init(inout[i].data);
    }
}

void sc_poly_mpf_clear(sc_mpf_t *inout, size_t n)
{
    size_t i;
    for (i=n; i--;) {
        mpf_clear(inout[i].data);
    }
}

void sc_poly_mpf_copy(sc_mpf_t *out, size_t n, sc_mpf_t *in)
{
    size_t i;
    for (i=n; i--;) {
        mpf_set(out[i].data, in[i].data);
    }
}

void sc_poly_mpf_reset(sc_mpf_t *inout, size_t offset, size_t n)
{
    size_t i;
    for (i=offset; i<n; i++) {
        mpf_set_d(inout[i].data, 0.0);
    }
}

SINT32 sc_poly_mpf_set(sc_mpf_t *inout, size_t index, DOUBLE value)
{
    /// @todo Check for bad index here, using n built into sc_mpf_t
    mpf_set_d(inout[index].data, value);
    return SC_FUNC_SUCCESS;
}

void sc_poly_mpf_add_scalar(sc_mpf_t *poly, size_t n, sc_mpf_t in)
{
    if (n > 0) {
        mpf_t sum;
        mpf_init(sum);
        mpf_add (sum, poly[0].data, in.data);
        mpf_set(poly[0].data, sum);
        mpf_clear(sum);
    }
}

void sc_poly_mpf_sub_scalar(sc_mpf_t *poly, size_t n, sc_mpf_t in)
{
    if (n > 0) {
        mpf_t sum;
        mpf_init(sum);
        mpf_sub (sum, poly[0].data, in.data);
        mpf_set(poly[0].data, sum);
        mpf_clear(sum);
    }
}

void sc_poly_mpf_mul_scalar(sc_mpf_t *poly, size_t n, sc_mpf_t in)
{
    size_t i;
    mpf_t product;
    mpf_init(product);
    for (i=n; i--;) {
        mpf_mul(product, poly[i].data, in.data);
        mpf_set(poly[0].data, product);
    }
    mpf_clear(product);
}

void sc_poly_mpf_add(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2)
{
    size_t i;
    for (i=n; i--;) {
        mpf_add(out[i].data, in1[i].data, in2[i].data);
    }
}

void sc_poly_mpf_sub(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2)
{
    size_t i;
    for (i=n; i--;) {
        mpf_sub(out[i].data, in1[i].data, in2[i].data);
    }
}

void sc_poly_mpf_add_single(sc_mpf_t *out, size_t n, sc_mpf_t *in)
{
    size_t i;
    mpf_t sum;
    mpf_init(sum);
    for (i=n; i--;) {
        mpf_add(sum, out[i].data, in[i].data);
        mpf_set(out[i].data, sum);
    }
    mpf_clear(sum);
}

void sc_poly_mpf_sub_single(sc_mpf_t *out, size_t n, sc_mpf_t *in)
{
    size_t i;
    mpf_t sum;
    mpf_init(sum);
    for (i=n; i--;) {
        mpf_sub(sum, out[i].data, in[i].data);
        mpf_set(out[i].data, sum);
    }
    mpf_clear(sum);
}

void sc_poly_mpf_mul(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2)
{
    size_t i, j;
    mpf_t product;
    mpf_init(product);
    mpf_t sum;
    mpf_init(sum);

    // Clear the output polynomial
    sc_poly_mpf_reset(out, 0, 2*n);

    // Multiply-accumulate over a window
    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            mpf_mul(product, in1[i].data, in2[j].data);
            mpf_add(sum, out[i+j].data, product);
            mpf_set(out[i+j].data, sum);
        }
    }

    mpf_clear(product);
    mpf_clear(sum);
}

void sc_poly_mpf_mul_mod(sc_mpf_t *out, size_t n, sc_mpf_t *in1, sc_mpf_t *in2)
{
    size_t i;
    sc_mpf_t prod[2*n+2], polymod[n+1], dummy[n+1];
    for (i=2*n+2; i--;) {
        mpf_init(prod[i].data);
    }
    for (i=n+1; i--;) {
        mpf_init(polymod[i].data);
        mpf_init(dummy[i].data);
    }

    mpf_set_d(polymod[0].data, 1.0);
    mpf_set_d(polymod[n].data, 1.0);

    sc_poly_mpf_mul(prod, n, in1, in2);
    sc_poly_mpf_div(prod, polymod, n+1, dummy, out);

    for (i=2*n+2; i--;) {
        mpf_clear(prod[i].data);
    }
    for (i=n+1; i--;) {
        mpf_clear(polymod[i].data);
        mpf_clear(dummy[i].data);
    }
}

void sc_poly_mpf_uniform_rand(prng_ctx_t *ctx, sc_mpf_t *v, size_t n, const UINT16 *c, size_t c_len)
{
    size_t i, j;
    UINT32 mask = n - 1;

    // Reset the output polynomial to all zeros
    for (i=n; i--;) {
        mpf_set_d(v[i].data, 0.0);
    }

    // Given the list of coefficient occurences c (in descending order of value),
    // randomly place the correct number of signed coefficient within the
    // polynomial of dimension n.
    for (j=0; j<c_len; j++) {
        i = 0;
        while (i < c[j]) {
            UINT32 rand = prng_32(ctx);
            size_t index = (rand >> 1) & mask;
            if (0 == mpf_cmp_d(v[index].data, 0.0)) {
                mpf_set_d(v[index].data, (DOUBLE)((rand & 1)? j-c_len : c_len-j));
                i++;
            }
        }
    }
}

sc_mpf_t sc_poly_mpf_dot_product(sc_mpf_t *x, size_t n)
{
    sc_mpf_t dot;
    mpf_init(dot.data);

    if (NULL == x) {
        mpf_set_si(dot.data, -1);
        return dot;
    }

    mpf_t product, sum;
    mpf_init(product);
    mpf_init(sum);
    for(size_t k=0; k<n; k++)
    {
        mpf_mul(product, x[k].data, x[k].data);
        mpf_add(sum, dot.data, product);
        mpf_set(dot.data, sum);
    }
    mpf_clear(product);
    mpf_clear(sum);
    return (dot);
}

sc_mpf_t sc_poly_mpf_modulus(sc_mpf_t *x, size_t n)
{
    sc_mpf_t mod;
    mpf_init(mod.data);

    if (NULL == x) {
        mpf_set_si(mod.data, -1);
        return mod;
    }

    mpf_sqrt(mod.data, sc_poly_mpf_dot_product(x, n).data);
    return mod;
}

SINT32 sc_poly_mpf_degree(sc_mpf_t *h, size_t n)
{
    SINT32 deg = -1;
    if (NULL != h && n > 0) {
        size_t j = n - 1;
        while (0 == mpf_cmp_d(h[j].data, 0.0)) {
            if (0 == j) break;
            j--;
        }
        deg = j;
    }
    return deg;
}

SINT32 sc_poly_mpf_div(sc_mpf_t *num, sc_mpf_t *den, size_t n, sc_mpf_t *q, sc_mpf_t *r)
{
    SINT32 j, k;
    SINT32 deg_num, deg_den;

    deg_num = sc_poly_mpf_degree(num, n);
    if (deg_num < 0) {
        return SC_FUNC_FAILURE;
    }

    deg_den = sc_poly_mpf_degree(den, n);
    if (deg_den < 0) {
        return SC_FUNC_FAILURE;
    }

    // r = num, q = 0
    sc_poly_mpf_copy(r, n, num);
    sc_poly_mpf_reset(q, 0, n);

    if (deg_num < deg_den) {
        return SC_FUNC_SUCCESS;
    }

    mpf_t product, sum, one, inv;
    mpf_init(product);
    mpf_init(sum);
    mpf_init(one);
    mpf_init(inv);
    mpf_set_si(one, 1);
    mpf_div(inv, one, den[deg_den].data);

    for (k=deg_num-deg_den; k>=0; k--) {
        //mpf_div(q[k].data, r[deg_den+k].data, den[deg_den].data);
        mpf_mul(q[k].data, r[deg_den+k].data, inv);
        for (j=deg_den+k-1; j>=k; j--) {
            mpf_mul(product, q[k].data, den[j-k].data);
            mpf_sub(sum, r[j].data, product);
            mpf_set(r[j].data, sum);
        }
    }
    sc_poly_mpf_reset(r, deg_den, n);

    sc_mpf_t t[2*n]; // 2n in length
    sc_mpf_t s[2*n]; // 2n in length
    size_t i;
    for (i=2*n; i--;) {
        mpf_init(t[i].data);
        mpf_init(s[i].data);
    }
    sc_poly_mpf_mul(t, n, q, den);
    sc_poly_mpf_add(s, n, t, r);
    for (i=0; i<n; i++) {
        assert(1 == equal(num[i], s[i]));
    }

    mpf_clear(product);
    mpf_clear(sum);
    mpf_clear(one);
    mpf_clear(inv);

    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpf_gcd(sc_mpf_t *a, sc_mpf_t *b, sc_mpf_t *gcd, sc_mpf_t *temp, size_t n)
{
    size_t i;
    mpf_t copy, zero;
    sc_mpf_t *quo = temp;
    sc_mpf_t *r0  = temp + 1 * n;
    sc_mpf_t *r1  = temp + 2 * n;
    sc_mpf_t *r2  = temp + 3 * n;

    // Swap a and b if b > a
    mpf_init(copy);
    mpf_init(zero);
    UINT32 flag = 0;
    for (i=n; i--;) {
        if (mpf_cmp(b[i].data, a[i].data) > 0) {
            flag = 1;
            break;
        }
        else if (mpf_cmp_d(a[i].data, 0.0) != 0) {
            break;
        }
    }

    if (1 == flag) {
        sc_poly_mpf_copy(r1, n, a);
        sc_poly_mpf_copy(r0, n, b);
    }
    else {
        sc_poly_mpf_copy(r0, n, a);
        sc_poly_mpf_copy(r1, n, b);
    }

#if 0

#else
    // Iteratively update the variables while b is non-zero
    size_t iter = 0;
    while (1) {
        iter++;
        // Verify that b is non-zero
        SINT32 deg_b = sc_poly_mpf_degree(r1, n);
        if (0 == deg_b && 0 == mpf_cmp(r1[0].data, zero)) {
            goto finish;
        }

        if (SC_FUNC_FAILURE == sc_poly_mpf_div(r0, r1, n, quo, r2)) {
            return SC_FUNC_FAILURE;
        }

        sc_poly_mpf_copy(r0, n, r1);
        sc_poly_mpf_copy(r1, n, r2);
    }
#endif

finish:
    mpf_set(gcd->data, r0[0].data);
    mpf_clear(zero);
    mpf_clear(copy);
    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpf_gcd_single(sc_mpf_t a, sc_mpf_t b, sc_mpf_t *gcd)
{
    mpf_t A, B, s, sum, product, zero;
    mpf_init(A);
    mpf_init(B);
    mpf_init(s);
    mpf_init(sum);
    mpf_init(product);
    mpf_init(zero);

    // Swap a and b if b > a
    if (mpf_cmp(b.data, a.data) > 0) {
        mpf_set(A, b.data);
        mpf_set(B, a.data);
    }
    else {
        mpf_set(A, a.data);
        mpf_set(B, b.data);
    }

    // Iteratively update the variables while b is non-zero
    while (1) {
        // Verify that b is non-zero
        if (0 == mpf_cmp(B, zero)) {
            goto finish;
        }

        mpf_div(sum, A, B);
        mpf_floor(s, sum);
        mpf_mul(product, B, s);
        mpf_sub(s, A, product);

        mpf_set(A, B);
        mpf_set(B, s);
    }

finish:
    mpf_set(gcd->data, A);
    mpf_clear(A);
    mpf_clear(B);
    mpf_clear(s);
    mpf_clear(sum);
    mpf_clear(product);
    mpf_clear(zero);
    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpf_ext_euclidean(sc_mpf_t *a, sc_mpf_t *b, sc_mpf_t *gcd,
    sc_mpf_t *x, sc_mpf_t *y, sc_mpf_t *temp, size_t n)
{
    size_t i;
    mpf_t copy;
    sc_mpf_t *old_x = temp;
    sc_mpf_t *old_y = temp + 1 * n;
    sc_mpf_t *quo   = temp + 2 * n;
    sc_mpf_t *A     = temp + 3 * n;
    sc_mpf_t *B     = temp + 4 * n;
    sc_mpf_t *s     = temp + 5 * n;
    sc_mpf_t *t     = temp + 6 * n; // 2n in length

    // Swap a and b if b > a
    mpf_init(copy);
    UINT32 flag = 0;
    for (i=n; i--;) {
        if (mpf_cmp(b[i].data, a[i].data) > 0) {
            flag = 1;
            break;
        }
        else if (mpf_cmp_d(a[i].data, 0.0) != 0) {
            break;
        }
    }

    if (1 == flag) {
        sc_poly_mpf_copy(B, n, a);
        sc_poly_mpf_copy(A, n, b);
    }
    else {
        sc_poly_mpf_copy(A, n, a);
        sc_poly_mpf_copy(B, n, b);
    }

    // Initialise the intermediate results
    sc_poly_mpf_reset(x, 0, n);
    sc_poly_mpf_reset(y, 1, n);
    sc_poly_mpf_reset(old_x, 1, n);
    sc_poly_mpf_reset(old_y, 0, n);
    mpf_set_d(y[0].data, 1.0);
    mpf_set_d(old_x[0].data, 1.0);

    // Iteratively update the variables while b is non-zero
    size_t iter = 0;
    while (1) {
        iter++;
        // Verify that b is non-zero
        SINT32 deg_b = sc_poly_mpf_degree(B, n);
        if (0 == deg_b && 0 == mpf_cmp_d(B[0].data, 0.0)) {
            goto finish;
        }

        if (SC_FUNC_FAILURE == sc_poly_mpf_div(A, B, n, quo, s)) {
            return SC_FUNC_FAILURE;
        }
        sc_poly_mpf_copy(A, n, B);
        sc_poly_mpf_copy(B, n, s);

    /*fprintf(stderr, "iter = %lu, quo:\n", iter);
    for (i=0; i<3; i++) {
        fprintf(stderr, "%8.3f\n", mpf_get_d(quo[i].data));
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "rem:\n");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%8.3f\n", mpf_get_d(s[i].data));
    }
    fprintf(stderr, "\n");*/

        // Update x
        sc_poly_mpf_copy(s, n, x);
        sc_poly_mpf_mul(t, n, quo, x);
        sc_poly_mpf_sub(x, n, old_x, t);
        sc_poly_mpf_copy(old_x, n, s);

        // Update y
        sc_poly_mpf_copy(s, n, y);
        sc_poly_mpf_mul(t, n, quo, y);
        sc_poly_mpf_sub(y, n, old_y, t);
        sc_poly_mpf_copy(old_y, n, s);
    }

finish:
    if (flag) {
        sc_poly_mpf_copy(x, n, old_y);
        sc_poly_mpf_copy(y, n, old_x);
    }
    else {
        sc_poly_mpf_copy(x, n, old_x);
        sc_poly_mpf_copy(y, n, old_y);
    }

    mpf_set(gcd->data, A[0].data);

    sc_mpf_t t2[2*n]; // 2n in length
    for (i=2*n; i--;) {
        mpf_init(t2[i].data);
    }
    sc_poly_mpf_mul(t, n, A, x);
    sc_poly_mpf_mul(t2, n, B, y);
    sc_poly_mpf_add(s, n, t, t2);
    fprintf(stderr, "s:\n");
    for (i=0; i<n; i++) {
        fprintf(stderr, "%8.0f\n", mpf_get_d(s[i].data));
        if (7 == (i&7)) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    mpf_clear(copy);
    for (i=2*n; i--;) {
        mpf_clear(t2[i].data);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 sc_poly_mpf_ext_euclidean_single(sc_mpf_t a, sc_mpf_t b, sc_mpf_t *gcd,
    sc_mpf_t *x, sc_mpf_t *y)
{
    mpf_t old_x, old_y, quo, s, t, sum, A, B;
    mpf_init(old_x);
    mpf_init(old_y);
    mpf_init(quo);
    mpf_init(s);
    mpf_init(t);
    mpf_init(sum);
    mpf_init(A);
    mpf_init(B);

    mpf_set(A, a.data);
    mpf_set(B, b.data);

    // Swap a and b if b > a
    UINT32 flag = 0;
    if (mpf_cmp(B, A) > 0) {
        flag = 1;
        mpf_set(s, A);
        mpf_set(A, B);
        mpf_set(B, s);
    }

    // Initialise the intermediate results
    mpf_set_d(x->data, 0.0);
    mpf_set_d(old_y, 0.0);
    mpf_set_d(y->data, 1.0);
    mpf_set_d(old_x, 1.0);

    // Iteratively update the variables while b is non-zero
    while (1) {
        // Verify that b is non-zero
        if (0 == mpf_cmp_si(B, 0)) {
            goto finish;
        }

        mpf_div(sum, A, B);
        mpf_floor(quo, sum);
        mpf_mul(t, B, quo);
        mpf_sub(s, A, t);

        mpf_set(A, B);
        mpf_set(B, s);

        // Update x
        mpf_set(s, x->data);
        mpf_mul(t, quo, x->data);
        mpf_sub(x->data, old_x, t);
        mpf_set(old_x, s);

        // Update y
        mpf_set(s, y->data);
        mpf_mul(t, quo, y->data);
        mpf_sub(y->data, old_y, t);
        mpf_set(old_y, s);
    }

finish:
    if (flag) {
        mpf_set(x->data, old_y);
        mpf_set(y->data, old_x);
    }
    else {
        mpf_set(x->data, old_x);
        mpf_set(y->data, old_y);
    }

    mpf_set(gcd->data, A);
    mpf_clear(old_x);
    mpf_clear(old_y);
    mpf_clear(quo);
    mpf_clear(s);
    mpf_clear(t);
    mpf_clear(sum);
    mpf_clear(A);
    mpf_clear(B);
    return SC_FUNC_SUCCESS;
}

DOUBLE sc_poly_mpf_gram_schmidt_norm(DOUBLE *f, DOUBLE *g, size_t n,
    DOUBLE q, DOUBLE bd)
{
    DOUBLE x[2*n];  //2N entries. this is the catenation of g,-f


    // FIRST NORM
    // Don't bother creating the arrays with the correct signs,
    // the values are being squared so directly multiply-accumulate
    // the input f, g
    DOUBLE modx = 0;
    for (size_t i=n; i--;) {
        modx += f[i] * f[i] + g[i] * g[i];
    }
    modx = sqrt(modx);
    fprintf(stderr, "||(g, -f)|| = %3.3f\n", modx);

    // Early termination - if ||(g,-f)|| cannot satisfy the condition
    // threshold then there's no point continuing, output the bad
    // Gram Schmidt norm and try again.
    if (modx > bd) {
        return modx;
    }

    // SECOND NORM

    sc_fft_t *ctx_fft = create_fft(n);
    sc_complex_t f_fft[n], g_fft[n];
    sc_complex_t F[n], G[n];
    DOUBLE f2[n], g2[n];
    fwd_fft_dbl(ctx_fft, f_fft, f);
    fwd_fft_dbl(ctx_fft, g_fft, g);

    size_t i;
    for(i=0; i<n; i++) {
        F[i] = f_fft[i]/(f_fft[i]*f_fft[n-1-i]+g_fft[i]*g_fft[n-1-i]);
        G[i] = g_fft[i]/(f_fft[i]*f_fft[n-1-i]+g_fft[i]*g_fft[n-1-i]);
    }

    inv_fft_dbl(ctx_fft, f2, F);
    inv_fft_dbl(ctx_fft, g2, G);
    destroy_fft(ctx_fft);

    DOUBLE b_N1 = 0;
    for(i=0; i<n; i++)
    {
        b_N1 += f2[i] * f2[i] + g2[i] * g2[i];
    }
    b_N1 = q * sqrt(b_N1);

    fprintf(stderr, "||(qfb/(ggb + ffb), qgb/(ggb + ffb))|| = %3.3f\n", b_N1);
    if (modx > b_N1) {
        return modx;
    }
    else {
        return b_N1;
    }
}

DOUBLE test_f[512] = {
    683,   -383,   1636,   -444,   2202,     98,   -505,    984,  -1296,   2495,     68,   -526,   1041,   -572,  -1291,    468,
  -1182,   -211,  -1157,    402,    221,   -688,    626,    776,   2155,   1075,    203,  -1121,   1953,  -1183,   1538,    971,
    856,   -889,   -329,  -1592,    -73,   1524,   2311,   -856,   -207,   -634,   1285,   2091,   1714,   1926,   1205,    715,
   1054,  -1067,    470,  -1465,  -1207,   1506,  -1095,    945,    346,   2593,   -309,    538,    413,   -146,   -561,  -1612,
   -835,      0,    453,   -719,   1932,  -1910,     10,    272,   -669,    682,   1163,  -1233,   -947,   -173,   -747,    104,
   -836,   1854,   1205,    341,     96,   -586,  -1108,    730,   -908,    758,   -810,    460,   1210,   -300,      0,   1105,
   -918,   2339,  -2084,  -1269,    553,    -47,    882,   -159,   1230,   -505,    -40,    806,    342,  -2869,   -635,   1570,
    540,   -682,   -800,   -494,    619,    699,    747,   1325,   -139,    373,   -388,  -1126,    310,   -550,  -1316,   -470,
    -87,  -1295,   1823,   -367,   -457,   -264,   1253,   1537,   -500,   1863,   -134,   -590,  -1097,   -647,  -1399,    401,
   1196,    948,  -1137,    603,   2718,   -126,   -861,     18,   -340,   -217,   -723,    485,   1357,    263,   -215,  -2076,
     34,   -248,   -442,  -1402,    533,   -631,  -1875,  -2186,     49,   -891,    224,    662,  -1450,   -406,  -1063,   1128,
  -2159,   -789,  -1136,    -73,  -1601,    761,  -1631,   1935,  -2104,    159,   -665,   -838,  -1399,     34,  -1270,   -454,
    322,    465,   -294,   1170,  -1169,   1437,    639,    155,     -9,    473,   2533,    272,    -12,   -187,   -748,   1301,
  -1168,    342,   -456,  -3192,   -982,   -105,   2316,   -326,  -2073,    191,    203,   -592,   -975,    258,    711,   -403,
    474,     70,    304,   -332,   -253,   -453,   1223,    719,   -999,    998,   -983,  -2203,   1262,   -491,    692,    416,
   1028,   1131,   -213,    443,    121,    608,    -53,  -1813,   -952,     99,   1418,    354,   1645,    284,    -88,    818,
   -869,   1210,  -2104,   1142,    233,  -1475,   2662,   1711,    962,    607,   -778,    291,   -873,   -502,   2418,  -1971,
   -637,    542,   -762,  -1797,   -869,  -2041,  -2532,   2097,  -1089,   1733,  -1171,   -565,    -56,  -2339,   -938,  -1203,
   -152,     30,    867,   1078,   -850,    574,  -1509,  -1068,    240,   -147,   1162,   -443,  -1443,  -1730,  -1581,   -177,
    329,     50,   1183,    247,   -788,    315,   -855,    225,    760,    504,   2292,    651,  -1359,   1105,   1143,  -1188,
  -1431,   -923,   -947,   1649,   -694,   2610,    781,   -756,   -428,   -993,    308,  -1185,  -2657,   -664,   -157,   -290,
    341,    557,   -587,   1509,   -341,     82,  -1001,   1203,    565,   1208,    -55,   -393,   2541,  -1843,  -1157,  -1536,
    -54,   1361,   2549,   1933,    -61,  -1844,    972,   -869,   -332,  -1524,   1344,    170,  -1890,    818,   1013,  -3265,
   2363,  -1992,     84,   -408,   1644,   1624,   1020,   -857,  -1513,     98,   -532,   -255,   -138,   1555,   1541,   -567,
     52,   -230,  -3595,   -727,   -357,   -641,    624,  -1916,   1647,   -667,  -1230,  -1516,   -512,    699,  -2029,  -2126,
    678,  -1230,   -839,    114,    906,   1442,   -437,    -23,   -712,  -1094,  -2883,    -70,   -535,   1923,   -714,   -586,
  -2011,   -223,  -2815,    689,    591,     91,     79,    213,    501,   1888,    610,   -879,    325,  -1281,    -35,  -1424,
   -192,   1644,   -584,    343,   2250,   -330,   1281,  -1409,    854,   -470,   3246,   -586,   1520,   -240,    696,    534,
   1514,     30,  -1390,   -677,    576,  -2520,  -1265,   -986,   -121,  -1392,    300,    645,     85,   -228,   -956,   2115,
  -1591,     55,    726,  -1929,  -1939,   -699,  -2062,    901,    254,   1044,    405,  -2558,    855,   -629,  -2614,   -163,
    477,   1794,    251,  -1240,   -214,    296,    750,    665,    683,   1617,   -468,   -148,  -1514,    428,     34,   1037,
    351,   1157,   -895,   1716,   1260,     56,    293,    110,   -332,   -457,     73,  -1079,    489,    400,  -2248,    303
};
DOUBLE test_g[512] = {
     50,  -1764,   -937,   -409,    123,  -1547,    260,    532,  -1633,   -548,    594,    553,   -360,   2805,    770,    543,
   -344,   2507,     28,     68,   -874,    308,  -2794,    657,   -228,  -2010,     12,   -925,    862,    142,  -1520,   2279,
    213,     91,   2954,   -208,    715,   -724,  -1377,    679,   1065,   1241,   1305,     19,   -188,   1250,  -1069,  -2162,
   1641,   1310,   1217,   1097,   -633,    887,   -993,   -448,   1108,     73,  -2070,   2990,    483,  -1197,   -809,   1178,
   -382,   -573,   -474,  -1848,  -1610,   1055,   -847,   1297,    367,    740,    485,     20,  -1266,   -295,    407,  -1631,
    601,   1559,    606,  -1763,   -159,  -1220,   -593,   -646,   -343,  -2168,  -2546,   -495,   -812,    476,   1198,   -883,
    113,  -2097,     50,  -2213,   -466,   -701,  -1631,   1780,  -1743,  -1137,     91,  -1209,    751,   1091,    333,   2182,
   -725,   -740,   -683,    962,    828,   -723,   -774,    458,    800,   -341,  -1402,   -824,    181,   -344,    794,    957,
  -2518,   2445,   -376,   1418,   1472,   -467,   1007,   1322,   -194,  -1313,    775,    250,   -132,   1862,   2565,    102,
    479,   -228,   -106,    517,    187,    661,   -798,  -1563,   -571,    134,    910,     63,   -397,   -146,   -711,   1021,
  -2002,    695,   -854,   1030,    404,   -235,  -1160,   1148,   1090,    384,    466,    135,   1201,     99,   1597,    568,
    -82,  -1707,   -461,   1455,   -878,    988,   -162,   1149,  -2626,    232,    497,   -528,   -153,  -1421,    239,    435,
   2234,     56,  -2026,  -2090,   -596,   2136,    552,    535,   -766,    266,   2299,  -1007,    509,  -2171,    893,  -1879,
    737,    924,    618,    -94,   1143,   -155,    994,    -64,   -232,  -1405,  -1185,    464,  -1473,    391,    400,   2125,
    782,    314,  -1153,   1063,   1420,    842,   -665,    469,   -619,  -1362,   2316,   -591,   -709,    895,    830,    416,
   1335,  -2697,   -785,   -995,   -857,   1341,    -38,  -1989,    521,  -2000,   1326,    -86,   -981,    623,   2080,   1075,
   1607,   -379,  -1030,   -816,    250,    240,  -2755,     36,  -1824,   1052,    483,   -309,     15,    825,  -2252,   1208,
   -339,      5,   1534,    356,  -2533,     90,   -591,  -1202,   -291,   1189,  -1360,    813,  -1176,    996,  -2027,   -182,
    576,  -1485,   -613,  -1093,  -1147,  -1093,   -554,    666,    510,   -819,    394,   -143,    685,  -1106,   1623,   -511,
   -358,  -1072,   2797,    249,   -272,    679,    381,  -1409,    -67,   -634,  -3065,  -2340,  -1438,   -414,   -413,   1307,
    -22,     45,    -95,   -227,  -1802,   1878,    319,   -539,  -1096,  -2703,   1352,     96,   -743,     31,    -11,   -574,
     83,   1190,   2098,    427,    387,    703,   1000,  -1345,   -521,   1993,   1443,  -2834,   2261,  -1268,   -365,   -862,
    638,   -322,   -208,    613,  -1011,    -87,  -1387,   -599,   -942,   -646,   -187,    809,   2729,   1648,  -1715,    812,
  -1250,  -1391,   -343,   -930,    910,   -564,   -184,    562,    924,    324,    741,  -1439,   1530,  -1594,   -225,   -817,
   1586,     17,     76,    468,  -1303,  -1179,   1070,   -129,    437,   -401,   1061,   -107,  -1237,    333,    151,   1380,
  -2393,    629,    108,   -255,   -121,    -12,    -69,   2034,   1877,  -1782,    700,   1517,  -1545,   -370,   1381,    425,
  -1275,  -1370,    -48,   1263,   -344,   -245,  -1467,   -118,     -9,   1442,  -1677,    429,  -1796,  -2122,  -1277,   -285,
    924,   1306,   -684,    539,   -962,    619,    330,   2195,   -515,  -1048,   -477,   2720,    750,   1113,  -1494,    130,
   -294,    219,   1204,   1927,    955,    587,  -1087,    930,  -1052,    487,   1805,   1064,    653,      0,    745,    534,
  -1755,   -532,    778,   1665,   -475,    808,  -2263,  -1091,   -656,   -900,    183,    559,    324,   -729,   1081,    103,
    -37,   -982,    685,  -1705,    -33,  -1058,   2990,    652,  -2603,  -1282,   2977,    -97,  -1006,    205,   1425,    144,
   -579,    516,    459,    -61,   -993,   -991,   -177,   -635,   -815,   -901,   -623,    169,   1407,   -891,    333,   1961
};
SINT32 sc_poly_mpf_gen_basis(safecrypto_t *sc, DOUBLE *f, DOUBLE *g, DOUBLE *h,
    size_t n, DOUBLE q,
    utils_sampling_t *sampling, prng_ctx_t *prng_ctx,
    DOUBLE *F, DOUBLE *G, DOUBLE *sq_norm)
{
    DOUBLE sigma;
    void *sampler;
    DOUBLE gs_norm;
    sc_mpf_t Rf, Rg, gcd1, gcd2;
    sc_mpf_t rho_f[2*n+2], rho_g[2*n+2], rho_dummy[2*n+2], temp[16*(n+1)];
    sc_mpf_t u, v, mp_q;
    sc_mpf_t mp_f[n], mp_g[n];

    sc_poly_mpf_init(&Rf, 1);
    sc_poly_mpf_init(&Rg, 1);
    sc_poly_mpf_init(&gcd1, 1);
    sc_poly_mpf_init(&gcd2, 1);
    sc_poly_mpf_init(rho_f, 2*n+2);
    sc_poly_mpf_init(rho_g, 2*n+2);
    sc_poly_mpf_init(rho_dummy, 2*n+2);
    sc_poly_mpf_init(temp, (16*(n+1)));
    sc_poly_mpf_init(&u, 1);
    sc_poly_mpf_init(&v, 1);
    sc_poly_mpf_init(mp_f, n+1);
    sc_poly_mpf_init(mp_g, n+1);
    sc_poly_mpf_init(&mp_q, 1);

    // Computations are done mod x^N+1-----this defines this polynomial
    sc_mpf_t polymod[2*n+2];
    sc_poly_mpf_init(polymod, 2*n+2);
    sc_poly_mpf_set(polymod, 0, 1);
    sc_poly_mpf_set(polymod, n, 1);

    // Step 1. set standard deviation of Gaussian distribution
    DOUBLE s_f, bd;
    s_f = 1.17*sqrt(q / (2*n));
    bd  = 1.17*sqrt(q);

    // Step 2. Obtain f, g using Gaussian Samplers
    sigma  = sqrt((1.36 * q / 2) / n);//sqrt(s_f / n);
    sampler = sampling->create(prng_ctx, 13, sigma, NORMAL_SAMPLES);
    fprintf(stderr, "n=%lu, q=%3.3f\n", n, q);
    fprintf(stderr, "s_f=%3.3f, sigma=%3.3f\n", s_f, sigma);
step2:
#if 1
    SC_MEMCOPY(f, test_f, sizeof(DOUBLE) * n);
    SC_MEMCOPY(g, test_g, sizeof(DOUBLE) * n);
#else
    sampling->vector_dbl(prng_ctx, sampling, sampler, f, n);
    sampling->vector_dbl(prng_ctx, sampling, sampler, g, n);
#endif

    // Step 3. calculate the GramSchmidt norm
    gs_norm = sc_poly_mpf_gram_schmidt_norm(f, g, n, q, bd);

    // Step 4. check whether norm is small enough; if not, repeat
    fprintf(stderr, "GS=%3.3f, threshold=%3.3f\n", gs_norm, bd);
    /*if (gs_norm > bd) {
        goto step2;
    }*/

    poly_dbl_to_mpf(mp_f, n, f);
    poly_dbl_to_mpf(mp_g, n, g);
    sc_poly_mpf_set(&mp_q, 0, q);

    // Step 5, 6, 7. Polynomial Euclidean to find 4 unknowns
    sc_poly_mpf_reset(rho_f, 0, 2*n+2);
    sc_poly_mpf_ext_euclidean(mp_f, polymod, &Rf, rho_f, rho_dummy, temp, n+1);
    //sc_poly_mpf_gcd(mp_f, polymod, &Rf, temp, n+1);
    fprintf(stderr, "Rf = ");
    mpf_out_str(stderr, 10, 0, Rf.data);
    fprintf(stderr, "\n");
    sc_poly_mpf_gcd_single(Rf, mp_q, &gcd2);

    if (1 != mpf_get_d(gcd2.data)) {
        // It is more efficient to check that gcd(Rf,q) == 1 early
        fprintf(stderr, "gcd2 is NOT 1 (it is %f %% %f = %f)\n",
            mpf_get_d(Rf.data), mpf_get_d(mp_q.data), mpf_get_d(gcd2.data));
        goto step2;
    }
    exit(-1);
    /*poly_dbl_ext_euclidean(g, polymod, &Rg, rho_g, rho_dummy, temp, n+1);
    poly_dbl_ext_euclidean_single(Rf, Rg, &gcd1, &u, &v);
    if (1 != gcd1) {
        // The gcd(Rf,Rg) and the computation of u and v are performed
        // together for efficiency
        fprintf(stderr, "gcd1 is NOT 1\n");
        goto step2;
    }
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "f", f, n);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "g", g, n);

    // Step 8. Calculate the polynomials F, G
    for (size_t i=0; i<n; i++) {
        F[i] = q*v*rho_g[i];
        G[i] = -q*u*rho_f[i];
    }
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "F", F, n);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "G", G, n);

    // Step 9. Calculate f-bar, g-bar and the reduction factor k
    DOUBLE fb[n], gb[n];
    fb[0] = f[0];
    gb[0] = g[0];
    for (size_t i=1; i<n; i++) {
        fb[i] = -f[n-i];
        gb[i] = -g[n-i];
    }

    // k = (F*fb + G*gb) / (f*fb + g*gb)
    DOUBLE num[2*n+2], den[2*n+2];
    poly_dbl_reset(den, n, 2*n+2);
    poly_dbl_mul(temp, n, f, fb);
    poly_dbl_mul(den, n, g, gb);
    poly_dbl_add_single(den, n, temp);

    DOUBLE scale;
    poly_dbl_ext_euclidean(den, polymod, &scale, rho_f, rho_dummy, temp, 2*n+2);

step9:
    poly_dbl_reset(num, n, 2*n+2);
    poly_dbl_mul(temp, n, fb, F);
    poly_dbl_mul(num, n, gb, G);
    poly_dbl_add_single(num, n, temp);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "num", num, 2*n+2);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "den", den, 2*n+2);

    // den * rho_f + polymod * rho_dummy = gcd(den, polymod) = scale
    // => den * rho_f = scale
    // => 1/den = rho_f / scale
    // Therefore, k = num/den = num * rho_f / scale
    DOUBLE k[2*n+2];
    poly_dbl_reset(k, 0, 2*n+2);
    poly_dbl_mul_mod(k, 2*n+2, num, rho_f);
    poly_dbl_reset(k, n, 2*n+2);
    for (size_t i=0; i<n; i++) {
        k[i] /= scale;
    }
    fprintf(stderr, "scale = %7.3f\n", scale);
    SC_PRINT_DEBUG(sc, "scale = %3.5f", scale);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "k", k, n);

    // Step 10. Reduce F and G
    poly_dbl_mul_mod(temp, n, k, f);
    poly_dbl_sub(F, n, F, temp);      // F = F - k*f
    poly_dbl_mul_mod(temp, n, k, g);
    poly_dbl_sub(G, n, G, temp);      // G = G - k*g

    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "F", F, n);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "G", G, n);

    if (poly_dbl_degree(k, n) >= 0) goto step9;

    // Step 11. Compute the public key h = g/f mod q
    // NOTE: May be able to do this faster using inversion in NTT domain
    DOUBLE *one  = temp;
    DOUBLE *quo  = temp +   n + 1;
    DOUBLE *invf = temp + 2*n + 2;
    poly_dbl_reset(one, 0, n+1);
    one[0] = 1;
    poly_dbl_div(one, f, n, quo, invf);
    poly_dbl_mul_mod(h, n, g, invf);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "h", h, n);
    poly_dbl_mul_mod(g, n, h, f);
    SC_PRINT_1D_DOUBLE(sc, SC_LEVEL_DEBUG, "g", g, n);

    // Step 12. Compute the polynomial basis B
    // Do this on the fly?
    DOUBLE *mat_M = SC_MALLOC(4*n*n*sizeof(DOUBLE));
    if (SC_FUNC_FAILURE == poly_dbl_expand_basis(f, g, F, G, n, mat_M)) {
        SC_FREE(mat_M, 4*n*n*sizeof(DOUBLE));
        return SC_FUNC_FAILURE;
    }
    SC_FREE(mat_M, 4*n*n*sizeof(DOUBLE));

    *sq_norm = gs_norm;

    fprintf(stderr, "Polynomial basis found\n");
    return SC_FUNC_SUCCESS;*/
}
