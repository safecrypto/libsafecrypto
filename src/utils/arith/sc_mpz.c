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

#include "utils/arith/sc_mpz.h"
#include "utils/arith/sc_mpn.h"
#include "utils/arith/sc_math.h"
#include "safecrypto_types.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"

#include <math.h>
#include <assert.h>


void sc_mpz_init(sc_mpz_t *inout)
{
    mpz_init(inout);
}

void sc_mpz_init2(sc_mpz_t *inout, size_t bits)
{
    mpz_init2(inout, bits);
}

void sc_mpz_clear(sc_mpz_t *inout)
{
    mpz_clear(inout);
}

sc_ulimb_t sc_mpz_to_limb_mod(const sc_mpz_t *in, sc_ulimb_t m)
{
    sc_ulimb_t ret;
    sc_mpz_t out;
    sc_mpz_init(&out);
    mpz_mod_ui(&out, in, m);
    ret = mpz_get_ui(&out);
    sc_mpz_clear(&out);
    return ret;
}

size_t sc_mpz_out_str(FILE *stream, SINT32 base, const sc_mpz_t *in)
{
    return mpz_out_str(stream, base, in);
}

sc_ulimb_t sc_mpz_get_ui(const sc_mpz_t *in)
{
    return mpz_get_ui(in);
}

sc_slimb_t sc_mpz_get_si(const sc_mpz_t *in)
{
    return mpz_get_si(in);
}

DOUBLE sc_mpz_get_d(const sc_mpz_t *in)
{
    return mpz_get_d(in);
}

SINT32 sc_mpz_get_bytes(UINT8 *out, const sc_mpz_t *in)
{
    sc_ulimb_t *limbs;
    size_t num_limbs = sc_mpz_get_size(in);

    if (NULL == in || NULL == out) {
        return SC_FUNC_FAILURE;
    }

    limbs = sc_mpz_get_limbs(in);
#if SC_LIMB_BITS == 64
    SC_LITTLE_ENDIAN_64_COPY(out, 0, limbs, num_limbs * 8);
#else
    SC_LITTLE_ENDIAN_32_COPY(out, 0, limbs, num_limbs * 4);
#endif

    return SC_FUNC_SUCCESS;
}

sc_ulimb_t * sc_mpz_get_limbs(const sc_mpz_t *in)
{
#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION
    return in->limbs;
#else
    return in->_mp_d;
#endif
}

SINT32 sc_mpz_get_size(const sc_mpz_t *in)
{
#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION
    return in->used;
#else
    __mpz_struct *z = (__mpz_struct *) in;
    return z->_mp_size;
#endif
}

void sc_mpz_set_size(sc_mpz_t *inout, SINT32 size)
{
#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION
    inout->used = size;
#else
    __mpz_struct *z = (__mpz_struct *) inout;
    z->_mp_size = size;
#endif
}

SINT32 sc_mpz_cmp(sc_mpz_t *a, const sc_mpz_t *b)
{
    return mpz_cmp(a, b);
}

SINT32 sc_mpz_cmp_d(sc_mpz_t *a, DOUBLE b)
{
    return mpz_cmp_d(a, b);
}

SINT32 sc_mpz_cmp_ui(sc_mpz_t *a, sc_ulimb_t b)
{
    return mpz_cmp_ui(a, b);
}

SINT32 sc_mpz_cmp_si(sc_mpz_t *a, sc_slimb_t b)
{
    return mpz_cmp_si(a, b);
}

SINT32 sc_mpz_cmpabs(sc_mpz_t *a, const sc_mpz_t *b)
{
    return mpz_cmpabs(a, b);
}

SINT32 sc_mpz_cmpabs_d(sc_mpz_t *a, DOUBLE b)
{
    return mpz_cmpabs_d(a, b);
}

SINT32 sc_mpz_cmpabs_ui(sc_mpz_t *a, sc_ulimb_t b)
{
    return mpz_cmpabs_ui(a, b);
}

void sc_mpz_negate(sc_mpz_t *out, const sc_mpz_t *in)
{
    mpz_neg(out, in);
}

SINT32 sc_mpz_is_zero(const sc_mpz_t *in)
{
    SINT32 flag = 1;
    if (mpz_cmp_si(in, 0)) {
        flag = 0;
    }
    return flag;
}

SINT32 sc_mpz_is_one(const sc_mpz_t *in)
{
    SINT32 flag = 1;
    if (0 != mpz_cmp_si(in, 1)) {
        flag = 0;
    }
    return flag;
}

SINT32 sc_mpz_is_neg(const sc_mpz_t *in)
{
#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION
    if (in->used < 0) {
        return 1;
    }
#else
    __mpz_struct *z = (__mpz_struct *) in;
    mp_size_t limbs = z->_mp_size;
    if (limbs < 0) {
        return 1;
    }
#endif
    return 0;
}

void sc_mpz_max_bits(const sc_mpz_t *in, sc_ulimb_t *mask, size_t *max_limbs)
{
#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION
    SINT32 limbs = SC_ABS(in->used);

    if (limbs == *max_limbs) {
        *mask |= in->limbs[limbs-1];
    }
    else if (limbs > *max_limbs) {
        *mask  = in->limbs[limbs-1];
        *max_limbs = limbs;
    }
#else
    __mpz_struct *z = (__mpz_struct *) in;
    mp_size_t limbs = SC_ABS(z->_mp_size);

    if (limbs == *max_limbs) {
        *mask |= z->_mp_d[limbs-1];
    }
    else if (limbs > *max_limbs) {
        *mask  = z->_mp_d[limbs-1];
        *max_limbs = limbs;
    }
#endif
}

SINT32 sc_mpz_sizeinbase(const sc_mpz_t *in, SINT32 base)
{
    return mpz_sizeinbase(in, base);
}

void sc_mpz_com_to_poly_limb(sc_ulimb_t *out, const sc_ulimb_t *in, size_t size)
{
    mpn_com(out, in, size);
}

SINT32 sc_mpz_sign(const sc_mpz_t *in)
{
    if (in == 0) {
        return 0;
    }
    return mpz_sgn(in);
}

void sc_mpz_copy(sc_mpz_t *out, const sc_mpz_t *in)
{
    mpz_set(out, in);
}

SINT32 sc_mpz_invmod(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *m)
{
    return mpz_invert(out, in, m);
}

void sc_mpz_add(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    mpz_add(out, in1, in2);
}

void sc_mpz_add_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    mpz_add_ui(out, in1, in2);
}

void sc_mpz_sub(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    mpz_sub(out, in1, in2);
}

void sc_mpz_sub_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    mpz_sub_ui(out, in1, in2);
}

void sc_mpz_set_ui(sc_mpz_t *inout, sc_ulimb_t value)
{
    mpz_set_ui(inout, value);
}

void sc_mpz_set_si(sc_mpz_t *inout, sc_slimb_t value)
{
    mpz_set_si(inout, value);
}

void sc_mpz_set_d(sc_mpz_t *inout, DOUBLE value)
{
    mpz_set_d(inout, value);
}

void sc_mpz_set_bytes(sc_mpz_t *out, const UINT8 *bytes, size_t n)
{
    size_t i;
    sc_mpz_t temp;
    mpz_init(&temp);

    sc_mpz_set_ui(out, 0);
    for (i=n; i--;) {
        sc_mpz_mul_2exp(&temp, out, 8);
        sc_mpz_add_ui(out, &temp, bytes[i]);
    }

    mpz_clear(&temp);
}

void sc_mpz_set_limbs(sc_mpz_t *out, const sc_ulimb_t *limbs, size_t n)
{
    size_t i;
    sc_mpz_t temp;
    mpz_init(&temp);

    sc_mpz_set_ui(out, 0);
    for (i=n; i--;) {
        sc_mpz_mul_2exp(&temp, out, SC_LIMB_BITS);
        sc_mpz_add_ui(out, &temp, limbs[i]);
    }

    mpz_clear(&temp);
}

SINT32 sc_mpz_set_str(sc_mpz_t *out, SINT32 base, const char *str)
{
    return mpz_set_str(out, str, base);
}

void sc_mpz_mul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    mpz_mul(out, in1, in2);
}

void sc_mpz_mul_scalar(sc_mpz_t *inout, const sc_mpz_t *in)
{
    mpz_mul(inout, inout, in);
}

void sc_mpz_mul_ui(sc_mpz_t *out, const sc_mpz_t *in1, const sc_ulimb_t in2)
{
    mpz_mul_ui(out, in1, in2);
}

void sc_mpz_mul_si(sc_mpz_t *out, const sc_mpz_t *in1, const sc_slimb_t in2)
{
    mpz_mul_si(out, in1, in2);
}

void sc_mpz_addmul(sc_mpz_t *inout, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    mpz_addmul(inout, in1, in2);
}

void sc_mpz_mul_2exp(sc_mpz_t *out, const sc_mpz_t *in, size_t exp)
{
    mpz_mul_2exp(out, in, exp);
}

void sc_mpz_submul(sc_mpz_t *inout, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    mpz_submul(inout, in1, in2);
}

void sc_mpz_addmul_ui(sc_mpz_t *inout, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    mpz_addmul_ui(inout, in1, in2);
}

void sc_mpz_submul_ui(sc_mpz_t *inout, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    mpz_submul_ui(inout, in1, in2);
}

void sc_mpz_addsqr(sc_mpz_t *inout, const sc_mpz_t *in)
{
    mpz_addmul(inout, in, in);
}

void sc_mpz_subsqr(sc_mpz_t *inout, const sc_mpz_t *in)
{
    mpz_submul(inout, in, in);
}

void sc_mpz_div(sc_mpz_t *q, sc_mpz_t *r, const sc_mpz_t *n, const sc_mpz_t *d)
{
    mpz_fdiv_qr(q, r, n, d);
}

void sc_mpz_divrem(sc_mpz_t *r, const sc_mpz_t *n, const sc_mpz_t *d)
{
    mpz_fdiv_r(r, n, d);
}

void sc_mpz_divquo(sc_mpz_t *q, const sc_mpz_t *n, const sc_mpz_t *d)
{
    mpz_fdiv_q(q, n, d);
}

void sc_mpz_divquo_2exp(sc_mpz_t *q, const sc_mpz_t *n, size_t exp)
{
    mpz_fdiv_q_2exp(q, n, exp);
}

void sc_mpz_sqrt(sc_mpz_t *out, const sc_mpz_t *in)
{
    mpz_sqrt(out, in);
}

void sc_mpz_pow_ui(sc_mpz_t *out, const sc_mpz_t *in, sc_ulimb_t exp)
{
    if (SC_LIMB_WORD(0) == exp) {
        sc_mpz_set_ui(out, SC_LIMB_WORD(1));
        return;
    }

    mpz_pow_ui(out, in, exp);
}

void sc_mpz_mod_barrett(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *m, size_t k, const sc_mpz_t *mu)
{
    // q1 = floor(in / b^(k-1))    i.e. right shift (k-1) words
    // q2 = q1 * mu
    // q3 = floor(q2 / b^(k+1))    i.e. right shift (k+1) words, or truncate the (k+1) least significant words of q2
    // r1 = in mod b^(k+1)          i.e. mask of the least significant (k+1) words
    // r2 = (q3 * m) mod b^(k+1)   i.e. mask of the least significant (k+1) words
    // r  = r1 - r2
    // if (r < 0)
    //   r += b^(k+1)
    // while (r >= m)
    //   r -= m

    sc_mpz_t temp, q1_q3;
    mpz_init2(&temp, SC_LIMB_BITS*2*(k+1));
    mpz_init2(&q1_q3, SC_LIMB_BITS*(k+1));

    sc_mpz_divquo_2exp(&q1_q3, in, SC_LIMB_BITS*(k-1));
    mpz_mul(&temp, &q1_q3, mu);
    sc_mpz_divquo_2exp(&q1_q3, &temp, SC_LIMB_BITS*(k+1));
    mpz_mul(&temp, &q1_q3, m);
    sc_mpz_copy(&q1_q3, in);
    if (sc_mpz_get_size(&q1_q3) > (k+1)) {
        sc_mpz_set_size(&q1_q3, k+1);            // r1
    }
    if (sc_mpz_get_size(&temp) > (k+1)) {
        sc_mpz_set_size(&temp, k+1);             // r2
    }
    mpz_sub(out, &q1_q3, &temp);           // r = r1 - r2
    /*if (sc_mpz_is_neg(out)) {
        sc_mpz_set_ui(&temp, 2);
        sc_mpz_pow_ui(&temp, &temp, SC_LIMB_BITS*(k+1));
        sc_mpz_add(out, out, &temp);
    }*/
    while (sc_mpz_cmp(out, m) >= 0) {
        mpz_sub(out, out, m);
    }

    mpz_clear(&temp);
    mpz_clear(&q1_q3);
}

void sc_mpz_mod(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *m)
{
    mpz_mod(out, in, m);
}

void sc_mpz_mod_ui(sc_mpz_t *out, const sc_mpz_t *in, sc_ulimb_t m)
{
    mpz_mod_ui(out, in, m);
}

sc_ulimb_t sc_mpz_ceil_div_ui(sc_mpz_t *in, sc_ulimb_t m)
{
    return mpz_cdiv_ui(in, m);
}

sc_ulimb_t sc_mpz_floor_div_ui(sc_mpz_t *in, sc_ulimb_t m)
{
    return mpz_fdiv_ui(in, m);
}

void sc_mpz_crt(sc_mpz_t *result, const sc_mpz_t *a, const sc_mpz_t *a_m,
    sc_ulimb_t b, sc_mod_t *b_m, sc_ulimb_t m, const sc_mpz_t *ab_m,
    sc_mpz_t *temp)
{
    // result = a + a_m * ((b - a%b_m) % b_m)^-1

    sc_mpz_copy(temp, a);
    if (mpz_sgn(a) < 0) {
        sc_mpz_add(temp, temp, a_m);
    }

    sc_ulimb_t a1 = mpz_fdiv_ui(temp, b_m->m);
    sc_ulimb_t s = limb_sub_mod(b, a1, b_m->m);
    s = limb_mul_mod(s, m, b_m->m, b_m->m_inv);
    mpz_addmul_ui(temp, a_m, s);

    mpz_sub(result, temp, ab_m);
    if (mpz_cmpabs(temp, result) <= 0) {
        mpz_set(result, temp);
    }
}

sc_ulimb_t sc_mpz_get_ui_mod(const sc_mpz_t *a, const sc_mod_t *mod)
{
    sc_mpz_t temp;
    mpz_init(&temp);
    sc_ulimb_t r;
    if (mpz_fits_slong_p(a)) {
        // Directly obtain a % m
        sc_slimb_t c1 = mpz_get_si(a);
        if (c1 < 0) {
            // Compensate if the value is negative
            r = limb_mod_l(-c1, mod->m, mod->m_inv, mod->norm);
            r = mod->m - r;
            if (r == mod->m)
                r = 0;
        }
        else {
            r = limb_mod_l(c1, mod->m, mod->m_inv, mod->norm);
        }
    }
    else {
        // Calculate rem(a/m)
        r = mpz_fdiv_r_ui(&temp, a, mod->m);
    }
    mpz_clear(&temp);
    return r;
}

SINT32 sc_mpz_gcd(const sc_mpz_t *a, const sc_mpz_t *b, sc_mpz_t *gcd)
{
#if 0
    // Swap a and b if b > a
    if (mpz_cmp(b, a) > 0) {
        return sc_mpz_gcd(b, a, gcd);
    }

    if (sc_mpz_is_zero(a)) {
        mpz_abs(gcd, b);
        return SC_FUNC_SUCCESS;
    }
    if (sc_mpz_is_zero(b)) {
        mpz_abs(gcd, a);
        return SC_FUNC_SUCCESS;
    }

    sc_mpz_t A, B, q, t;
    mpz_init(&A);
    mpz_init(&B);
    mpz_init(&q);
    mpz_init(&t);
    mpz_set(&A, a);
    mpz_set(&B, b);

    // Iteratively update the variables while b is non-zero
    while (1) {
        // Verify that b is non-zero
        if (0 == mpz_cmp_ui(&B, 0)) {
            goto finish;
        }

        // q = floor(A_i/B_i), A_(i+1) = B_i, B_(i+1) = A_i - B_i.q
        mpz_fdiv_q(&q, &A, &B);
        mpz_mul(&t, &B, &q);
        mpz_sub(&q, &A, &t);
        mpz_set(&A, &B);
        mpz_set(&B, &q);
    }

finish:
    mpz_set(gcd, &A);
    mpz_clear(&A);
    mpz_clear(&B);
    mpz_clear(&q);
    mpz_clear(&t);
    return SC_FUNC_SUCCESS;
#else
    mpz_gcd(gcd, a, b);
    return SC_FUNC_SUCCESS;
#endif
}

SINT32 sc_mpz_xgcd(const sc_mpz_t *a, const sc_mpz_t *b, sc_mpz_t *gcd,
    sc_mpz_t *x, sc_mpz_t *y)
{
#if 1
    // Ensure that a >= b by swapping the inputs as necessary
    if (mpz_cmp(b, a) > 0) {
        return sc_mpz_xgcd(b, a, gcd, y, x);
    }

    sc_mpz_t x2, y2, q, s, t, A, B;
    mpz_init(&x2);
    mpz_init(&y2);
    mpz_init(&q);
    mpz_init(&s);
    mpz_init(&t);
    mpz_init(&A);
    mpz_init(&B);

    mpz_set(&A, a);
    mpz_set(&B, b);

    // Initialise the intermediate results
    mpz_set_si(x, 0);
    mpz_set_si(&y2, 0);
    mpz_set_si(y, 1);
    mpz_set_si(&x2, 1);

    // Iteratively update the variables while b is non-zero
    while (1) {
        // Verify that b is non-zero
        if (0 == mpz_cmp_si(&B, 0)) {
            goto finish;
        }

        // q = floor(A_i/B_i), A_(i+1) = B_i, B_(i+1) = A_i - B_i.q
        mpz_fdiv_q(&q, &A, &B);
        mpz_mul(&t, &B, &q);
        mpz_sub(&s, &A, &t);
        mpz_set(&A, &B);
        mpz_set(&B, &s);

        // Update x_(i+1) = x_2 - q.x_i, x_2 = x_i
        mpz_set(&s, x);
        mpz_mul(&t, &q, x);
        mpz_sub(x, &x2, &t);
        mpz_set(&x2, &s);

        // Update y_(i+1) = y_2 - q.y_i, y_2 = y_i
        mpz_set(&s, y);
        mpz_mul(&t, &q, y);
        mpz_sub(y, &y2, &t);
        mpz_set(&y2, &s);
    }

finish:
    mpz_set(gcd, &A);
    mpz_set(x, &x2);
    mpz_set(y, &y2);

    mpz_clear(&x2);
    mpz_clear(&y2);
    mpz_clear(&q);
    mpz_clear(&s);
    mpz_clear(&t);
    mpz_clear(&A);
    mpz_clear(&B);
    return SC_FUNC_SUCCESS;
#else
    mpz_gcdext(gcd, x, y, a, b);
    return SC_FUNC_SUCCESS;
#endif
}

