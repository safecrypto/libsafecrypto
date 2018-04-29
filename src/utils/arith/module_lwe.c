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

#include "utils/arith/module_lwe.h"

#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/crypto/xof.h"
#include "utils/arith/arith.h"
#include "utils/arith/ntt.h"
#include "utils/arith/sc_math.h"
#include "utils/sampling/sampling.h"
#ifdef _ENABLE_AVX2_INTRINSICS
#include <immintrin.h>
#endif



extern UINT32 round_alpha(const UINT32 a, SINT32 *a0, const ntt_params_t *alpha, const ntt_params_t *p);

// Translate an element in Zq to an integer in the range 0 ... 2^d - 1,
// where d < rnd(2^d - 1)
void mlwe_compress(SINT32 *inout, size_t n, size_t k, UINT32 d,
    UINT32 q, UINT32 q_inv, SINT32 q_norm)
{
    size_t i;
    UINT32 rnd_q2 = q >> 1;
    UINT32 mod_2d = (1 << d) - 1;

    for (i=0; i<k*n; i++) {
        SINT32 t = inout[i] << d;
        t       += rnd_q2;
        t        = ((UINT64)t * (UINT64)q_inv) >> (32 + q_norm);
        inout[i] = t & mod_2d;
    }
}

// Translate an integer in the range 0 ... 2^d - 1 to an element in Zq,
// where d < rnd(2^d - 1)
void mlwe_decompress(SINT32 *inout, size_t n, size_t k, UINT32 d, UINT32 q)
{
    size_t i;

    for (i=0; i<k*n; i++) {
        SINT32 t;
        t        = inout[i] * q;
        inout[i] = t >> d;
    }
}

// Truncate the input ring polynomial by d bits.
// NOTE: in MUST be in the range 0 to q-1 inclusive
void pwr_2_round(SINT32 *out, const SINT32 *in, size_t n, size_t k, UINT32 d)
{
    size_t i;
    SINT32 mask   = (1 << d) - 1;
    SINT32 sign   = 1 << d;
    SINT32 thresh = 1 << (d - 1);

    for (i=0; i<n*k; i++) {
        SINT32 t = in[i] & mask;
        t -= (t > thresh) * sign;
        out[i] = (in[i] - t) >> d;
    }
}

// Truncate the input ring polynomial by d bits and compute the residual.
// NOTE: in MUST be in the range 0 to q-1 inclusive
void decompose(SINT32 *t1, SINT32 *t0, const SINT32 *in, size_t n,
    size_t k, UINT32 alpha, SINT32 q)
{
    size_t i;
    SINT32 *v     = (SINT32 *) in;
    SINT32 mask   = (1 << alpha) - 1;
    SINT32 sign   = 1 << alpha;
    SINT32 thresh = 1 << (alpha - 1);

    for (i=0; i<k*n; i++) {
        SINT32 t = *v & mask;
        t -= (t > thresh) * sign;
        *t1++ = (*v++ - t) >> alpha;
        *t0++ = (t >= 0)? t : t + q;
    }
}

// Truncate the input ring polynomial by d bits and compute the residual.
// NOTE: in MUST be in the range 0 to q-1 inclusive
void decompose_g(SINT32 *t1, SINT32 *t0, const SINT32 *in, size_t n,
    size_t k, const ntt_params_t *alpha, SINT32 q)
{
    size_t i;
    SINT32 alpha_q = alpha->u.ntt32.q;
    SINT32 alpha_m = alpha->u.ntt32.m;
    SINT32 alpha_k = alpha->u.ntt32.k;
    SINT32 *v     = (SINT32 *) in;
    SINT32 thresh = alpha_q >> 1;

    for (i=0; i<k*n; i++) {
        SINT32 t, dividend;
        MODULE_LWE_BARRETT_REDUCTION(t, *v, alpha_k, alpha_m, alpha_q);

        t -= (t > thresh) * alpha_q;
        dividend = *v++ - t;
        if (dividend >= (q - 1)) {
            *t1++ = 0;
            *t0++ = t - 1;
        }
        else {
            UINT32 div;
            MODULE_LWE_BARRETT_DIVISION(div, dividend, alpha_k, alpha_m, alpha_q);
            *t1++ = div & 0x1FF;
            *t0++ = (t >= 0)? t : t + q;
        }
    }
}

void collision_resistant_hash(const UINT8 *a, size_t a_size, const UINT8 *b, size_t b_size, UINT8 *hash)
{
    utils_crypto_xof_t *xof = utils_crypto_xof_create(SC_XOF_SHAKE256);

    // Initialise the XOF
    xof_init(xof);

    // Absorb the input data to configure the state
    xof_absorb(xof, a, a_size);
    xof_absorb(xof, b, b_size);
    xof_final(xof);

    // Create 48 bytes of output data
    xof_squeeze(xof, hash, 48);

    // Destroy the XOF
    utils_crypto_xof_destroy(xof);
}

void expand_mask(const SINT32 *K, const SINT32 *mu, SINT32 kappa, SINT32 gamma_1, size_t l, SINT32 *y)
{
    size_t i, j = 0;
    UINT8 kappa_bytes[2] = {kappa >> 8, kappa & 0xFF};

    utils_crypto_xof_t *xof = utils_crypto_xof_create(SC_XOF_SHAKE256);

    // Initialise the XOF
    xof_init(xof);

    // Absorb the input data to configure the state
    xof_absorb(xof, mu, 48);
    xof_absorb(xof, K, 32);
    xof_absorb(xof, kappa_bytes, 2);
    xof_final(xof);

    while (j < 256) {
        UINT8 seed[5];
        UINT32 samples[2];
        UINT32 cond;

        // Create 5 bytes from which two 20-bit samples are generated
        xof_squeeze(xof, seed, 5);
        samples[0] = (((UINT32)seed[2] & 0xF) << 16) | ((UINT32)seed[1] << 8) | ((UINT32)seed[0]);
        samples[1] = ((UINT32)seed[2] << 12) | ((UINT32)seed[1] << 4) | ((UINT32)seed[2] >> 4);

        // Overwrite the current output index with a sample, incrementing the output index only if
        // the value lies within the range 0 to 2^20 - 1
        cond = (samples[0] - 0x100000) >> 31;
        y[j] = samples[0];
        j   += cond;
        if (256 == j) {
            break;
        }
        cond = (samples[1] - 0x100000) >> 31;
        y[j] = samples[1];
        j   += cond;
    }

    // Destroy the XOF
    utils_crypto_xof_destroy(xof);
}

// Uniform sampling of an mx1 matrix with coefficients of -eta to +eta
void uniform_rand_sample_csprng(prng_ctx_t *csprng, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m)
{
    size_t i;

#if 1
    UINT32 mask = (1 << (bits + 1)) - 1;

    prng_mem(csprng, (UINT8*) s, m * n * sizeof(SINT32));
    for (i=0; i<m*n; i++) {
        SINT32 temp = s[i] & mask;
        temp >>= (temp > 2*eta);    // eta is <=5, so two range checks are sufficient
        temp >>= (temp > 2*eta);
        s[i] = eta - temp;
    }
#else
    size_t j;
    SINT32 *mat_s;
    for (i=0; i<m; i++) {
        mat_s = s + i * n;
        for (j=0; j<n; j++) {
            UINT32 rand = prng_var(csprng, bits + 1);
            mat_s[j] = rand & mask;
            while (mat_s[j] > 2*eta) {
                mat_s[j] >>= 1;
            }
            mat_s[j] = eta - mat_s[j];
        }
    }
#endif
}

// Uniform sampling of an mx1 matrix with coefficients of -eta to +eta
void uniform_rand_sample_small_csprng(prng_ctx_t *csprng, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m)
{
    size_t i, j;
    UINT32 mask = (1 << (bits + 1)) - 1;

#ifndef CONSTRAINED_RAM
    SINT32 *ptr = s;

    for (i=0; i<m*n; i+=1024) {
        UINT8 r[512];
        prng_mem(csprng, r, 512);

        size_t blocks = ((i+m*n) > 512)? 512 : m*n;

        // This inner loop is vectorisable for SIMD
        for (j=0; j<blocks; j++) {
            SINT32 temp;

            temp = r[j] & mask;
            if (temp > 2*eta) {
                temp >>= 1;
            }
            *ptr++ = eta - temp;

            r[j] >>= 4;
            temp = r[j] & mask;
            if (temp > 2*eta) {
                temp >>= 1;
            }
            *ptr++ = eta - temp;
        }
    }
#else
    SINT32 *mat_s;
    for (i=0; i<m; i++) {
        mat_s = s + i * n;
        for (j=0; j<n; j++) {
            UINT32 rand = prng_var(csprng, bits + 1);
            mat_s[j] = rand & mask;
            while (mat_s[j] > 2*eta) {
                mat_s[j] >>= 1;
            }
            mat_s[j] = eta - mat_s[j];
        }
    }
#endif
}

// Uniform sampling of an mx1 matrix with coefficients of -eta to +eta
void uniform_rand_sample_xof(utils_crypto_xof_t *xof, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m)
{
    size_t i;

    UINT32 mask = (1 << (bits + 1)) - 1;

    xof_squeeze(xof, (UINT8*) s, m * n * sizeof(SINT32));
    for (i=0; i<m*n; i++) {
        SINT32 temp = s[i] & mask;
        temp >>= (temp > 2*eta);    // eta is <=5, so two range checks are sufficient
        temp >>= (temp > 2*eta);
        s[i] = eta - temp;
    }
}

// Uniform sampling of an mx1 matrix with coefficients of -eta to +eta
void uniform_rand_sample_small_xof(utils_crypto_xof_t *xof, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m)
{
    size_t i, j;
    UINT32 mask = (1 << (bits + 1)) - 1;

    SINT32 *ptr = s;

    for (i=0; i<(m*n)>>10; i++) {
        UINT8 r[512];
        xof_squeeze(xof, r, 512);

        // This inner loop is vectorisable for SIMD
        for (j=0; j<512; j++) {
            SINT32 temp;

            temp = r[j] & mask;
            if (temp > 2*eta) {
                temp >>= 1;
            }
            *ptr++ = eta - temp;

            r[j] >>= 4;
            temp = r[j] & mask;
            if (temp > 2*eta) {
                temp >>= 1;
            }
            *ptr++ = eta - temp;
        }
    }
}

// Random sampling with a binomial distribution
void binomial_rand_sample_csprng(prng_ctx_t *csprng, SINT32 q, SINT32 eta,
    SINT32 *s, size_t n, size_t m)
{
#ifndef CONSTRAINED_RAM
    size_t i, j, idx;
    static const size_t log2_blks = 6;
    size_t blks = 1 << log2_blks;

    for (i=0; i<(m*n)>>(2+log2_blks); i++) {
        UINT8 t[5*blks];
        UINT8 *ptr = t;

        prng_mem(csprng, t, eta*blks);

        for (j=0; j<blks; j++) {
            UINT32 a[8];
            a[0] = *ptr & 0x01;
            a[1] = *ptr & 0x02;
            a[2] = *ptr & 0x04;
            a[3] = *ptr & 0x08;
            a[4] = *ptr & 0x10;
            a[5] = *ptr & 0x20;
            a[6] = *ptr & 0x40;
            a[7] = *ptr & 0x80;
            ptr++;
            for (idx=1; idx<eta; idx++) {
                a[0] += *ptr & 0x01;
                a[1] += *ptr & 0x02;
                a[2] += *ptr & 0x04;
                a[3] += *ptr & 0x08;
                a[4] += *ptr & 0x10;
                a[5] += *ptr & 0x20;
                a[6] += *ptr & 0x40;
                a[7] += *ptr & 0x80;
                ptr++;
            }
    
            *s++ = (a[0]     ) - (a[1] >> 1);
            *s++ = (a[2] >> 2) - (a[3] >> 3);
            *s++ = (a[4] >> 4) - (a[5] >> 5);
            *s++ = (a[6] >> 6) - (a[7] >> 7);
        }
    }
#else
    UINT32 a[8];
    UINT8 t[5];
    size_t i, j, idx;

    for (i=0; i<(m*n)>>2; i++) {
        prng_mem(csprng, t, eta);
        for (j=0; j<8; j++) {
            a[j]   = t[0] & 1;
            t[0] >>= 1;
        }
        for (idx=1; idx<eta; idx++) {
            for (j=0; j<8; j++) {
                a[j]    += t[idx] & 1;
                t[idx] >>= 1;
            }
        }

        s[4*i+0] = a[0] - a[1];
        s[4*i+1] = a[2] - a[3];
        s[4*i+2] = a[4] - a[5];
        s[4*i+3] = a[6] - a[7];
    }
#endif
}

void binomial_rand_sample_xof(utils_crypto_xof_t *xof, SINT32 q, SINT32 eta,
    SINT32 *s, size_t n, size_t m)
{
#ifndef CONSTRAINED_RAM
    size_t i, j, idx;
    SINT32 *out = s;

    for (i=0; i<(m*n)>>10; i++) {
        UINT8 t[5*256];
        UINT8 *ptr = t;
        SINT32 *out = s;

        xof_squeeze(xof, t, eta*256);

        for (j=0; j<256; j++) {
            UINT32 a[8];
            a[0] = *ptr & 0x01;
            a[1] = *ptr & 0x02;
            a[2] = *ptr & 0x04;
            a[3] = *ptr & 0x08;
            a[4] = *ptr & 0x10;
            a[5] = *ptr & 0x20;
            a[6] = *ptr & 0x40;
            a[7] = *ptr & 0x80;
            ptr++;
            for (idx=1; idx<eta; idx++) {
                a[0] += *ptr & 0x01;
                a[1] += *ptr & 0x02;
                a[2] += *ptr & 0x04;
                a[3] += *ptr & 0x08;
                a[4] += *ptr & 0x10;
                a[5] += *ptr & 0x20;
                a[6] += *ptr & 0x40;
                a[7] += *ptr & 0x80;
                ptr++;
            }
    
            *out++ = (a[0]     ) - (a[1] >> 1);
            *out++ = (a[2] >> 2) - (a[3] >> 3);
            *out++ = (a[4] >> 4) - (a[5] >> 5);
            *out++ = (a[6] >> 6) - (a[7] >> 7);
        }
    }
#else
    UINT32 a[8];
    UINT8 t[5];
    size_t i, j, idx;

    for (i=0; i<(m*n)>>2; i++) {
        xof_squeeze(xof, t, eta);
        for (j=0; j<8; j++) {
            a[j]   = t[0] & 1;
            t[0] >>= 1;
        }
        for (idx=1; idx<eta; idx++) {
            for (j=0; j<8; j++) {
                a[j]    += t[idx] & 1;
                t[idx] >>= 1;
            }
        }

        s[4*i+0] = a[0] - a[1];
        s[4*i+1] = a[2] - a[3];
        s[4*i+2] = a[4] - a[5];
        s[4*i+3] = a[6] - a[7];
    }
#endif
}

// Uniform random sampling of a ring of n elements
void uniform_random_ring_q_csprng(prng_ctx_t *csprng, SINT32 *a, size_t n, SINT32 q, UINT32 q_bits)
{
#if 1
    size_t i, j;
    SINT32 mask = (1 << q_bits) - 1;

    union u {
        UINT8 b[512];
        UINT16 s[256];
    };

    for (j=n>>8; j--;) {
        union u t;
        prng_mem(csprng, t.b, 512);
        for (i=0; i<256; i++) {
            a[i]  = t.s[i] & mask;
            a[i] -= (a[i] >= q) * q;
        }
    }
#else
    size_t i;
    for (i=0; i<n; i++) {
        a[i] = prng_var(csprng, q_bits);
        if (a[i] >= q) {
            a[i] -= q;
        }
    }
#endif
}

// Uniform random sampling of a ring of n elements
void uniform_random_ring_q_xof(utils_crypto_xof_t *xof, SINT32 *a, size_t n, SINT32 q, UINT32 q_bits)
{
    size_t i;
    SINT32 mask = (1 << q_bits) - 1;

    xof_squeeze(xof, (UINT8*)a, n * sizeof(SINT32));
    for (i=0; i<n; i++) {
        a[i] &= mask;
        a[i] -= (a[i] >= q) * q;
    }
}

// Multiplication of a kxl matrix of ring polynomials with a kx1 vector
// All inputs are assumed to be in NTT domain.
static void mul_matrix_vector(SINT32 *out, const SINT32 *mat_in1, const SINT32 *vec_in2,
    size_t n, size_t k, size_t l,
    const SINT16 *ntt_w, const SINT16 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt)
{
    size_t i, j;
    SINT32 c[n] SC_DEFAULT_ALIGNED;

    for (i=0; i<k; i++) {
        sc_ntt->mul_32_pointwise(out + i*n, ntt, vec_in2, mat_in1 + k*i*n);

        for (j=1; j<l; j++) {
            sc_ntt->mul_32_pointwise(c, ntt, vec_in2 + j*n, mat_in1 + k*i*n + j*n);
            sc_poly->add_32(out + i*n, n, out + i*n, c);
        }
        sc_ntt->normalize_32(out, l*n, ntt);

        sc_ntt->inv_ntt_32_16(out + i*n, ntt, out + i*n, ntt_w, ntt_r);
        sc_ntt->normalize_32(out + i*n, n, ntt);
    }
}

// Compute t = A * y
void create_rand_product_32_csprng(prng_ctx_t *csprng,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT32 *ntt_w, const SINT32 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt)
{
    size_t i, j;
    SINT32 block[n] SC_DEFAULT_ALIGNED;

#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
    if (ntt_overwrite) {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_32(y + j*n, ntt, y + j*n, ntt_w);
        }
    }
    else {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_32(temp + j*n, ntt, y + j*n, ntt_w);
        }
    }

    SINT32 *ntt_y = (ntt_overwrite)? y : temp;
#endif

    if (transpose) {
        SINT32 *out;

        // k x l matrix multiplication of n-element rings
        for (j=0; j<l; j++) {
            for (i=0; i<k; i++) {
                out = (0 == j)? t + i*n : block;

                uniform_random_ring_q_csprng(csprng, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(out, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_32(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(out, ntt, block, c);
#endif
                if (0 != j) {
                    sc_poly->add_32(t + i*n, n, out, c);
                    sc_ntt->normalize_32(t + i*n, n, ntt);
                }
            }
        }

        for (i=0; i<k; i++) {
            sc_ntt->inv_ntt_32_32(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
        }
    }
    else {
        // k x l matrix multiplication of n-element rings
        for (i=0; i<k; i++) {
	       uniform_random_ring_q_csprng(csprng, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
            sc_ntt->mul_32_pointwise(t + i*n, ntt, ntt_y, c);
#else
            sc_ntt->fwd_ntt_32_32(block, ntt, y, ntt_w);
            sc_ntt->mul_32_pointwise(t + i*n, ntt, block, c);
#endif

            for (j=1; j<l; j++) {
                uniform_random_ring_q_csprng(csprng, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(c, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_32(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(c, ntt, block, c);
#endif

                sc_poly->add_32(t + i*n, n, t + i*n, c);
            }
            sc_ntt->normalize_32(t, l*n, ntt); // Needed for parameter set 3 of (Dilithium and Dilithium-G)

            sc_ntt->inv_ntt_32_32(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
            sc_ntt->normalize_32(t + i*n, n, ntt);
        }
    }
}

void create_rand_product_16_csprng(prng_ctx_t *csprng,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT16 *ntt_w, const SINT16 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt)
{
    size_t i, j;
    SINT32 block[n] SC_DEFAULT_ALIGNED;

#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
    if (ntt_overwrite) {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_16(y + j*n, ntt, y + j*n, ntt_w);
        }
    }
    else {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_16(temp + j*n, ntt, y + j*n, ntt_w);
        }
    }

    SINT32 *ntt_y = (ntt_overwrite)? y : temp;
#endif

    if (transpose) {
        SINT32 *out;

        // k x l matrix multiplication of n-element rings
        for (j=0; j<l; j++) {
            for (i=0; i<k; i++) {
                out = (0 == j)? t + i*n : block;

                uniform_random_ring_q_csprng(csprng, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(out, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_16(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(out, ntt, block, c);
#endif
                if (0 != j) {
                    sc_poly->add_32(t + i*n, n, t + i*n, out);
                    sc_ntt->normalize_32(t + i*n, n, ntt);
                }
            }
        }

        for (i=0; i<k; i++) {
            sc_ntt->inv_ntt_32_16(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
        }
    }
    else {
        // k x l matrix multiplication of n-element rings
        for (i=0; i<k; i++) {
            uniform_random_ring_q_csprng(csprng, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
            sc_ntt->mul_32_pointwise(t + i*n, ntt, ntt_y, c);
#else
            sc_ntt->fwd_ntt_32_16(block, ntt, y, ntt_w);
            sc_ntt->mul_32_pointwise(t + i*n, ntt, block, c);
#endif

            for (j=1; j<l; j++) {
                uniform_random_ring_q_csprng(csprng, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(c, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_16(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(c, ntt, block, c);
#endif

                sc_poly->add_32(t + i*n, n, t + i*n, c);
            }
            sc_ntt->normalize_32(t, l*n, ntt); // Needed for parameter set 3 of (Dilithium and Dilithium-G)

            sc_ntt->inv_ntt_32_16(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
            sc_ntt->normalize_32(t + i*n, n, ntt);
        }
    }
}

// Compute t = A * y
void create_rand_product_32_xof(utils_crypto_xof_t *xof,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT32 *ntt_w, const SINT32 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt)
{
    size_t i, j;
    SINT32 block[n] SC_DEFAULT_ALIGNED;

#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
    if (ntt_overwrite) {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_32(y + j*n, ntt, y + j*n, ntt_w);
        }
    }
    else {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_32(temp + j*n, ntt, y + j*n, ntt_w);
        }
    }

    SINT32 *ntt_y = (ntt_overwrite)? y : temp;
#endif

    if (transpose) {
        SINT32 *out;

        // k x l matrix multiplication of n-element rings
        for (j=0; j<l; j++) {
            for (i=0; i<k; i++) {
                out = (0 == j)? t + i*n : block;

                uniform_random_ring_q_xof(xof, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(out, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_32(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(out, ntt, block, c);
#endif

                if (0 != j) {
                    sc_poly->add_32(t + i*n, n, out, c);
                    sc_ntt->normalize_32(t + i*n, n, ntt);
                }
            }
        }

        for (i=0; i<k; i++) {
            sc_ntt->inv_ntt_32_32(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
        }
    }
    else {
        // k x l matrix multiplication of n-element rings
        for (i=0; i<k; i++) {
           uniform_random_ring_q_xof(xof, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
            sc_ntt->mul_32_pointwise(t + i*n, ntt, ntt_y, c);
#else
            sc_ntt->fwd_ntt_32_32(block, ntt, y, ntt_w);
            sc_ntt->mul_32_pointwise(t + i*n, ntt, block, c);
#endif

            for (j=1; j<l; j++) {
                uniform_random_ring_q_xof(xof, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(c, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_32(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(c, ntt, block, c);
#endif

                sc_poly->add_32(t + i*n, n, t + i*n, c);
            }
            sc_ntt->normalize_32(t, l*n, ntt); // Needed for parameter set 3 of (Dilithium and Dilithium-G)

            sc_ntt->inv_ntt_32_32(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
            sc_ntt->normalize_32(t + i*n, n, ntt);
        }
    }
}

void create_rand_product_16_xof(utils_crypto_xof_t *xof,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT16 *ntt_w, const SINT16 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt)
{
    size_t i, j;
    SINT32 block[n] SC_DEFAULT_ALIGNED;

#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
    if (ntt_overwrite) {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_16(y + j*n, ntt, y + j*n, ntt_w);
        }
    }
    else {
        for (j=0; j<l; j++) {
            sc_ntt->fwd_ntt_32_16(temp + j*n, ntt, y + j*n, ntt_w);
        }
    }

    SINT32 *ntt_y = (ntt_overwrite)? y : temp;
#endif

    if (transpose) {
        SINT32 *out;

        // k x l matrix multiplication of n-element rings
        for (j=0; j<l; j++) {
            for (i=0; i<k; i++) {
                out = (0 == j)? t + i*n : block;

                uniform_random_ring_q_xof(xof, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(out, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_16(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(out, ntt, block, c);
#endif
                if (0 != j) {
                    sc_poly->add_32(t + i*n, n, t + i*n, out);
                    sc_ntt->normalize_32(t + i*n, n, ntt);
                }
            }
        }

        for (i=0; i<k; i++) {
            sc_ntt->inv_ntt_32_16(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
        }
    }
    else {
        // k x l matrix multiplication of n-element rings
        for (i=0; i<k; i++) {
            uniform_random_ring_q_xof(xof, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
            sc_ntt->mul_32_pointwise(t + i*n, ntt, ntt_y, c);
#else
            sc_ntt->fwd_ntt_32_16(block, ntt, y, ntt_w);
            sc_ntt->mul_32_pointwise(t + i*n, ntt, block, c);
#endif

            for (j=1; j<l; j++) {
                uniform_random_ring_q_xof(xof, c, n, q, q_bits);
#ifdef MODULE_LWE_STORE_NTT_MATRIX_INPUT
                sc_ntt->mul_32_pointwise(c, ntt, ntt_y + j*n, c);
#else
                sc_ntt->fwd_ntt_32_16(block, ntt, y + j*n, ntt_w);
                sc_ntt->mul_32_pointwise(c, ntt, block, c);
#endif

                sc_poly->add_32(t + i*n, n, t + i*n, c);
            }
            sc_ntt->normalize_32(t, l*n, ntt); // Needed for parameter set 3 of (Dilithium and Dilithium-G)

            sc_ntt->inv_ntt_32_16(t + i*n, ntt, t + i*n, ntt_w, ntt_r);
            sc_ntt->normalize_32(t + i*n, n, ntt);
        }
    }
}

prng_ctx_t * create_csprng(safecrypto_t *sc, const UINT8 *r, size_t len)
{
    static const UINT8 nonce[16] = "dilithiumcrystal";

    prng_ctx_t *csprng;
    safecrypto_prng_e type = prng_get_type(sc->prng_ctx[0]);

    csprng = prng_create(SC_ENTROPY_USER_PROVIDED, type,
        SC_PRNG_THREADING_NONE, 0x01000000);
    if (NULL == csprng) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return NULL;
    }
    if (SC_FUNC_FAILURE == prng_set_entropy(csprng, r, len)) {
        SC_LOG_ERROR(sc, SC_ERROR);
        goto finish_free;
    }
    if (SC_FUNC_FAILURE == prng_init(csprng, nonce, 16)) {
        SC_LOG_ERROR(sc, SC_ERROR);
        goto finish_free;
    }

    return csprng;
finish_free:
    prng_destroy(csprng);
    return NULL;
}

UINT32 max_singular_value(const SINT32 *s1, size_t l,
    const SINT32 *s2, size_t k, size_t n)
{
    size_t i, j;
    FLOAT *a = SC_MALLOC(n * (l + k) * sizeof(FLOAT));
    FLOAT w[l + k], temp;

    for (i = 0; i < l; i++) {
        for (j = 0; j < n; j++) {
            //a[i*n + j] = s1[i*n + j];
            a[j*(l + k) + i] = s1[i*n + j];
            //a[i*n + j] = s1[i*n + j];
        }
    }
    for (i = 0; i < k; i++) {
        for (j = 0; j < n; j++) {
            //a[(i+l)*n + j] = s2[i*n + j];
            a[j*(l + k) + i + l] = s2[i*n + j];
            //a[(i+l)*n + j] = s2[i*n + j];
        }
    }

    /*for (i = 0; i < n; i++) {
        for (j = 0; j < l + k; j++) {
            fprintf(stderr, "%f ", a[i*(l + k) + j]);
        }
    }
    fprintf(stderr, "\n");*/

    svd(a, n, l + k, w);

    temp = 0;
    //fprintf(stderr, "%f %f %f %f     ", w[0], w[1], w[2], w[3]);
    for (i = 0; i < l + k; i++) {
#if 0
        temp += w[i];
#else
        if (w[i] > temp) {
            temp = w[i];
        }
#endif
    }
    //fprintf(stderr, "SVD = %f\n", temp);
    //exit(-1);

    SC_FREE(a, n * (l + k) * sizeof(FLOAT));
    return (UINT32)temp;
}

#ifdef _ENABLE_AVX2_INTRINSICS
SINT32 high_order_bits(UINT8 *out, const SINT32 *in, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha)
{
	size_t i;

    union u {
        __m256i m;
        SINT64 s[4];
    };

    // Create Barret reduction constant vectors
    UINT32 hexmask = 0xFFFFFFFF;
    __m256i b_m   = _mm256_setr_epi32(alpha->u.ntt32.m, 0, alpha->u.ntt32.m, 0, alpha->u.ntt32.m, 0, alpha->u.ntt32.m, 0);
    __m256i b_q   = _mm256_setr_epi32(alpha->u.ntt32.q, 0, alpha->u.ntt32.q, 0, alpha->u.ntt32.q, 0, alpha->u.ntt32.q, 0);
    __m256i b_q2  = _mm256_setr_epi32((alpha->u.ntt32.q>>1), 0, (alpha->u.ntt32.q>>1), 0, (alpha->u.ntt32.q>>1), 0, (alpha->u.ntt32.q>>1), 0);
    __m256i p_qm1 = _mm256_setr_epi32(p->u.ntt32.q-1, 0, p->u.ntt32.q-1, 0, p->u.ntt32.q-1, 0, p->u.ntt32.q-1, 0);
    __m256i mask  = _mm256_setr_epi32(hexmask, 0, hexmask, 0, hexmask, 0, hexmask, 0);
    __m128i shift = _mm_setr_epi32(alpha->u.ntt32.k, alpha->u.ntt32.k, alpha->u.ntt32.k, alpha->u.ntt32.k);
    //__m256i p_m   = _mm256_setr_epi32(p->u.ntt32.m, 0, p->u.ntt32.m, 0, p->u.ntt32.m, 0, p->u.ntt32.m, 0);
    //__m256i p_q   = _mm256_setr_epi32(p->u.ntt32.q, 0, p->u.ntt32.q, 0, p->u.ntt32.q, 0, p->u.ntt32.q, 0);
    //__m128i p_k   = _mm_setr_epi32(p->u.ntt32.k, p->u.ntt32.k, p->u.ntt32.k, p->u.ntt32.k);
    __m256i one   = _mm256_setr_epi32(1, 0, 1, 0, 1, 0, 1, 0);

    for (i=0; i<k*n; i+=4) {
    	// Load the input as a vector
        __m128i int32in  = _mm_load_si128((__m128i*)(in + i));
        __m256i vec      = _mm256_cvtepi32_epi64(int32in);

        // Modular reduction of in by alpha_q
        __m256i b0       = _mm256_mul_epi32(b_m, vec);
        __m256i b1       = _mm256_srl_epi64(b0, shift);
        __m256i b2       = _mm256_castps_si256(
                               _mm256_and_ps(_mm256_castsi256_ps(mask),
                                             _mm256_castsi256_ps(b1)));
        __m256i t        = _mm256_mul_epi32(b2, b_q);
        __m256i c        = _mm256_sub_epi32(vec, t);
        __m256i cond     = _mm256_cmpgt_epi64(b_q, c);
        __m256i sub      = _mm256_castps_si256(
                               _mm256_andnot_ps(_mm256_castsi256_ps(cond),
                                                _mm256_castsi256_ps(b_q)));
        __m256i red      = _mm256_sub_epi32(c, sub);

        // if (red >= q/2) red -= q
        __m256i cond2    = _mm256_cmpgt_epi64(red, b_q2);
        __m256i sub2     = _mm256_castps_si256(
                               _mm256_and_ps(_mm256_castsi256_ps(cond2),
                                             _mm256_castsi256_ps(b_q)));
        __m256i a1_red   = _mm256_sub_epi32(red, sub2);
        __m256i a1       = _mm256_sub_epi32(vec, a1_red);

        // Divide a1 by alpha_q
        __m256i b3       = _mm256_mul_epi32(b_m, a1);
        __m256i b4       = _mm256_srl_epi64(b3, shift);
        __m256i b5       = _mm256_castps_si256(
                               _mm256_and_ps(_mm256_castsi256_ps(mask),
                                             _mm256_castsi256_ps(b4)));
        __m256i t2       = _mm256_mul_epi32(b5, b_q);
        __m256i c3       = _mm256_sub_epi32(a1, t2);
        __m256i cond4    = _mm256_cmpgt_epi64(b_q, c3);
        __m256i plus1    = _mm256_castps_si256(
                               _mm256_andnot_ps(_mm256_castsi256_ps(cond4),
                                                _mm256_castsi256_ps(one)));
        __m256i div      = _mm256_add_epi32(b5, plus1);

        // if ((q-1) == a1) { out = 0; } else out = div
        __m256i cond3    = _mm256_cmpeq_epi64(a1, p_qm1);
        __m256i result   = _mm256_castps_si256(
                               _mm256_andnot_ps(_mm256_castsi256_ps(cond3),
                                                _mm256_castsi256_ps(div)));

        // Write the result vector to output
        union u simd;
        simd.m = result;
        out[i  ] = simd.s[0];
        out[i+1] = simd.s[1];
        out[i+2] = simd.s[2];
        out[i+3] = simd.s[3];
    }
    

    return SC_FUNC_SUCCESS;
}
#else
SINT32 high_order_bits(UINT8 *out, const SINT32 *in, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha)
{
    size_t i;

    for (i=0; i<k*n; i++) {
        SINT32 r1;
        out[i] = round_alpha(in[i], &r1, alpha, p);
    }

    return SC_FUNC_SUCCESS;
}
#endif

SINT32 high_order_g_bits(SINT32 *out, const SINT32 *in, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha)
{
    size_t i;

    for (i=0; i<k*n; i++) {
        SINT32 r1;
        out[i] = round_alpha(in[i], &r1, alpha, p);
    }

    return SC_FUNC_SUCCESS;
}

void low_order_bits(SINT32 *out, const SINT32 *in, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha)
{
    size_t i;
    SINT32 r1;
    SINT32 q = p->u.ntt32.q;

    for (i=0; i<k*n; i++) {
        round_alpha(in[i], &r1, alpha, p);
        out[i] = (r1 < 0)? q + r1 : r1;
    }
}

void kyber_oracle_core(size_t n, size_t weight_of_c, SINT32 *c,
    size_t num_weight_bytes, const UINT8 *signs)
{
    size_t i, j, k, b;
    UINT8 mask = 1;

    // Initialise the first n - weight_of_c output coefficients
    for (i=0; i<n-weight_of_c; i++) {
        c[i] = 0;
    }

    // Distribute the weight_of_c non-zero bytes throughout the array
    for (i=n-weight_of_c, j=0, k=num_weight_bytes; i<n; i++, k++) {
        b = signs[k];
        while (b > i) {
            b >>= 1;
        }

        c[i] = c[b];
        c[b] = (signs[j] & mask)? -1 : 1;
        mask <<= 1;
        if (0 == mask) {
            mask = 1;
            j++;
        }
    }
}

// Create a random oracle output from a hash function
void kyber_oracle_csprng(safecrypto_t *sc, size_t n, UINT32 q, UINT32 q_bits, UINT32 weight_of_c,
    const UINT8 *md, size_t md_len, SINT32 *c)
{
    size_t num_weight_bytes = (weight_of_c + 7) >> 3;
    UINT8 signs[num_weight_bytes + weight_of_c] SC_DEFAULT_ALIGNED;

    // Use the message digest as an IV for a csprng
    prng_ctx_t *csprng = create_csprng(sc, md, md_len);

    // Create num_weight_bytes sign bits in an array of bytes
    prng_mem(csprng, signs, num_weight_bytes + weight_of_c);

    // Generate the output coefficients for the spare polynomial
    kyber_oracle_core(n, weight_of_c, c, num_weight_bytes, signs);

    // Destroy the CSPRNG
    prng_destroy(csprng);
}

// Create a random oracle output from a XOF
void kyber_oracle_xof(safecrypto_t *sc, size_t n, UINT32 q, UINT32 q_bits, UINT32 weight_of_c,
    const UINT8 *md, size_t md_len, SINT32 *c)
{
    size_t num_weight_bytes = (weight_of_c + 7) >> 3;
    UINT8 signs[num_weight_bytes + weight_of_c] SC_DEFAULT_ALIGNED;

    utils_crypto_xof_t *xof = utils_crypto_xof_create(SC_XOF_SHAKE128);

    // Initialise the XOF
    xof_init(xof);

    // Absorb the input data to configure the state
    xof_absorb(xof, md, md_len);
    xof_final(xof);

    // Create num_weight_bytes sign bits in an array of bytes
    xof_squeeze(xof, signs, num_weight_bytes + weight_of_c);

    // Generate the output coefficients for the spare polynomial
    kyber_oracle_core(n, weight_of_c, c, num_weight_bytes, signs);

    // Destroy the XOF
    utils_crypto_xof_destroy(xof);
}

SINT32 kyber_cpa_keygen(safecrypto_t *sc, SINT32 use_csprng_sam, SINT32 s_ntt_domain,
    UINT8 *rho, SINT32 *s, SINT32 *e, SINT32 *t, SINT32 *temp)
{
    size_t i, n, k;
    UINT32 q, q_bits, q_inv, q_norm, eta, dt_bits;
    prng_ctx_t *csprng = NULL;
    utils_crypto_xof_t *xof = sc->xof;

    // NOTE: the psuedorandom number r is provided as an input
    // and the public key is already decompressed

    n        = sc->kyber->params->n;
    k        = sc->kyber->params->k;
    q        = sc->kyber->params->q;
    q_bits   = sc->kyber->params->q_bits;
    q_inv    = sc->kyber->params->q_inv;
    q_norm   = sc->kyber->params->q_norm;
    eta      = sc->kyber->params->eta;
    dt_bits  = sc->kyber->params->d_t;

    // Generate a 256 bit random byte array to be used to seed a CSPRNG.
    prng_mem(sc->prng_ctx[0], rho, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "rho", rho, 32);

    // Generate s1 and s2 from a uniform random distribution with values of
    // -eta to +eta inclusive.
    binomial_rand_sample_csprng(sc->prng_ctx[0], q, eta, s, n, k);
    binomial_rand_sample_csprng(sc->prng_ctx[0], q, eta, e, n, k);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "s = Sam(sigma)", s, k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "e = Sam(sigma)", e, k * n);

    const SINT16 *ntt_w = sc->kyber->params->w;
    const SINT16 *ntt_r = sc->kyber->params->r;
    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;

    // Matrix multiplication of A and s1, where A is uniform random
    // sampled as a k x l matrix of ring polynomials with n coefficients.
    // The kxl A matrix is multiplied by the lx1 s1 matrix to form a kx1
    // matrix to which s2 is added.
    if (use_csprng_sam) {
        // Generate a CSPRNG and seed it with rho as entropy.
        csprng = create_csprng(sc, rho, 32);

        create_rand_product_16_csprng(csprng,
            q, q_bits, t, s, n, k, k, temp+k*n, temp,
            s_ntt_domain? RND_PRD_ENABLE_OVERWRITE : RND_PRD_DISABLE_OVERWRITE,
            RND_PRD_NOT_TRANSPOSED,
            ntt_w, ntt_r, sc_poly, sc_ntt, ntt);
    }
    else {
        xof_init(xof);
        xof_absorb(xof, rho, 32);
        xof_final(xof);

        create_rand_product_16_xof(xof,
            q, q_bits, t, s, n, k, k, temp+k*n, temp,
            s_ntt_domain? RND_PRD_ENABLE_OVERWRITE : RND_PRD_DISABLE_OVERWRITE,
            RND_PRD_NOT_TRANSPOSED,
            ntt_w, ntt_r, sc_poly, sc_ntt, ntt);
    }
    sc_poly->add_32(t, k*n, t, e);
    sc_ntt->center_32(t, k*n, ntt);
    mlwe_compress(t, n, k, dt_bits, q, q_inv, q_norm);
    mlwe_decompress(t, n, k, dt_bits, q);
    sc_ntt->normalize_32(t, k*n, ntt);
    sc_ntt->center_32(s, k*n, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t = As + e", t, k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "NTT(s)", s, k * n);

    if (use_csprng_sam) {
        // Destroy the CSPRNG
        prng_destroy(csprng);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 kyber_cpa_enc(safecrypto_t *sc, SINT32 use_csprng_sam, SINT32 *u, SINT32 *v, const SINT32 *t,
    SINT32 t_ntt_domain, const UINT8 *rho,
    size_t n, size_t k, const UINT8 *m, const UINT8 *r, SINT32 *prealloc)
{
    size_t i, j;
    UINT32 q, q2, q_bits, q_inv, q_norm, eta, d_u, d_v;
    SINT32 *c, *temp, *r_eta, *e1, *e2;
    prng_ctx_t *csprng;
    utils_crypto_xof_t *xof = sc->xof;

    // NOTE: the psuedorandom number r is provided as an input
    // and the public key is already decompressed

    q        = sc->kyber->params->q;
    q2       = q >> 1;
    q_bits   = sc->kyber->params->q_bits;
    q_inv    = sc->kyber->params->q_inv;
    q_norm   = sc->kyber->params->q_norm;
    eta      = sc->kyber->params->eta;
    d_u      = sc->kyber->params->d_u;
    d_v      = sc->kyber->params->d_v;

    r_eta = prealloc;
    e1    = r_eta + k * n;
    e2    = e1 + k * n;
    temp  = e2 + n;
    c     = temp + k*n;

    SC_PRINT_DEBUG(sc, "KYBER CPA ENCRYPTION");
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "rho", rho, 32);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "r", r, 32);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "t", t, k * n);

    const SINT16 *ntt_w = sc->kyber->params->w;
    const SINT16 *ntt_r = sc->kyber->params->r;
    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;

    // Generate the small matrices r_eta, e1 and e2
    if (use_csprng_sam) {
        csprng = create_csprng(sc, r, 32);
        if (NULL == csprng) {
            return SC_FUNC_FAILURE;
        }

        binomial_rand_sample_csprng(csprng, q, eta, r_eta, n, k);
        binomial_rand_sample_csprng(csprng, q, eta, e1, n, k);
        binomial_rand_sample_csprng(csprng, q, eta, e2, n, 1);

        prng_destroy(csprng);
    }
    else {
        binomial_rand_sample_xof(xof, q, eta, r_eta, n, k);
        binomial_rand_sample_xof(xof, q, eta, e1, n, k);
        binomial_rand_sample_xof(xof, q, eta, e2, n, 1);
    }
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "r_eta = Sam(r)", r_eta, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "e1 = Sam(r)", e1, k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "e2 = Sam(r)", e2, n);

    // Generate a random kxk matrix A of n-element rings, multiply by r_eta
    // and add e1
    if (use_csprng_sam) {
        // Generate a CSPRNG and seed it with rho as entropy.
        csprng = create_csprng(sc, rho, 32);
        if (NULL == csprng) {
            return SC_FUNC_FAILURE;
        }

        create_rand_product_16_csprng(csprng, q, q_bits, u, r_eta,
            n, k, k, c, temp, RND_PRD_ENABLE_OVERWRITE, RND_PRD_TRANSPOSED,
            ntt_w, ntt_r, sc_poly, sc_ntt, ntt);

        prng_destroy(csprng);
    }
    else {
        xof_init(xof);
        xof_absorb(xof, rho, 32);
        xof_final(xof);

        create_rand_product_16_xof(xof, q, q_bits, u, r_eta,
            n, k, k, c, temp, RND_PRD_ENABLE_OVERWRITE, RND_PRD_TRANSPOSED,
            ntt_w, ntt_r, sc_poly, sc_ntt, ntt);
    }
    sc_poly->add_32(u, k*n, u, e1);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "NTT(r)", r_eta, k * n);

    // Calculate the sum of the products of the k n-element rings of t and r
    for (i=0; i<k; i++) {
        if (t_ntt_domain) {
            sc_ntt->mul_32_pointwise(v + i*n, ntt, r_eta + i*n, t + i*n);
        }
        else {
            sc_ntt->fwd_ntt_32_16(v + i*n, ntt, t + i*n, ntt_w);
            sc_ntt->mul_32_pointwise(v + i*n, ntt, r_eta + i*n, v + i*n);
        }
        if (0 != i) {
            sc_poly->add_32(v, n, v + i*n, v);
            sc_ntt->normalize_32(v, n, ntt);
        }
    }
    sc_ntt->inv_ntt_32_16(v, ntt, v, ntt_w, ntt_r);
    //sc_ntt->center_32(v, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "tT.r", v, n);
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, 32);

    // Map the message to q/2 and add to v
    for (i=0, j=0; i<n>>3; i++, j+=8) {
        v[j  ] += (m[i] & 0x80)? q2 : 0;
        v[j+1] += (m[i] & 0x40)? q2 : 0;
        v[j+2] += (m[i] & 0x20)? q2 : 0;
        v[j+3] += (m[i] & 0x10)? q2 : 0;
        v[j+4] += (m[i] & 0x08)? q2 : 0;
        v[j+5] += (m[i] & 0x04)? q2 : 0;
        v[j+6] += (m[i] & 0x02)? q2 : 0;
        v[j+7] += (m[i] & 0x01)? q2 : 0;
    }

    // Generate e2 and add to v to form the final uncompressed v
    sc_poly->add_32(v, n, v, e2);
    //sc_ntt->center_32(v, ntt);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "u = AT.r + e1", u, k * n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v = t^Tr + [q/2].m + e2", v, n);

    // Compress the two encryption variables
    mlwe_compress(u, n, k, d_u, q, q_inv, q_norm);
    mlwe_compress(v, n, 1, d_v, q, q_inv, q_norm);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Compress(u)", u, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Compress(v)", v, n);

    // Reset the memory to zero
    SC_MEMZERO(prealloc, (3 * k + 2) * n * sizeof(SINT32));

    return SC_FUNC_SUCCESS;
}

static UINT32 flipabs(UINT32 x, UINT32 q)
{
  SINT16 r, m;
  r = x;

  r = r - (q >> 1);
  m = r >> 15;
  return (r + m) ^ m;
}

SINT32 kyber_cpa_dec(safecrypto_t *sc, SINT32 *u, SINT32 *v,
    SINT32 s_ntt_domain, const SINT32 *s,
    size_t n, size_t k, UINT8 *m)
{
    size_t i, j;
    UINT32 q, q_inv, q_norm, d_u, d_v;

    SC_PRINT_DEBUG(sc, "KYBER CPA DECRYPTION\n");
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, (s_ntt_domain)? "NTT(s)" : "s", s, k*n);

    q        = sc->kyber->params->q;
    q_inv    = sc->kyber->params->q_inv;
    q_norm   = sc->kyber->params->q_norm;
    d_u      = sc->kyber->params->d_u;
    d_v      = sc->kyber->params->d_v;

    const SINT16 *ntt_w = sc->kyber->params->w;
    const SINT16 *ntt_r = sc->kyber->params->r;
    const utils_arith_poly_t *sc_poly = sc->sc_poly;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->kyber->ntt;

    // Expand the transmitted u and v coefficients 
    mlwe_decompress(u, n, k, d_u, q);
    mlwe_decompress(v, n, 1, d_v, q);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Decompress(u)", u, k*n);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Decompress(v)", v, n);

    // Multiply the transpose of s by u and subtract from v
    for (i=0; i<k; i++) {
        sc_ntt->fwd_ntt_32_16(u + i*n, ntt, u + i*n, ntt_w);
        if (s_ntt_domain) {
            sc_ntt->mul_32_pointwise(u + i*n, ntt, s + i*n, u + i*n);
        }
        else {
            SINT32 block[n] SC_DEFAULT_ALIGNED;
            sc_ntt->fwd_ntt_32_16(block, ntt, s + i*n, ntt_w);
            sc_ntt->mul_32_pointwise(u + i*n, ntt, block, u + i*n);
        }
        if (0 != i) {
            sc_poly->add_32(u, n, u + i*n, u);
        }
    }
    sc_ntt->inv_ntt_32_16(u, ntt, u, ntt_w, ntt_r);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "sT.u", u, n);
    sc_poly->sub_32(v, n, v, u);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "v - sT.u", v, n);

    // Perform rounding of the output message
    mlwe_compress(v, n, 1, 1, q, q_inv, q_norm);
    SC_PRINT_1D_INT32(sc, SC_LEVEL_DEBUG, "Compress(v)", v, n);

    // Generate the output message bytes
    for (i=0, j=0; i<32; i++) {
        m[i]  = v[j++] << 7;
        m[i] |= v[j++] << 6;
        m[i] |= v[j++] << 5;
        m[i] |= v[j++] << 4;
        m[i] |= v[j++] << 3;
        m[i] |= v[j++] << 2;
        m[i] |= v[j++] << 1;
        m[i] |= v[j++];
    }
    SC_PRINT_1D_UINT8_HEX(sc, SC_LEVEL_DEBUG, "m", m, 32);

    return SC_FUNC_SUCCESS;
}
