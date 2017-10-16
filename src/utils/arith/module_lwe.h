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
#include "utils/arith/arith.h"
#include "utils/arith/ntt.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/xof.h"
#include <string.h>


#define MODULE_LWE_ENC_CSPRNG_ENABLED   1
#define MODULE_LWE_ENC_CSPRNG_DISABLED  0


#define RND_PRD_DISABLE_OVERWRITE  0
#define RND_PRD_ENABLE_OVERWRITE   1
#define RND_PRD_NOT_TRANSPOSED     0
#define RND_PRD_TRANSPOSED         1

/// Compute the NTT of the input to create_rand_product() as an initial step
#define MODULE_LWE_STORE_NTT_MATRIX_INPUT


#define MODULE_LWE_FP_REDUCTION(_r,_x,_q,_q_inv) \
    {DOUBLE _temp = (DOUBLE) _x * _inv_q; \
    _r = _x - _q * (SINT64) _temp;}

#define MODULE_LWE_FP_DIVISION(_r,_x,_q,_q_inv) \
    {DOUBLE _temp = (DOUBLE) _x * _inv_q; \
    _r = (SINT64) _temp;}

/// A preprocessor macro for barrett reduction:
///     r = x - q*((x*m) >> k)
///     if (q < r) r -= q
#define MODULE_LWE_BARRETT_REDUCTION(_r,_x,_k,_m,_q) \
    {SINT64 _t, _c; \
    _t = ((SINT64)(_x) * (SINT64)(_m)) >> (_k); \
    _c = (_x) - _t * (_q); \
    if ((_q) <= _c) \
        _c -= (_q); \
    _r = (SINT32) _c;}

#define MODULE_LWE_BARRETT_DIVISION(_r,_x,_k,_m,_q) \
    {SINT64 _t, _c; \
    _t = ((SINT64)(_x) * (SINT64)(_m)) >> (_k); \
    _c = (_x) - _t * (_q); \
    if ((_q) <= _c) \
        _t++; \
    _r = (SINT32) _t;}


SC_STRUCT_PACK_START
typedef struct kyber_set_t {
    const UINT32      set;
    safecrypto_hash_e oracle_hash;
    const UINT32      q;
    const UINT32      q_bits;
    const UINT32      q_inv;
    const UINT32      q_norm;
    const UINT32      n;
    const UINT32      n_bits;
    const UINT32      k;
    const UINT32      eta;
    const UINT32      eta_bits;
    const UINT32      d_u;
    const UINT32      d_v;
    const UINT32      d_t;
    const DOUBLE      delta;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT16           *w;
    SINT16           *r;
#else
    const SINT16     *w;
    const SINT16     *r;
#endif
} SC_STRUCT_PACKED kyber_set_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct kyber_cfg_t {
    kyber_set_t              *params;
    safecrypto_ntt_e          ntt_optimisation;
    ntt_params_t              ntt;
    sc_entropy_type_e         entropy;
    safecrypto_hash_e         oracle_hash;
} SC_STRUCT_PACKED kyber_cfg_t;
SC_STRUCT_PACK_END


typedef void (*uniform_random_ring_q)(void *, SINT32 *, size_t, SINT32, UINT32);


SC_INLINE UINT32 round_alpha(const UINT32 a, SINT32 *a0, const ntt_params_t *alpha, const ntt_params_t *p)
{
    UINT32 a1;
    SINT32 q       = p->u.ntt32.q;
    SINT32 alpha_q = alpha->u.ntt32.q;
    SINT32 alpha_m = alpha->u.ntt32.m;
    SINT32 alpha_k = alpha->u.ntt32.k;

    // *a0 = temp mod alpha_q
    MODULE_LWE_BARRETT_REDUCTION(*a0, a, alpha_k, alpha_m, alpha_q);
    if (*a0 >= (alpha_q >> 1)) {
        *a0 -= alpha_q;
    }
    a1 = a - *a0;
    if (a1 == (q - 1)) {
        a1 = 0;
        *a0 -= 1;
    }
    else {
        // a1 = a1 / alpha_q;
        MODULE_LWE_BARRETT_DIVISION(a1, a1, alpha_k, alpha_m, alpha_q);
    }

    return a1;
}

void mlwe_compress(SINT32 *inout, size_t n, size_t k, UINT32 d,
    UINT32 q, UINT32 q_inv, SINT32 q_norm);

void mlwe_decompress(SINT32 *inout, size_t n, size_t k, UINT32 d, UINT32 q);

void pwr_2_round(SINT32 *out, const SINT32 *in, size_t n, size_t k, UINT32 d);

void decompose(SINT32 *t1, SINT32 *t0, const SINT32 *in, size_t n,
    size_t k, UINT32 alpha, SINT32 q);

void decompose_g(SINT32 *t1, SINT32 *t0, const SINT32 *in, size_t n,
    size_t k, const ntt_params_t *alpha, SINT32 q);

void uniform_rand_sample_csprng(prng_ctx_t *csprng, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m);

void uniform_rand_sample_small_csprng(prng_ctx_t *csprng, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m);

void uniform_rand_sample_xof(utils_crypto_xof_t *xof, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m);

void uniform_rand_sample_small_xof(utils_crypto_xof_t *xof, SINT32 q, SINT32 eta, UINT32 bits,
    SINT32 *s, size_t n, size_t m);

void binomial_rand_sample_csprng(prng_ctx_t *csprng, SINT32 q, SINT32 eta,
    SINT32 *s, size_t n, size_t m);

void binomial_rand_sample_xof(utils_crypto_xof_t *xof, SINT32 q, SINT32 eta,
    SINT32 *s, size_t n, size_t m);

void uniform_random_ring_q_csprng(prng_ctx_t *csprng, SINT32 *a, size_t n, SINT32 q, UINT32 q_bits);

void uniform_random_ring_q_xof(utils_crypto_xof_t *xof, SINT32 *a, size_t n, SINT32 q, UINT32 q_bits);

void create_rand_product_32_csprng(prng_ctx_t *csprng,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT32 *ntt_w, const SINT32 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt);

void create_rand_product_16_csprng(prng_ctx_t *csprng,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT16 *ntt_w, const SINT16 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt);

void create_rand_product_32_xof(utils_crypto_xof_t *xof,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT32 *ntt_w, const SINT32 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt);

void create_rand_product_16_xof(utils_crypto_xof_t *xof,
    UINT32 q, UINT32 q_bits, SINT32 *t, SINT32 *y, size_t n,
    size_t k, size_t l, SINT32 *c, SINT32 *temp, SINT32 ntt_overwrite, SINT32 transpose,
    const SINT16 *ntt_w, const SINT16 *ntt_r,
    const utils_arith_poly_t *sc_poly, const utils_arith_ntt_t *sc_ntt,
    ntt_params_t *ntt);

prng_ctx_t * create_csprng(safecrypto_t *sc, const UINT8 *r, size_t len);

UINT32 max_singular_value(const SINT32 *s1, size_t l,
    const SINT32 *s2, size_t k, size_t n);

SINT32 high_order_bits(UINT8 *out, const SINT32 *in, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha);

SINT32 high_order_g_bits(SINT32 *out, const SINT32 *in, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha);

void low_order_bits(SINT32 *out, const SINT32 *in, size_t n,
    size_t k, ntt_params_t *p, ntt_params_t *alpha);

void kyber_oracle_core(size_t n, size_t weight_of_c, SINT32 *c,
    size_t num_weight_bytes, const UINT8 *signs);

// Use a random oracle output from a message digest
void kyber_oracle_csprng(safecrypto_t *sc, size_t n, UINT32 q, UINT32 q_bits, UINT32 weight_of_c,
    const UINT8 *md, size_t md_len, SINT32 *c);
void kyber_oracle_xof(safecrypto_t *sc, size_t n, UINT32 q, UINT32 q_bits, UINT32 weight_of_c,
    const UINT8 *md, size_t md_len, SINT32 *c);

SINT32 kyber_cpa_keygen(safecrypto_t *sc, SINT32 use_csprng_sam, SINT32 s_ntt_domain,
    UINT8 *rho, SINT32 *s, SINT32 *e, SINT32 *t, SINT32 *temp);
SINT32 kyber_cpa_enc(safecrypto_t *sc,  SINT32 use_csprng_sam, SINT32 *u, SINT32 *v, const SINT32 *t,
    SINT32 t_ntt_domain, const UINT8 *rho,
    size_t n, size_t k, const UINT8 *m, const UINT8 *r, SINT32 *prealloc);
SINT32 kyber_cpa_dec(safecrypto_t *sc, SINT32 *u, SINT32 *v, SINT32 s_ntt_domain, const SINT32 *s,
    size_t n, size_t k, UINT8 *m);
