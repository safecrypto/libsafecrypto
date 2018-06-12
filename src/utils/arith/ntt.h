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
#include "utils/arith/ntt_barrett.h"
//#include "utils/arith/ntt_barrett_rev.h"
#include "utils/arith/ntt_fp.h"
//#include "utils/arith/ntt_fp_rev.h"
#include "utils/arith/ntt_reference.h"
//#include "utils/arith/ntt_reference_rev.h"
#ifdef HAVE_AVX2
#include "utils/arith/ntt_avx.h"
//#include "utils/arith/ntt_avx_rev.h"
#endif
#include "utils/arith/ntt_7681.h"
//#include "utils/arith/ntt_7681_rev.h"
#include "utils/arith/ntt_8380417.h"
//#include "utils/arith/ntt_8380417_rev.h"
//#include "utils/arith/ntt_16813057.h"
//#include "utils/arith/ntt_134348801.h"
#ifndef USE_RUNTIME_NTT_TABLES
#include "utils/arith/ntt_tables.h"
#endif
#include "utils/arith/roots_of_unity.h"
#include "utils/arith/limb.h"
#include <string.h>

#if !defined(CONSTRAINED_RAM) && !defined(CONSTRAINED_ROM)
#define LUT_BASED_INVERSE_SHUFFLE
#endif


/// 16-bit specific modular reduction parameters for NTT
SC_STRUCT_PACK_START
typedef struct ntt16_params_t {
    SINT16 q;
    UINT16 q_inv;
    SINT16 m;
    SINT16 k;
} SC_STRUCT_PACKED ntt16_params_t;
SC_STRUCT_PACK_END

/// 32-bit specific modular reduction parameters for NTT
SC_STRUCT_PACK_START
typedef struct ntt32_params_t {
    SINT32 q;
    UINT32 q_inv;
    SINT32 m;
    SINT32 k;
} SC_STRUCT_PACKED ntt32_params_t;
SC_STRUCT_PACK_END

/// 64-bit specific modular reduction parameters for NTT
SC_STRUCT_PACK_START
typedef struct ntt64_params_t {
    SINT64 q;
    UINT64 q_inv;
    SINT64 m;
    SINT64 k;
} SC_STRUCT_PACKED ntt64_params_t;
SC_STRUCT_PACK_END

/// Limb-type modular reduction parameters for NTT
SC_STRUCT_PACK_START
typedef struct nttlimb_params_t {
    sc_slimb_t q;
    sc_ulimb_t q_inv;
    sc_slimb_t m;
    sc_slimb_t k;
} SC_STRUCT_PACKED nttlimb_params_t;
SC_STRUCT_PACK_END

/// A struct used to store the NTT modulo reduction parameters
SC_STRUCT_PACK_START
typedef struct ntt_params_t {
    DOUBLE q_dbl;
    DOUBLE inv_q_dbl;
    FLOAT inv_q_flt;
	size_t n;
    union ntt_u {
        nttlimb_params_t nttlimb;
        ntt64_params_t ntt64;
        ntt32_params_t ntt32;
        ntt16_params_t ntt16;
    } u;
} SC_STRUCT_PACKED ntt_params_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef enum safecrypto_ntt {
    SC_NTT_REFERENCE = 0,
    SC_NTT_BARRETT,
    SC_NTT_FLOATING_POINT,
    SC_NTT_AVX,
    SC_NTT_SOLINAS_7681,
    SC_NTT_SOLINAS_8380417,
    SC_NTT_SOLINAS_16813057,
    SC_NTT_SOLINAS_134348801,
    SC_NTT_REFERENCE_REV,
    SC_NTT_BARRETT_REV,
    SC_NTT_FLOATING_POINT_REV,
    SC_NTT_AVX_REV,
    SC_NTT_SOLINAS_7681_REV,
    SC_NTT_SOLINAS_8380417_REV,
    SC_NTT_SOLINAS_16813057_REV,
    SC_NTT_SOLINAS_134348801_REV,
} SC_STRUCT_PACKED safecrypto_ntt_e;
SC_STRUCT_PACK_END


typedef SINT16 (*ntt16_modn)(SINT16, const ntt_params_t *);
typedef SINT16 (*ntt16_muln)(SINT16, SINT16, const ntt_params_t *);
typedef SINT16 (*ntt16_sqrn)(SINT16, const ntt_params_t *);
typedef void (*ntt16_mult_sparse)(SINT16 *, size_t, UINT16, const SINT16 *, const SINT16 *);
typedef void (*ntt16_mult_pointwise)(SINT16 *, const ntt_params_t *, const SINT16 *, const SINT16 *);
typedef void (*ntt16_mult_scalar)(SINT16 *, const ntt_params_t*, const SINT16 *, SINT16);
typedef void (*ntt16_flip_invert)(SINT16 *, const ntt_params_t*);
typedef void (*ntt16_fft)(SINT16 *, const ntt_params_t *, const SINT16 *);
typedef void (*ntt16_large_fft)(SINT16 *, const ntt_params_t *, const SINT16 *);
typedef SINT32 (*ntt16_pwr)(SINT16, SINT16, const ntt_params_t *);
typedef SINT32 (*ntt16_invert)(SINT16 *, const ntt_params_t *, size_t);
typedef SINT32 (*ntt16_div)(SINT16 *, const SINT16 *, const ntt_params_t *, size_t);
typedef void (*ntt16_flip)(SINT16 *, const ntt_params_t*);
typedef void (*ntt16_center)(SINT16 *, size_t, const ntt_params_t*);
typedef void (*ntt16_normalize)(SINT16 *, size_t, const ntt_params_t*);
typedef void (*ntt16_fwd_ntt)(SINT16 *, const ntt_params_t *, const SINT16 *, const SINT16 *);
typedef void (*ntt16_inv_ntt)(SINT16 *, const ntt_params_t *, const SINT16 *, const SINT16 *, const SINT16 *);
typedef void (*ntt16_large_fwd_ntt)(SINT16 *, const ntt_params_t *, const SINT16 *, const SINT16 *);
typedef void (*ntt16_large_inv_ntt)(SINT16 *, const ntt_params_t *, const SINT16 *, const SINT16 *, const SINT16 *);

typedef SINT32 (*ntt32_modn)(SINT32, const ntt_params_t *);
typedef SINT32 (*ntt32_muln)(SINT32, SINT32, const ntt_params_t *);
typedef SINT32 (*ntt32_sqrn)(SINT32, const ntt_params_t *);
typedef void (*ntt32_mult_sparse_32)(SINT32 *, size_t, UINT16,
    const SINT32 *, const SINT32 *);
typedef void (*ntt32_mult_sparse_16)(SINT32 *, size_t, UINT16,
    const SINT16 *, const SINT32 *);
typedef void (*ntt32_mult_pointwise)(SINT32 *, const ntt_params_t*,
    const SINT32 *, const SINT32 *);
typedef void (*ntt32_mult_pointwise_16)(SINT32 *, const ntt_params_t*,
    const SINT32 *, const SINT16 *);
typedef void (*ntt32_mult_scalar)(SINT32 *, const ntt_params_t*,
    const SINT32 *, SINT32);
typedef void (*ntt32_flip_invert)(SINT32 *, const ntt_params_t*);
typedef void (*ntt32_fft_32)(SINT32 *, const ntt_params_t*, const SINT32 *);
typedef void (*ntt32_fft_16)(SINT32 *, const ntt_params_t*, const SINT16 *);
typedef SINT32 (*ntt32_pwr)(SINT32, SINT32, const ntt_params_t*);
typedef SINT32 (*ntt32_invert)(SINT32 *v, const ntt_params_t *p, size_t n);
typedef SINT32 (*ntt32_div)(SINT32 *num, const SINT32 *den, const ntt_params_t *p, size_t n);
typedef void (*ntt32_flip)(SINT32 *, const ntt_params_t*);
typedef void (*ntt32_center)(SINT32 *, size_t, const ntt_params_t*);
typedef void (*ntt32_normalize)(SINT32 *, size_t, const ntt_params_t*);
typedef void (*ntt32_fwd_ntt_32)(SINT32 *, const ntt_params_t *,
    const SINT32 *, const SINT32 *);
typedef void (*ntt32_inv_ntt_32)(SINT32 *, const ntt_params_t *,
    const SINT32 *, const SINT32 *, const SINT32 *);
typedef void (*ntt32_fwd_ntt_16)(SINT32 *, const ntt_params_t *,
    const SINT32 *, const SINT16 *);
typedef void (*ntt32_inv_ntt_16)(SINT32 *, const ntt_params_t *,
    const SINT32 *, const SINT16 *, const SINT16 *);

typedef sc_slimb_t (*ntt_modn)(sc_slimb_t, const ntt_params_t *);
typedef sc_slimb_t (*ntt_muln)(sc_slimb_t, sc_slimb_t, const ntt_params_t *);
typedef sc_slimb_t (*ntt_sqrn)(sc_slimb_t, const ntt_params_t *);
typedef void (*ntt_mult_sparse_32)(sc_slimb_t *, size_t, UINT16,
    const SINT32 *, const sc_slimb_t *);
typedef void (*ntt_mult_sparse_16)(sc_slimb_t *, size_t, UINT16,
    const SINT16 *, const sc_slimb_t *);
typedef void (*ntt_mult_pointwise)(sc_slimb_t *, const ntt_params_t*,
    const sc_slimb_t *, const sc_slimb_t *);
typedef void (*ntt_mult_pointwise_32)(sc_slimb_t *, const ntt_params_t*,
    const sc_slimb_t *, const SINT32 *);
typedef void (*ntt_mult_pointwise_16)(sc_slimb_t *, const ntt_params_t*,
    const sc_slimb_t *, const SINT16 *);
typedef void (*ntt_mult_scalar)(sc_slimb_t *, const ntt_params_t*,
    const sc_slimb_t *, sc_slimb_t);
typedef void (*ntt_flip_invert)(sc_slimb_t *, const ntt_params_t*);
typedef void (*ntt_fft)(sc_slimb_t *, const ntt_params_t*, const sc_slimb_t *);
typedef void (*ntt_fft_32)(sc_slimb_t *, const ntt_params_t*, const SINT32 *);
typedef void (*ntt_fft_16)(sc_slimb_t *, const ntt_params_t*, const SINT16 *);
typedef sc_slimb_t (*ntt_pwr)(sc_slimb_t, sc_slimb_t, const ntt_params_t*);
typedef SINT32 (*ntt_invert)(sc_slimb_t *v, const ntt_params_t *p, size_t n);
typedef SINT32 (*ntt_div)(sc_slimb_t *num, const sc_slimb_t *den, const ntt_params_t *p, size_t n);
typedef void (*ntt_flip)(sc_slimb_t *, const ntt_params_t*);
typedef void (*ntt_center)(sc_slimb_t *, size_t, const ntt_params_t*);
typedef void (*ntt_normalize)(sc_slimb_t *, size_t, const ntt_params_t*);
typedef void (*ntt_fwd_ntt)(sc_slimb_t *, const ntt_params_t *,
    const sc_slimb_t *, const sc_slimb_t *);
typedef void (*ntt_inv_ntt)(sc_slimb_t *, const ntt_params_t *,
    const sc_slimb_t *, const sc_slimb_t *, const sc_slimb_t *);
typedef void (*ntt_fwd_ntt_32)(sc_slimb_t *, const ntt_params_t *,
    const sc_slimb_t *, const SINT32 *);
typedef void (*ntt_inv_ntt_32)(sc_slimb_t *, const ntt_params_t *,
    const sc_slimb_t *, const SINT32 *, const SINT32 *);
typedef void (*ntt_fwd_ntt_16)(sc_slimb_t *, const ntt_params_t *,
    const sc_slimb_t *, const SINT16 *);
typedef void (*ntt_inv_ntt_16)(sc_slimb_t *, const ntt_params_t *,
    const sc_slimb_t *, const SINT16 *, const SINT16 *);

SC_STRUCT_PACK_START
typedef struct _utils_arith_ntt {
    ntt16_modn              modn_16;
    ntt16_muln              muln_16;
    ntt16_sqrn              sqrn_16;
    ntt16_mult_sparse       mul_16_sparse;
    ntt16_mult_pointwise    mul_16_pointwise;
    ntt16_mult_scalar       mul_16_scalar;
    ntt16_fft               fft_16;
    ntt16_large_fft         large_fft_16;
    ntt16_pwr               pwr_16;
    ntt16_invert            invert_16;
    ntt16_div               div_16;
    ntt16_flip              flip_16;
    ntt16_center            center_16;
    ntt16_normalize         normalize_16;
    ntt16_fwd_ntt           fwd_ntt_16;
    ntt16_inv_ntt           inv_ntt_16;
    ntt16_large_fwd_ntt     fwd_ntt_16_large;
    ntt16_large_inv_ntt     inv_ntt_16_large;

    ntt32_modn              modn_32;
    ntt32_muln              muln_32;
    ntt32_sqrn              sqrn_32;
    ntt32_mult_sparse_32    mul_32_sparse;
    ntt32_mult_sparse_16    mul_32_sparse_16;
    ntt32_mult_pointwise    mul_32_pointwise;
    ntt32_mult_pointwise_16 mul_32_pointwise_16;
    ntt32_mult_scalar       mul_32_scalar;
    ntt32_fft_32            fft_32_32;
    ntt32_fft_32            fft_32_32_large;
    ntt32_fft_16            fft_32_16;
    ntt32_fft_16            fft_32_16_large;
    ntt32_pwr               pwr_32;
    ntt32_invert            invert_32;
    ntt32_div               div_32;
    ntt32_flip              flip_32;
    ntt32_center            center_32;
    ntt32_normalize         normalize_32;
    ntt32_fwd_ntt_32        fwd_ntt_32_32;
    ntt32_inv_ntt_32        inv_ntt_32_32;
    ntt32_fwd_ntt_32        fwd_ntt_32_32_large;
    ntt32_inv_ntt_32        inv_ntt_32_32_large;
    ntt32_fwd_ntt_16        fwd_ntt_32_16;
    ntt32_inv_ntt_16        inv_ntt_32_16;
    ntt32_fwd_ntt_16        fwd_ntt_32_16_large;
    ntt32_inv_ntt_16        inv_ntt_32_16_large;

    ntt_modn                modn_limb;
    ntt_muln                muln_limb;
    ntt_sqrn                sqrn_limb;
    ntt_mult_sparse_32      mul_limb_sparse;
    ntt_mult_sparse_16      mul_limb_sparse_16;
    ntt_mult_pointwise      mul_limb_pointwise;
    ntt_mult_pointwise_32   mul_limb_pointwise_32;
    ntt_mult_pointwise_16   mul_limb_pointwise_16;
    ntt_mult_scalar         mul_limb_scalar;
    ntt_fft                 fft_limb;
    ntt_fft                 fft_limb_large;
    ntt_fft_32              fft_limb_32;
    ntt_fft_32              fft_limb_32_large;
    ntt_fft_16              fft_limb_16;
    ntt_fft_16              fft_limb_16_large;
    ntt_pwr                 pwr_limb;
    ntt_invert              invert_limb;
    ntt_div                 div_limb;
    ntt_flip                flip_limb;
    ntt_center              center_limb;
    ntt_normalize           normalize_limb;
    ntt_fwd_ntt             fwd_ntt_limb;
    ntt_inv_ntt             inv_ntt_limb;
    ntt_fwd_ntt             fwd_ntt_limb_large;
    ntt_inv_ntt             inv_ntt_limb_large;
    ntt_fwd_ntt_32          fwd_ntt_limb_32;
    ntt_inv_ntt_32          inv_ntt_limb_32;
    ntt_fwd_ntt_32          fwd_ntt_limb_32_large;
    ntt_inv_ntt_32          inv_ntt_limb_32_large;
    ntt_fwd_ntt_16          fwd_ntt_limb_16;
    ntt_inv_ntt_16          inv_ntt_limb_16;
    ntt_fwd_ntt_16          fwd_ntt_limb_16_large;
    ntt_inv_ntt_16          inv_ntt_limb_16_large;
} SC_STRUCT_PACKED utils_arith_ntt_t;
SC_STRUCT_PACK_END

extern const utils_arith_ntt_t *ntt_table;

void ntt16_mult_scalar_generic(SINT16 *v, const ntt_params_t *p,
    const SINT16 *t, SINT16 c);
void ntt16_mult_sparse_generic(SINT16 *v, size_t n, UINT16 omega,
    const SINT16 *t, const SINT16 *u);
void ntt16_flip_generic(SINT16 *v, const ntt_params_t *p);
SINT16 invert_16(SINT16 *u, const ntt_params_t *ntt, size_t n);
void inverse_shuffle_16(SINT16 *v, size_t n);

SINT32 barrett_reduction_32(SINT64 a, SINT32 m, SINT32 k, SINT32 q);
void ntt32_mult_scalar_generic(SINT32 *v, const ntt_params_t *p,
    const SINT32 *t, SINT32 c);
void ntt32_mult_sparse_32_generic(SINT32 *v, size_t n, UINT16 omega,
    const SINT32 *t, const SINT32 *u);
void ntt32_mult_sparse_16_generic(SINT32 *v, size_t n, UINT16 omega,
    const SINT16 *t, const SINT32 *u);
void ntt32_flip_generic(SINT32 *v, const ntt_params_t *p);
SINT32 invert_32(SINT32 *u, const ntt_params_t *ntt, size_t n);
void inverse_shuffle_32(SINT32 *v, size_t n);

void ntt_mult_scalar_generic(sc_slimb_t *v, const ntt_params_t *p,
    const sc_slimb_t *t, sc_slimb_t c);
void ntt_mult_sparse_limb_generic(sc_slimb_t *v, size_t n, UINT16 omega,
    const sc_slimb_t *t, const sc_slimb_t *u);
void ntt_mult_sparse_32_generic(sc_slimb_t *v, size_t n, UINT16 omega,
    const SINT32 *t, const sc_slimb_t *u);
void ntt_mult_sparse_16_generic(sc_slimb_t *v, size_t n, UINT16 omega,
    const SINT16 *t, const sc_slimb_t *u);
void ntt_flip_generic(sc_slimb_t *v, const ntt_params_t *p);
void inverse_shuffle(sc_slimb_t *v, size_t n);

void init_reduce(ntt_params_t *p, size_t n, SINT32 q);
void barrett_init(ntt_params_t *p);

SINT32 roots_of_unity_slimb(sc_slimb_t *fwd, sc_slimb_t *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim, SINT32 ternary);
SINT32 roots_of_unity_s32(SINT32 *fwd, SINT32 *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim, SINT32 ternary);
SINT32 roots_of_unity_s16(SINT16 *fwd, SINT16 *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim, SINT32 ternary);

