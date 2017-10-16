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
#include "utils/arith/vectors.h"
#include "utils/arith/poly_16.h"
#include "utils/arith/poly_32.h"
#include "utils/arith/poly_z2.h"
#include "utils/arith/ntt.h"
#include <string.h>

typedef struct _prng_pool prng_pool_t;

typedef void (*arith_poly_16_copy)(SINT16 *, size_t, const SINT16 *);
typedef void (*arith_poly_16_reset)(SINT16 *, size_t, size_t);
typedef void (*arith_poly_16_add_16_scalar)(SINT16 *, size_t, SINT16);
typedef void (*arith_poly_16_sub_16_scalar)(SINT16 *, size_t, SINT16);
typedef void (*arith_poly_16_mul_16_scalar)(SINT16 *, size_t, SINT16);
typedef void (*arith_poly_16_add_16)(SINT16 *, size_t, const SINT16 *, const SINT16 *);
typedef void (*arith_poly_16_sub_16)(SINT16 *, size_t, const SINT16 *, const SINT16 *);
typedef void (*arith_poly_16_add_single_16)(SINT16 *, size_t, const SINT16 *);
typedef void (*arith_poly_16_sub_single_16)(SINT16 *, size_t, const SINT16 *);
typedef void (*arith_poly_16_mul_16)(SINT16 *, size_t, const SINT16 *, const SINT16 *);
typedef void (*arith_poly_16_uniform)(prng_ctx_t *, SINT16 *, size_t, const UINT16 *, size_t);
typedef SINT32 (*arith_poly_16_degree)(const SINT16 *, size_t);

typedef void (*arith_poly_32_copy)(SINT32 *, size_t, const SINT32 *);
typedef void (*arith_poly_32_reset)(SINT32 *, size_t, size_t);
typedef void (*arith_poly_32_add_32_scalar)(SINT32 *, size_t, SINT32);
typedef void (*arith_poly_32_sub_32_scalar)(SINT32 *, size_t, SINT32);
typedef void (*arith_poly_32_mul_32_scalar)(SINT32 *, size_t, SINT32);
typedef void (*arith_poly_32_add_32)(SINT32 *, size_t, const SINT32 *, const SINT32 *);
typedef void (*arith_poly_32_sub_32)(SINT32 *, size_t, const SINT32 *, const SINT32 *);
typedef void (*arith_poly_32_add_single_32)(SINT32 *, size_t, const SINT32 *);
typedef void (*arith_poly_32_sub_single_32)(SINT32 *, size_t, const SINT32 *);
typedef void (*arith_poly_32_mul_32)(SINT32 *, size_t, const SINT32 *, const SINT32 *);
typedef void (*arith_poly_32_mod_negate)(SINT32 *, size_t, SINT32, const SINT32 *);
typedef void (*arith_poly_32_uniform)(prng_ctx_t *, SINT32 *, size_t, const UINT16 *, size_t);
typedef SINT32 (*arith_poly_32_degree)(const SINT32 *, size_t);

typedef SINT32 (*arith_poly_32_bin_inv)(SINT32 *, SINT32 *, SINT32 *, size_t);
typedef void (*arith_z2_mul)(SINT32 *, SINT32, const SINT32 *, const SINT32 *);
typedef SINT32 (*arith_z2_div)(SINT32 *, SINT32 *, SINT32, const SINT32 *, const SINT32 *);
typedef SINT32 (*arith_z2_mul_mod2)(const SINT32 *, const SINT32 *, SINT32, SINT32 *);
typedef SINT32 (*arith_z2_conv)(const UINT32 *, UINT32 *, size_t, UINT32 *);
typedef void (*arith_z2_uniform)(prng_ctx_t *, SINT32 *, size_t, size_t);

SC_STRUCT_PACK_START
typedef struct _utils_arith_poly {
    arith_poly_16_copy          copy_16;
    arith_poly_16_reset         reset_16;
    arith_poly_16_add_16_scalar add_16_scalar;
    arith_poly_16_sub_16_scalar sub_16_scalar;
    arith_poly_16_mul_16_scalar mul_16_scalar;
    arith_poly_16_add_16        add_16;
    arith_poly_16_sub_16        sub_16;
    arith_poly_16_add_single_16 add_single_16;
    arith_poly_16_sub_single_16 sub_single_16;
    arith_poly_16_mul_16        mul_16;
    arith_poly_16_uniform       uniform_16;
    arith_poly_16_degree        degree_16;
    arith_poly_32_copy          copy_32;
    arith_poly_32_reset         reset_32;
    arith_poly_32_add_32_scalar add_32_scalar;
    arith_poly_32_sub_32_scalar sub_32_scalar;
    arith_poly_32_mul_32_scalar mul_32_scalar;
    arith_poly_32_add_32        add_32;
    arith_poly_32_sub_32        sub_32;
    arith_poly_32_add_single_32 add_single_32;
    arith_poly_32_sub_single_32 sub_single_32;
    arith_poly_32_mul_32        mul_32;
    arith_poly_32_mod_negate    mod_negate_32;
    arith_poly_32_uniform       uniform_32;
    arith_poly_32_degree        degree_32;
    arith_poly_32_bin_inv       bin_inv_32;
    arith_z2_mul                z2_mul;
    arith_z2_div                z2_div;
    arith_z2_mul_mod2           z2_mul_mod2;
    arith_z2_conv               z2_conv;
    arith_z2_uniform            uniform_z2;
} SC_STRUCT_PACKED utils_arith_poly_t;
SC_STRUCT_PACK_END

extern const utils_arith_poly_t *utils_arith_poly(void);


// absolute maximinum of a vector

typedef SINT32 (*arith_vec_32_absmax)(const SINT32 *, size_t);
typedef SINT32 (*arith_vec_32_scalar)(const SINT32 *, const SINT32 *, size_t);
typedef SINT32 (*arith_vec_16_absmax)(const SINT16 *, size_t);
typedef SINT32 (*arith_vec_16_scalar)(const SINT16 *, const SINT16 *, size_t);

SC_STRUCT_PACK_START
typedef struct _utils_arith_vec {
    arith_vec_32_absmax absmax_32;
    arith_vec_32_scalar scalar_32;
    arith_vec_16_absmax absmax_16;
    arith_vec_16_scalar scalar_16;
} SC_STRUCT_PACKED utils_arith_vec_t;
SC_STRUCT_PACK_END

extern const utils_arith_vec_t *utils_arith_vectors(void);


extern const utils_arith_ntt_t *utils_arith_ntt(safecrypto_ntt_e type);

