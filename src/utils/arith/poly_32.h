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
#include "safecrypto_private.h"
#include <string.h>

void poly_32_copy(SINT32 *out, size_t n, const SINT32 *in);
void poly_32_reset(SINT32 *inout, size_t offset, size_t n);
void poly_32_add_scalar(SINT32 *poly, size_t n, SINT32 in);
void poly_32_sub_scalar(SINT32 *poly, size_t n, SINT32 in);
void poly_32_mul_scalar(SINT32 *poly, size_t n, SINT32 in);
void poly_32_add(SINT32 *out, size_t n, const SINT32 *in1, const SINT32 *in2);
void poly_32_sub(SINT32 *out, size_t n, const SINT32 *in1, const SINT32 *in2);
void poly_32_add_single(SINT32 *out, size_t n, const SINT32 *in);
void poly_32_sub_single(SINT32 *out, size_t n, const SINT32 *in);
void poly_32_mul(SINT32 *out, size_t n, const SINT32 *in1, const SINT32 *in2);
void poly_32_uniform_rand(prng_ctx_t *ctx, SINT32 *v, size_t n, const UINT16 *c, size_t c_len);
void poly_32_mod_negate(SINT32 *out, size_t n, SINT32 q, const SINT32 *in);
SINT32 poly_32_cmp_not_equal(volatile const SINT32 *in1, volatile const SINT32 *in2, size_t n);
SINT32 poly_32_degree(const SINT32 *h, size_t n);

