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

void poly_16_copy(SINT16 *out, size_t n, const SINT16 *in);
void poly_16_reset(SINT16 *inout, size_t offset, size_t n);
void poly_16_add_scalar(SINT16 *poly, size_t n, SINT16 in);
void poly_16_sub_scalar(SINT16 *poly, size_t n, SINT16 in);
void poly_16_mul_scalar(SINT16 *poly, size_t n, SINT16 in);
void poly_16_add(SINT16 *out, size_t n, const SINT16 *in1, const SINT16 *in2);
void poly_16_sub(SINT16 *out, size_t n, const SINT16 *in1, const SINT16 *in2);
void poly_16_add_single(SINT16 *out, size_t n, const SINT16 *in);
void poly_16_sub_single(SINT16 *out, size_t n, const SINT16 *in);
void poly_16_mul(SINT16 *out, size_t n, const SINT16 *in1, const SINT16 *in2);
void poly_16_uniform_rand(prng_ctx_t *ctx, SINT16 *v, size_t n, const UINT16 *c, size_t c_len);
SINT32 poly_16_degree(const SINT16 *h, size_t n);
