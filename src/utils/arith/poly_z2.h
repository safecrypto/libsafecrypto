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


SINT32 z2_ext_euclidean(SINT32 *inv, SINT32 *f, SINT32 *scratch, size_t n);
SINT32 z2_inv(SINT32 *inv, SINT32 *f, SINT32 *scratch, size_t n);
void z2_mul(SINT32 *out, SINT32 n, const SINT32 *in1, const SINT32 *in2);
SINT32 z2_div(SINT32 *q, SINT32 *r, SINT32 n, const SINT32 *num, const SINT32 *den);
SINT32 z2_mul_mod2(const SINT32 *in1, const SINT32 *in2, SINT32 n, SINT32 *out);
SINT32 z2_conv_mod2(const UINT32 *a, UINT32 *b_rev, size_t n, UINT32 *out);
void z2_uniform(prng_ctx_t *ctx, SINT32 *v, size_t n, size_t num_ones);
