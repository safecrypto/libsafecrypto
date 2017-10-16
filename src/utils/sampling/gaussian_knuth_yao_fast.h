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


typedef enum sample_blinding sample_blinding_e;

extern void * gaussian_knuth_yao_fast_256_create(prng_ctx_t *prng_ctx,
	FLOAT tail, FLOAT sigma, size_t dummy, sample_blinding_e blinding);
extern void * gaussian_knuth_yao_fast_512_create(prng_ctx_t *prng_ctx,
	FLOAT tail, FLOAT sigma, size_t dummy, sample_blinding_e blinding);
extern SINT32 gaussian_knuth_yao_fast_destroy(void **sampler);
extern prng_ctx_t * gaussian_knuth_yao_fast_get_prng(void *sampler);
extern SINT32 gaussian_knuth_yao_fast_sample(void *sampler);

