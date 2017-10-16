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

extern prng_ctx_t * gaussian_cdf_get_prng_128(void *sampler);
extern prng_ctx_t * gaussian_cdf_get_prng_64(void *sampler);
extern prng_ctx_t * gaussian_cdf_get_prng_32(void *sampler);

#ifdef HAVE_128BIT
extern void * gaussian_cdf_create_128(prng_ctx_t *prng_ctx,
	FLOAT tail, float sigma, size_t max_lut_bytes, sample_blinding_e blinding);
extern SINT32 gaussian_cdf_destroy_128(void **sampler);
extern SINT32 gaussian_cdf_sample_128(void *sampler);
#endif

#ifdef HAVE_64BIT
extern void * gaussian_cdf_create_64(prng_ctx_t *prng_ctx,
	FLOAT tail, float sigma, size_t max_lut_bytes, sample_blinding_e blinding);
extern SINT32 gaussian_cdf_destroy_64(void **sampler);
extern SINT32 gaussian_cdf_sample_64(void *sampler);
#endif

extern void * gaussian_cdf_create_32(prng_ctx_t *prng_ctx,
	FLOAT tail, float sigma, size_t max_lut_bytes, sample_blinding_e blinding);
extern SINT32 gaussian_cdf_destroy_32(void **sampler);
extern SINT32 gaussian_cdf_sample_32(void *sampler);
