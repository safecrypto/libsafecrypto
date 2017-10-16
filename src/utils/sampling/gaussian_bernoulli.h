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

#ifdef HAVE_64BIT
extern void * bernoulli_create_64(prng_ctx_t *prng_ctx,
	FLOAT tail, float sigma, size_t dummy, sample_blinding_e blinding);
extern SINT32 bernoulli_destroy_64(void **sampler);
extern prng_ctx_t * bernoulli_get_prng(void *sampler);
extern SINT32 bernoulli_sample_64(void *sampler);
#endif
