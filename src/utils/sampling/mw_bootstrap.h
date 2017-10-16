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
#include "safecrypto_private.h"

// Forward declaration of the struct used to define sampling
typedef struct _utils_sampling utils_sampling_t;

extern void * mw_bootstrap_create(const utils_sampling_t *sc_gauss, void *base_sampler,
	FLOAT base_sigma, size_t max_slevels, size_t b, size_t precision, size_t max_flips, FLOAT eta);
extern SINT32 mw_bootstrap_destroy(void **sampler);

extern SINT32 mw_bootstrap_sample(void *sampler, DOUBLE sigma2, DOUBLE center);
