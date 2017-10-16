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
#include <string.h>


extern SINT32 vecabsmax_32(const SINT32 *v, size_t n);
extern SINT32 vecscalar_32(const SINT32 *t, const SINT32 *u, size_t n);

extern SINT32 vecabsmax_16(const SINT16 *v, size_t n);
extern SINT32 vecscalar_16(const SINT16 *t, const SINT16 *u, size_t n);

extern SINT32 svd(FLOAT *a, size_t m, size_t n, FLOAT *w);
