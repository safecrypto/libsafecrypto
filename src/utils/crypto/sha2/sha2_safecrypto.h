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

#include "sha2/sha2.h"
#include "prng_types.h"

SINT32 sc_sha2_make_copy(void *c, void *c_copy);
SINT32 sc_sha2_init(void *c, SINT32 outlen);
SINT32 sc_sha2_update(void *c, const void *data, size_t inlen);
SINT32 sc_sha2_final(void *c, void *out);
