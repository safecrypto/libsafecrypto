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

#include "blake2/blake2.h"
#include "prng_types.h"

SINT32 sc_blake2b_make_copy(void *ctx, void *ctx_copy);
SINT32 sc_blake2b_init(void *c, SINT32 outlen);
SINT32 sc_blake2b_update(void *c, const void *data, size_t inlen);
SINT32 sc_blake2b_final(void *c, void *out);

SINT32 sc_blake2xb_make_copy(void *ctx, void *ctx_copy);
SINT32 sc_blake2xb_init(void *c, SINT32 outlen);
SINT32 sc_blake2xb_update(void *c, const void *data, size_t inlen);
SINT32 sc_blake2xb_xof(void *c, void *out, size_t len);
