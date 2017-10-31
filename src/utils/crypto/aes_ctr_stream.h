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

#include "prng_types.h"
#include "aes256ctr/crypto_stream_aes256ctr.h"


#ifdef ENABLE_AES_CTR_STREAM

typedef struct user_entropy user_entropy_t;

typedef void (*func_get_random)(size_t, UINT8 *, user_entropy_t *);

/// A struct that stores the AES-CTR context
SC_STRUCT_PACK_START
typedef struct ctx_aes_ctr_t {
    func_get_random get_random;
    user_entropy_t *entropy_arg;
    UINT32          counter;
    UINT8           key[32];
} SC_STRUCT_PACKED ctx_aes_ctr_t;
SC_STRUCT_PACK_END


/// Create an instance of the AES-CTR
ctx_aes_ctr_t* aes_ctr_create(func_get_random func,
	user_entropy_t *user_entropy);

/// Free resources associated with the specified AES-CTR
SINT32 aes_ctr_destroy(ctx_aes_ctr_t *ctx);

/// Reset the specified AES-CTR
SINT32 aes_ctr_reset(ctx_aes_ctr_t *ctx);

/// Generate another n bytes of random data
SINT32 aes_ctr_update(ctx_aes_ctr_t *ctx, UINT8 *bytes, size_t n);

#endif
