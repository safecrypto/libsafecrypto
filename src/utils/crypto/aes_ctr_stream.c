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

#include "aes_ctr_stream.h"

#ifdef ENABLE_AES_CTR_STREAM

#include <string.h>
#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#else // WINDOWS
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

HCRYPTPROV hCryptProv;
#endif



/// Create and initialise a CTR-DRBG state context
ctx_aes_ctr_t* aes_ctr_create(func_get_random func,
    user_entropy_t *user_entropy)
{
    ctx_aes_ctr_t *ctx = PRNG_MALLOC(sizeof(ctx_aes_ctr_t));
    ctx->get_random = func;
    ctx->entropy_arg = user_entropy;

    // Reset the key and counter to zero
    ctx->counter = 0;
    PRNG_MEMZERO(ctx->key, 32);

    return ctx;
}

SINT32 aes_ctr_destroy(ctx_aes_ctr_t *ctx)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    PRNG_FREE(ctx, sizeof(ctx_aes_ctr_t));

    return SC_FUNC_SUCCESS;
}

SINT32 aes_ctr_reset(ctx_aes_ctr_t *ctx)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    ctx->counter = 0;
    PRNG_MEMZERO(ctx->key, 32);

    return SC_FUNC_SUCCESS;
}

SINT32 aes_ctr_update(ctx_aes_ctr_t *ctx, UINT8 *bytes, size_t n)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    if (NULL == bytes) {
        return SC_FUNC_FAILURE;
    }

    // Encrypt the counter using the specified key
    unsigned char data[16];
    data[0]  = ctx->counter >> 24;
    data[1]  = ctx->counter >> 16;
    data[2]  = ctx->counter >> 8;
    data[3]  = ctx->counter;
    data[4]  = ctx->counter >> 24;
    data[5]  = ctx->counter >> 16;
    data[6]  = ctx->counter >> 8;
    data[7]  = ctx->counter;
    data[8]  = ctx->counter >> 24;
    data[9]  = ctx->counter >> 16;
    data[10] = ctx->counter >> 8;
    data[11] = ctx->counter;
    data[12] = ctx->counter >> 24;
    data[13] = ctx->counter >> 16;
    data[14] = ctx->counter >> 8;
    data[15] = ctx->counter;

    crypto_stream_aes256ctr((unsigned char*) bytes, n, data, ctx->key);

    // Increment the counter
    ctx->counter++;

    return SC_FUNC_SUCCESS;
}

#endif
