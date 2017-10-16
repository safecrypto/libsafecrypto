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

#include "ctr_drbg.h"

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
ctx_ctr_drbg_t* ctr_drbg_create(func_get_random func,
    user_entropy_t *user_entropy, size_t seed_period)
{
    ctx_ctr_drbg_t *ctx = PRNG_MALLOC(sizeof(ctx_ctr_drbg_t));
    ctx->get_random = func;
    ctx->entropy_arg = user_entropy;

    // The seed_period relates to bytes, so convert to a reseed
    // block period and check the bounds
    seed_period >>= 4;
    if (seed_period > CTR_DRBG_MAX_RESEED) {
        seed_period = CTR_DRBG_MAX_RESEED;
    }
    else if (seed_period < CTR_DRBG_MIN_RESEED) {
        seed_period = CTR_DRBG_MIN_RESEED;
    }
    ctx->seed_period = (UINT32) seed_period;

    // Reset the key and counter to zero
    ctx->counter = 0;
    //PRNG_MEMZERO(ctx->key, 32);

    // Generate new initial keys
    aes_encrypt_key256(ctx->key, &ctx->ctx_aes);

    // Reseed the context
    if (PRNG_FUNC_FAILURE == ctr_drbg_reseed(ctx)) {
        PRNG_FREE(ctx, sizeof(ctx_ctr_drbg_t));
        return NULL;
    }

    return ctx;
}

SINT32 ctr_drbg_destroy(ctx_ctr_drbg_t *ctx)
{
    if (NULL == ctx) {
        return PRNG_FUNC_FAILURE;
    }

    PRNG_FREE(ctx, sizeof(ctx_ctr_drbg_t));

    return PRNG_FUNC_SUCCESS;
}

SINT32 ctr_drbg_reset(ctx_ctr_drbg_t *ctx)
{
    if (NULL == ctx) {
        return PRNG_FUNC_FAILURE;
    }

    // Reset the key and counter to zero
    ctx->counter = 0;
    PRNG_MEMZERO(ctx->key, 32);

    // Generate new initial keys
    aes_encrypt_key256(ctx->key, &ctx->ctx_aes);

    // Reseed the context
    if (PRNG_FUNC_FAILURE == ctr_drbg_reseed(ctx)) {
        return PRNG_FUNC_FAILURE;
    }

    return PRNG_FUNC_SUCCESS;
}

static void aes_ctr_drbg_update(ctx_ctr_drbg_t *ctx)
{
    size_t i;
    SINT32 seedlen = 4 + 32;
    SINT32 num_blocks = (seedlen + 15) >> 4;
    unsigned char bytes[num_blocks*16];
    union u {
        unsigned char b[4];
        UINT32 w;
    };
    union u ctr;

    SINT32 block = num_blocks;
    while (block) {
        ctx->counter++;
        ctr.w = ctx->counter;
        unsigned char data[16];
        data[0]  = ctr.b[0];
        data[1]  = ctr.b[1];
        data[2]  = ctr.b[2];
        data[3]  = ctr.b[3];
        data[4]  = data[0];
        data[5]  = data[1];
        data[6]  = data[2];
        data[7]  = data[3];
        data[8]  = data[0];
        data[9]  = data[1];
        data[10] = data[2];
        data[11] = data[3];
        data[12] = data[0];
        data[13] = data[1];
        data[14] = data[2];
        data[15] = data[3];
        block--;
        aes_encrypt(data, bytes + block*16, &ctx->ctx_aes);
    }

    // XOR the counter and key with entropy if required
    ctx->get_random(4, ctr.b, ctx->entropy_arg);
    ctx->get_random(32, ctx->key, ctx->entropy_arg);
    for (i=0; i<32; i++) {
        ctx->key[i] ^= bytes[num_blocks*16-seedlen+i];
    }
    ctx->counter ^= ctr.w;

    // Generate new keys
    aes_encrypt_key256(ctx->key, &ctx->ctx_aes);
}

SINT32 ctr_drbg_reseed(ctx_ctr_drbg_t *ctx)
{
    if (NULL == ctx) {
        return PRNG_FUNC_FAILURE;
    }

    ctx->reseed_ctr = 0;
    aes_ctr_drbg_update(ctx);

    return PRNG_FUNC_SUCCESS;
}

SINT32 ctr_drbg_update(ctx_ctr_drbg_t *ctx, UINT8 *bytes)
{
    size_t i;

    if (NULL == ctx) {
        return PRNG_FUNC_FAILURE;
    }

    if (NULL == bytes) {
        return PRNG_FUNC_FAILURE;
    }

    // Encrypt the counter using the specified key
    union u {
        unsigned char b[16];
        UINT32 w[4];
    };
    for (i=0; i<CSPRNG_BUFFER_SIZE; i+=16) {
        // Increment the counter
        union u data;
        data.w[0] = data.w[1] = data.w[2] = data.w[3] = ctx->counter++;

        // Encrypt the block
        aes_encrypt(data.b, (unsigned char*) bytes+i, &ctx->ctx_aes);
    }

    // Increment the reseed counter
    ctx->reseed_ctr++;
    if (ctx->reseed_ctr >= ctx->seed_period) {
        ctr_drbg_reseed(ctx);
    }

    return PRNG_FUNC_SUCCESS;
}
