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

#include "hash_drbg.h"
#include "safecrypto_private.h"

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


static SINT32 hash_df(hash_drbg_t *ctx, const UINT8 *in, size_t inlen,
    const UINT8 *out, size_t outlen)
{
    size_t len = 0, n;
    UINT8 start[5];
    size_t no_of_bits_to_return = outlen << 3;

    start[0] = 1;
    start[1] = (UINT8) (no_of_bits_to_return >> 24);
    start[2] = (UINT8) (no_of_bits_to_return >> 16);
    start[3] = (UINT8) (no_of_bits_to_return >>  8);
    start[4] = (UINT8) (no_of_bits_to_return      );

    /*printf("hash_df input (%lu):\n", 5 + inlen);
    for (size_t i=0; i<5; i++) {
        printf("%02X ", start[i]);
        if (7 == (i&0x7)) printf("\n");
    }
    printf("\n");
    for (size_t i=0; i<inlen; i++) {
        printf("%02X ", in[i]);
        if (7 == (i&0x7)) printf("\n");
    }
    printf("\n");*/

    while ((len + ctx->ctx_hash->length) < outlen) {
        //printf("hash_df iteration (len=%lu)\n", len);

        hash_init(ctx->ctx_hash);
        hash_update(ctx->ctx_hash, start, 5);
        hash_update(ctx->ctx_hash, in, inlen);
        hash_final(ctx->ctx_hash, (UINT8*)(out + len));

        /*printf("Hash:\n");
        for (size_t i=0; i<ctx->ctx_hash->length; i++) {
            printf("%02X ", out[i + len]);
            if (7 == (i&0x7)) printf("\n");
        }
        printf("\n");*/

        start[0]++;
        len += ctx->ctx_hash->length;
    }

    hash_init(ctx->ctx_hash);
    hash_update(ctx->ctx_hash, start, 5);
    hash_update(ctx->ctx_hash, in, inlen);
    hash_final(ctx->ctx_hash, ctx->df);

    /*printf("Hash:\n");
    for (size_t i=0; i<ctx->ctx_hash->length; i++) {
        printf("%02X ", ctx->df[i]);
        if (7 == (i&0x7)) printf("\n");
    }
    printf("\n");*/

    n = (ctx->ctx_hash->length < (outlen - len))?
         ctx->ctx_hash->length : (outlen - len);
    SC_MEMCOPY((void*)(out + len), ctx->df, n);

    return SC_FUNC_SUCCESS;
}

/// See NIST SP 800-90A 10.1.1.2 and 10.1.1.3, reseeding
static SINT32 hash_drbg_reseeding(hash_drbg_t *ctx,
    UINT8 *seed_material, size_t seedlen, size_t no_of_bits_to_return)
{
    hash_df(ctx, seed_material, seedlen,
        ctx->v+1, no_of_bits_to_return >> 3);

    /*printf("V:\n");
    for (size_t i=0; i<no_of_bits_to_return >> 3; i++) {
        printf("%02X ", ctx->v[1+i]);
        if (7 == (i&0x7)) printf("\n");
    }
    printf("\n");*/

    ctx->v[0] = 0;
    hash_df(ctx, ctx->v, (no_of_bits_to_return >> 3) + 1,
        ctx->c, no_of_bits_to_return >> 3);
    ctx->reseed_ctr = 1;

    /*printf("C:\n");
    for (size_t i=0; i<no_of_bits_to_return >> 3; i++) {
        printf("%02X ", ctx->c[i]);
        if (7 == (i&0x7)) printf("\n");
    }
    printf("\n");*/

    return SC_FUNC_SUCCESS;
}

/// See NIST SP 800-90A 10.1.1.2, we prepare the seed material
static SINT32 hash_drbg_instantiate(hash_drbg_t *ctx,
    const UINT8 *nonce, size_t len_nonce)
{
    // No personalisation string

    // If the nonce length in bits is less than half the
    // security strength in bits then return with an error
    if (len_nonce < (ctx->ctx_hash->length >> 2)) {
        return SC_FUNC_FAILURE;
    }

    size_t no_of_bits_to_return =
        (ctx->ctx_hash->length <= 32)? 440 : 888;
    size_t seedlen = no_of_bits_to_return >> 3;
    ctx->get_random(seedlen, (UINT8*) ctx->temp, ctx->entropy_arg);
    SC_MEMCOPY(ctx->temp + seedlen, nonce, len_nonce);
    seedlen += len_nonce;

    /*printf("seed_material (%lu):\n", seedlen);
    for (size_t i=0; i<seedlen; i++) {
        printf("%02X ", ctx->temp[i]);
        if (7 == (i&0x7)) printf("\n");
    }
    printf("\n");*/

    // Initialise the working state
    hash_drbg_reseeding(ctx, ctx->temp, seedlen, no_of_bits_to_return);

    return SC_FUNC_SUCCESS;
}

hash_drbg_t* hash_drbg_create(func_get_random func,
    user_entropy_t *user_entropy, sc_hash_e hash, size_t seed_period,
    const UINT8 *nonce, size_t len_nonce)
{
    // Check for a valid nonce pointer if used
    if (NULL == nonce && len_nonce > 0) {
        return NULL;
    }

    // Allocate memory for the hash
    hash_drbg_t *ctx = SC_MALLOC(sizeof(hash_drbg_t));
    if (NULL == ctx) {
        return NULL;
    }

    ctx->len_nonce = len_nonce;

    // Create a pointer to the hash
    ctx->ctx_hash = utils_crypto_hash_create(hash);

    // Allocate a scratch buffer
    ctx->temp = SC_MALLOC((((4*ctx->ctx_hash->length - 1 + len_nonce)/ctx->ctx_hash->length)*ctx->ctx_hash->length) * sizeof(UINT8));

    // Store the function pointer used to obtain entropy
    // for reseeding
    ctx->get_random = func;
    ctx->entropy_arg = user_entropy;

    // Check the bounds of the reseed period and store it
    if (seed_period > HASH_DRBG_MAX_RESEED) {
        seed_period = HASH_DRBG_MAX_RESEED;
    }
    else if (seed_period < HASH_DRBG_MIN_RESEED) {
        seed_period = HASH_DRBG_MIN_RESEED;
    }
    ctx->seed_period = (UINT32) seed_period;

    SC_MEMCOPY(ctx->nonce, nonce, len_nonce);

    // Reseed the context for initial operation
    if (SC_FUNC_FAILURE == hash_drbg_instantiate(ctx, ctx->nonce, len_nonce)) {
        SC_FREE(ctx->temp, (((4*ctx->ctx_hash->length - 1 + len_nonce)/ctx->ctx_hash->length)*ctx->ctx_hash->length) * sizeof(UINT8));
        utils_crypto_hash_destroy(ctx->ctx_hash);
        SC_FREE(ctx, sizeof(hash_drbg_t));
        return NULL;
    }

    return ctx;
}

SINT32 hash_drbg_destroy(hash_drbg_t *ctx)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    SINT32 depth = (((4*ctx->ctx_hash->length - 1 + ctx->len_nonce)/ctx->ctx_hash->length)*ctx->ctx_hash->length);
    utils_crypto_hash_destroy(ctx->ctx_hash);
    SC_FREE(ctx->temp, depth * sizeof(UINT8));
    SC_FREE(ctx, sizeof(hash_drbg_t));

    return SC_FUNC_SUCCESS;
}

SINT32 hash_drbg_reset(hash_drbg_t *ctx)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    // Reseed the context for initial operation
    if (SC_FUNC_FAILURE == hash_drbg_instantiate(ctx, ctx->nonce, ctx->len_nonce)) {
        return SC_FUNC_FAILURE;
    }

    return SC_FUNC_SUCCESS;
}

SINT32 hash_drbg_reseed(hash_drbg_t *ctx)
{
    // No personalisation string, nonce is half the length of the hash
    size_t seedlen = 1 + 2*ctx->ctx_hash->length + (ctx->ctx_hash->length>>1);
    ctx->temp[0] = 1;
    SC_MEMCOPY(ctx->temp + 1, ctx->v, ctx->ctx_hash->length);
    ctx->get_random(ctx->ctx_hash->length + (ctx->ctx_hash->length>>1),
        (UINT8*) ctx->temp + 1 + ctx->ctx_hash->length,
        ctx->entropy_arg);

    // Initialise the working state
    size_t no_of_bits_to_return =
        (ctx->ctx_hash->length <= 32)? 440 : 888;
    hash_drbg_reseeding(ctx, ctx->temp, seedlen, no_of_bits_to_return);

    ctx->reseed_ctr = 0;

    return SC_FUNC_SUCCESS;
}

SINT32 hash_drbg_update(hash_drbg_t *ctx, UINT8 *bytes, size_t num)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    if (NULL == bytes) {
        return SC_FUNC_FAILURE;
    }

    if (0 == num) {
        return SC_FUNC_SUCCESS;
    }

    UINT32 carrysum;
    size_t no_of_bits_to_return =
        (ctx->ctx_hash->length <= 32)? 440 : 888;
    size_t no_of_bytes_to_return = no_of_bits_to_return >> 3;
    size_t m = (num + ctx->ctx_hash->length - 1) / ctx->ctx_hash->length;
    //printf("m = %lu\n", m);

    // 10.1.1.4 Step 3 - Hashgen
    SC_MEMCOPY(ctx->temp, ctx->v + 1, no_of_bytes_to_return);
    for (size_t i=0; i<m; i++) {
        hash_init(ctx->ctx_hash);
        hash_update(ctx->ctx_hash, ctx->temp, no_of_bytes_to_return);
        hash_final(ctx->ctx_hash, ctx->df);

        size_t n = ((i+1)*ctx->ctx_hash->length > num)?
                       num - i*ctx->ctx_hash->length : ctx->ctx_hash->length;
        SC_MEMCOPY(bytes + i*ctx->ctx_hash->length, ctx->df, n);

        carrysum = 1;
        size_t j = no_of_bytes_to_return;
        while (j--) {
            carrysum += ctx->temp[j];
            ctx->temp[j] = carrysum & 0xFF;
            carrysum >>= 8;
        }
    }

    // 10.1.1.4 Step 4 - Hash( 0x03 || V )
    hash_init(ctx->ctx_hash);
    ctx->v[0] = 0x03;
    hash_update(ctx->ctx_hash, ctx->v, no_of_bytes_to_return + 1);
    hash_final(ctx->ctx_hash, ctx->temp);

    UINT32 be_reseed_ctr = SC_BIG_ENDIAN_32(ctx->reseed_ctr);
    carrysum = 0;
    size_t i = 0;
    UINT8 *v = ctx->v + 1 + no_of_bytes_to_return - 1;
    UINT8 *c = ctx->c + no_of_bytes_to_return - 1;
    UINT8 *h = ctx->temp + ctx->ctx_hash->length - 1;
    while (i < 4) {
        carrysum += *v + *c + *h + ((be_reseed_ctr >> (24 - 8*i)) & 0xFF);
        *v = carrysum & 0xFF;
        carrysum >>= 8;
        i++;
        v--;
        c--;
        h--;
    }
    while (i < ctx->ctx_hash->length) {
        carrysum += *v + *c + *h;
        *v = carrysum & 0xFF;
        carrysum >>= 8;
        i++;
        v--;
        c--;
        h--;
    }
    while (i < no_of_bytes_to_return) {
        carrysum += *v + *c;
        *v = carrysum & 0xFF;
        carrysum >>= 8;
        i++;
        v--;
        c--;
    }

    // Increment the reseed counter
    ctx->reseed_ctr++;
    if (ctx->reseed_ctr >= ctx->seed_period) {
        hash_drbg_reseed(ctx);
    }

    // Increment the counter
    ctx->counter++;

    return SC_FUNC_SUCCESS;
}
