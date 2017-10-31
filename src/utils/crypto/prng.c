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

#include "prng.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifndef ENABLE_BAREMETAL
#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/random.h>
#else // WINDOWS
#include <Windows.h>
#include <wincrypt.h>
#endif
#endif

#if 0
#include "utils/threading/pipe.h"
#include "utils/threading/threadpool.h"
#endif

#include "safecrypto_private.h"
#include "prng_get_func.h"

#ifdef ENABLE_ISAAC
#include "isaac_csprng.h"
#ifdef HAVE_64BIT
#include "isaac/isaac64.h"
#else
#include "isaac/rand.h"
#endif
#endif
#ifdef ENABLE_HASH_DRBG
#include "hash_drbg.h"
#endif
#ifdef ENABLE_AES
#include "ctr_drbg.h"
#endif
#ifdef ENABLE_AES_CTR_STREAM
#include "aes_ctr_stream.h"
#endif
#ifdef ENABLE_KISS
#include "kiss.h"
#endif
#ifdef ENABLE_CHACHA20
#include "chacha20_csprng.h"
#endif
#ifdef ENABLE_SALSA20
#include "salsa20_csprng.h"
#endif

#ifdef _ENABLE_CSPRNG_FILE
/// The filename used when reading CSPRNG data from file
/// (USED FOR DEBUG PURPOSES ONLY!)
#define CSPRNG_DEBUG_FILENAME    "csprng.dat"
#endif

/// Constants used to convert 53 random bits into a random double
/// @{
#define RND_DBL_DEN_SCALE 1.11022302462516e-16   // 1.0/9007199254740992.0
#define RND_DBL_NUM_SCALE 67108864.0
/// @}

/// The size of the bitpool in bits
#define RANDOM_POOL_MAXBITS     (32 * RANDOM_POOL_SIZE)

// The global pointer to an entropy callback function
extern prng_entropy_callback entropy_callback;


/********************** PRNG PRIVATE HELPER FUNCTIONS ************************/

#if 0
static void * prng_producer_u32_worker(void *p);
#endif

/// Add bits to the bitpool when its level dips below a predefined threshold
static SINT32 update_pool(prng_ctx_t *ctx)
{
    if (0 == ctx->bits) {
#if 0
        if (ctx->mt_enabled) {
            threadpool_add(ctx->pool, prng_producer_u32_worker, (void*)ctx);
            size_t pulled = pipe_pull(ctx->pipe_u32_consumer, ctx->random_pool, RANDOM_POOL_SIZE);// + ctx->wr_idx, RANDOM_POOL_SIZE - ctx->wr_idx);
            ctx->bits = 32 * pulled;
            ctx->wr_idx = 0;
        }
        else
#endif
        {
#ifdef HAVE_64BIT
            size_t num_reads = RANDOM_POOL_MAXBITS >> 6;
            size_t new_bits = RANDOM_POOL_MAXBITS;
            ctx->rd_idx = 0;
            ctx->wr_idx = 0;
            while (num_reads--) {
                UINT64 data = ctx->get_random_64(ctx);
                ctx->random_pool[ctx->wr_idx++] = (UINT32)(data >> 32);
                ctx->random_pool[ctx->wr_idx++] = (UINT32)(data & 0xFFFFFFFF);
#else
            size_t num_reads = RANDOM_POOL_MAXBITS >> 5;
            size_t new_bits = RANDOM_POOL_MAXBITS;
            ctx->rd_idx = 0;
            ctx->wr_idx = 0;
            while (num_reads--) {
                UINT32 data = ctx->get_random_32(ctx);
                ctx->random_pool[ctx->wr_idx++] = data;
#endif
            }
            ctx->bits = new_bits;
        }
    }

    return SC_FUNC_SUCCESS;
}

/// Remove 32 bits from the pool and increment the pool read index
static void decrease_pool_bits(prng_ctx_t *ctx)
{
    ctx->bits -= 32;
    ctx->rd_idx++;
    if (ctx->rd_idx >= RANDOM_POOL_SIZE) {
        ctx->rd_idx = 0;
    }
}

#ifndef ENABLE_BAREMETAL
static SINT32 init_rand()
{
    // NOTE: This code is not compatible with older C standards
    // (e.g. C90, gnu90)

    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) == 0) {
        return SC_CREATE_ERROR;
    }

    UINT32 seed = ts.tv_nsec ^ ts.tv_sec;
    srandom(seed);

    return SC_OK;
}
#endif

static SINT32 config_entropy(safecrypto_entropy_e entropy,
    safecrypto_prng_e type, func_get_random_entropy *fn_entropy)
{
#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
#ifndef ENABLE_BAREMETAL
    // If the POSIX random() function is used as an entropy source or 
    // the PRNG type ensure that it is seeded once using a fine
    // granularity timestamp
    if (SC_ENTROPY_RANDOM == entropy || SC_PRNG_SYSTEM == type) {
        if (SC_OK != init_rand()) {
            return SC_FUNC_FAILURE;
        }
    }
#endif

    // Select the entropy callback function
    switch (entropy)
    {
#ifndef ENABLE_BAREMETAL
        case SC_ENTROPY_RANDOM:
            {
                *fn_entropy = get_entropy_posix;
            } break;

        case SC_ENTROPY_DEV_RANDOM:
            {
                *fn_entropy = get_entropy_dev_random;
            } break;

        case SC_ENTROPY_DEV_URANDOM:
            {
                *fn_entropy = get_entropy_dev_urandom;
            } break;
#endif

        case SC_ENTROPY_CALLBACK:
            {
                *fn_entropy = get_entropy_callback;
            } break;

        case SC_ENTROPY_USER_PROVIDED:
            {
                *fn_entropy = get_entropy_user;
            } break;

        default:
            {
                return SC_FUNC_FAILURE;
            };
    }
#else
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        return SC_FUNC_FAILURE;
    }
#endif

    return SC_FUNC_SUCCESS;
}

static SINT32 config_csprng(prng_ctx_t *ctx,
    func_get_random_entropy fn_entropy,
    const UINT8 *nonce, size_t len_nonce)
{
    safecrypto_prng_e type = ctx->type;

    // Initialise the user selected PRNG/CSPRNG and configure the 32-bit
    // random number GET function
    switch (type)
    {
#ifdef ENABLE_AES
        case SC_PRNG_AES_CTR_DRBG:
            {
                ctx->ctr_drbg_ctx = ctr_drbg_create(
                    fn_entropy, ctx->user_entropy, ctx->seed_period);
                ctx->get_random_32 = get_random_32_aes;
            } break;
#endif

#ifdef ENABLE_AES_CTR_STREAM
        case SC_PRNG_AES_CTR:
            {
                ctx->aes_ctr_ctx = aes_ctr_create(fn_entropy, ctx->user_entropy);
                ctx->get_random_32 = get_random_32_aes_ctr;
            } break;
#endif

#ifdef ENABLE_CHACHA20
        case SC_PRNG_CHACHA:
            {
                ctx->chacha20_ctx = create_chacha20(
                    fn_entropy, ctx->user_entropy, ctx->seed_period);
                ctx->get_random_32 = get_random_32_chacha;
            } break;
#endif

#ifdef ENABLE_SALSA20
        case SC_PRNG_SALSA:
            {
                ctx->salsa20_ctx = create_salsa20(
                    fn_entropy, ctx->user_entropy, ctx->seed_period);
                ctx->get_random_32 = get_random_32_salsa;
            } break;
#endif

#ifdef ENABLE_ISAAC
        case SC_PRNG_ISAAC:
            {
                ctx->isaac_ctx = create_isaac(
                    fn_entropy, ctx->user_entropy, ctx->seed_period);
                ctx->get_random_32 = get_random_32_isaac;
            } break;
#endif

#ifdef ENABLE_KISS
        case SC_PRNG_KISS:
            {
                ctx->kiss_ctx = create_kiss(
                    fn_entropy, ctx->user_entropy, ctx->seed_period);
                ctx->get_random_32 = get_random_32_kiss;
            } break;
#endif

#ifdef ENABLE_HASH_DRBG
        case SC_PRNG_HASH_DRBG_SHA2_256:
            {
                ctx->hash_drbg_ctx = hash_drbg_create(
                    fn_entropy, ctx->user_entropy, SC_HASH_SHA2_256, ctx->seed_period,
                    nonce, len_nonce);
                ctx->get_random_32 = get_random_32_hash_drbg;
            } break;

        case SC_PRNG_HASH_DRBG_SHA2_512:
            {
                ctx->hash_drbg_ctx = hash_drbg_create(
                    fn_entropy, ctx->user_entropy, SC_HASH_SHA2_512, ctx->seed_period,
                    nonce, len_nonce);
                ctx->get_random_32 = get_random_32_hash_drbg;
            } break;

        case SC_PRNG_HASH_DRBG_SHA3_256:
            {
                ctx->hash_drbg_ctx = hash_drbg_create(
                    fn_entropy, ctx->user_entropy, SC_HASH_SHA3_256, ctx->seed_period,
                    nonce, len_nonce);
                ctx->get_random_32 = get_random_32_hash_drbg;
            } break;

        case SC_PRNG_HASH_DRBG_SHA3_512:
            {
                ctx->hash_drbg_ctx = hash_drbg_create(
                    fn_entropy, ctx->user_entropy, SC_HASH_SHA3_512, ctx->seed_period,
                    nonce, len_nonce);
                ctx->get_random_32 = get_random_32_hash_drbg;
            } break;

        case SC_PRNG_HASH_DRBG_BLAKE2_256:
            {
                ctx->hash_drbg_ctx = hash_drbg_create(
                    fn_entropy, ctx->user_entropy, SC_HASH_BLAKE2_256, ctx->seed_period,
                    nonce, len_nonce);
                ctx->get_random_32 = get_random_32_hash_drbg;
            } break;

        case SC_PRNG_HASH_DRBG_BLAKE2_512:
            {
                ctx->hash_drbg_ctx = hash_drbg_create(
                    fn_entropy, ctx->user_entropy, SC_HASH_BLAKE2_512, ctx->seed_period,
                    nonce, len_nonce);
                ctx->get_random_32 = get_random_32_hash_drbg;
            } break;

        case SC_PRNG_HASH_DRBG_WHIRLPOOL_512:
            {
                ctx->hash_drbg_ctx = hash_drbg_create(
                    fn_entropy, ctx->user_entropy, SC_HASH_WHIRLPOOL_512, ctx->seed_period,
                    nonce, len_nonce);
                ctx->get_random_32 = get_random_32_hash_drbg;
            } break;
#endif

        case SC_PRNG_HIGH_ENTROPY:
            {
                ctx->get_random_32 = get_random_32_high_entropy;
            } break;

#if !defined(ENABLE_BAREMETAL)
        case SC_PRNG_SYSTEM:
            {
#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
                ctx->get_random_32 = get_random_32_posix;
#else
                ctx->get_random_32 = get_random_32_windows;
#endif
            } break;

#ifdef _ENABLE_CSPRNG_FILE
        case SC_PRNG_FILE:
            {
                ctx->get_random_32 = get_random_32_file;
            } break;
#endif
#endif
        default: return SC_FUNC_FAILURE;
    }

#ifdef ENABLE_HASH_DRBG
    // If the Hash-DRBG context has not been initialised then return with an error
    switch (type)
    {
        case SC_PRNG_HASH_DRBG_WHIRLPOOL_512:
        case SC_PRNG_HASH_DRBG_BLAKE2_256:
        case SC_PRNG_HASH_DRBG_BLAKE2_512:
        case SC_PRNG_HASH_DRBG_SHA3_512:
        case SC_PRNG_HASH_DRBG_SHA3_256:
        case SC_PRNG_HASH_DRBG_SHA2_512:
        case SC_PRNG_HASH_DRBG_SHA2_256:
            if (NULL == ctx->hash_drbg_ctx) {
                return SC_FUNC_FAILURE;
            }
            break;
        default:;
    }
#endif // ENABLE_HASH_DRBG

#ifdef HAVE_64BIT
    // Initialise the 64-bit random number GET function
    switch (type)
    {
#ifdef ENABLE_AES
        case SC_PRNG_AES_CTR_DRBG:
            {
                ctx->get_random_64 = get_random_64_aes;
            } break;
#endif

#ifdef ENABLE_AES_CTR_STREAM
        case SC_PRNG_AES_CTR:
            {
                ctx->get_random_64 = get_random_64_aes_ctr;
            } break;
#endif

#ifdef ENABLE_CHACHA20
        case SC_PRNG_CHACHA:
            {
                ctx->get_random_64 = get_random_64_chacha;
            } break;
#endif

#ifdef ENABLE_SALSA20
        case SC_PRNG_SALSA:
            {
                ctx->get_random_64 = get_random_64_salsa;
            } break;
#endif

#ifdef ENABLE_ISAAC
        case SC_PRNG_ISAAC:
            {
                ctx->get_random_64 = get_random_64_isaac;
            } break;
#endif

#ifdef ENABLE_KISS
        case SC_PRNG_KISS:
            {
                ctx->get_random_64 = get_random_64_kiss;
            } break;
#endif

#ifdef ENABLE_HASH_DRBG
        case SC_PRNG_HASH_DRBG_WHIRLPOOL_512:
        case SC_PRNG_HASH_DRBG_BLAKE2_256:
        case SC_PRNG_HASH_DRBG_BLAKE2_512:
        case SC_PRNG_HASH_DRBG_SHA3_512:
        case SC_PRNG_HASH_DRBG_SHA3_256:
        case SC_PRNG_HASH_DRBG_SHA2_512:
        case SC_PRNG_HASH_DRBG_SHA2_256:
            {
                ctx->get_random_64 = get_random_64_hash_drbg;
            } break;
#endif

        case SC_PRNG_HIGH_ENTROPY:
            {
                ctx->get_random_64 = get_random_64_high_entropy;
            } break;

#if !defined(ENABLE_BAREMETAL)
        case SC_PRNG_SYSTEM:
            {
#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
                ctx->get_random_64 = get_random_64_posix;
#else
                ctx->get_random_64 = get_random_64_windows;
#endif
            } break;

#ifdef _ENABLE_CSPRNG_FILE
        case SC_PRNG_FILE:
            {
                ctx->get_random_64 = get_random_64_file;
            } break;
#endif
#endif
        default: return SC_FUNC_FAILURE;
    }
#endif

    return SC_FUNC_SUCCESS;
}

#if 0
static void * prng_producer_u32_worker(void *p)
{
    size_t i;//, j=RANDOM_POOL_SIZE;
    //const utils_threading_t *threading = utils_threading();
    prng_ctx_t *ctx = (prng_ctx_t*) p;
    pipe_producer_t *pipe = pipe_producer_create(ctx->pipe_u32);
    UINT32 data[RANDOM_POOL_SIZE];

    {//while(j--) {
        for (i=0; i<RANDOM_POOL_SIZE; i++) {
            data[i] = ctx->get_random_32(ctx);
        }
        pipe_push(pipe, data, RANDOM_POOL_SIZE);
    }

    pipe_producer_destroy(pipe);

    return NULL;
}


static void * prng_producer_u16_worker(void *p)
{
    size_t i;
    //const utils_threading_t *threading = utils_threading();
    prng_ctx_t *ctx = (prng_ctx_t*) p;
    pipe_producer_t *pipe = pipe_producer_create(ctx->pipe_u16);

    for (i=0; i<32; i++) {
        UINT32 data = ctx->get_random_32(ctx);
        UINT16 u16[2];
        u16[0] = data >> 16;
        u16[1] = data;
        if (SC_FUNC_FAILURE == pipe_push(pipe, u16, 2)) {
            break;
        }
    }

    pipe_producer_destroy(pipe);
    return NULL;
}

static void * prng_producer_u8_worker(void *p)
{
    size_t i;
    //const utils_threading_t *threading = utils_threading();
    prng_ctx_t *ctx = (prng_ctx_t*) p;
    pipe_producer_t *pipe = pipe_producer_create(ctx->pipe_u8);

    for (i=0; i<16; i++) {
        UINT32 data = ctx->get_random_32(ctx);
        UINT8 u8[4];
        u8[0] = data >> 24;
        u8[1] = data >> 16;
        u8[2] = data >> 8;
        u8[3] = data;
        if (SC_FUNC_FAILURE == pipe_push(pipe, u8, 4)) {
            break;
        }
    }

    pipe_producer_destroy(pipe);
    return NULL;
}

static void * prng_producer_flt_worker(void *p)
{
    size_t i;
    //const utils_threading_t *threading = utils_threading();
    prng_ctx_t *ctx = (prng_ctx_t*) p;
    pipe_producer_t *pipe = pipe_producer_create(ctx->pipe_flt);

    for (i=0; i<64; i++) {
        UINT32 data = ctx->get_random_32(ctx);
        FLOAT flt = ((FLOAT) data) / UINT32_MAX;;
        if (SC_FUNC_FAILURE == pipe_push(pipe, &flt, 1)) {
            break;
        }
    }

    pipe_producer_destroy(pipe);
    return NULL;
}

static void * prng_producer_dbl_worker(void *p)
{
    size_t i;
    //const utils_threading_t *threading = utils_threading();
    prng_ctx_t *ctx = (prng_ctx_t*) p;
    pipe_producer_t *pipe = pipe_producer_create(ctx->pipe_dbl);

    for (i=0; i<64; i++) {
        UINT32 a = ctx->get_random_32(ctx) >> 5;
        UINT32 b = ctx->get_random_32(ctx) >> 6;
        DOUBLE dbl = (a * RND_DBL_NUM_SCALE + b) * RND_DBL_DEN_SCALE;
        if (SC_FUNC_FAILURE == pipe_push(pipe, &dbl, 1)) {
            break;
        }
    }

    pipe_producer_destroy(pipe);
    return NULL;
}
#endif


/*************************** PRNG API FUNCTIONS ******************************/

prng_ctx_t * prng_create(safecrypto_entropy_e entropy,
    safecrypto_prng_e type, safecrypto_prng_threading_e mt,
    size_t seed_period)
{
#ifdef ENABLE_BAREMETAL
    if (SC_ENTROPY_USER_PROVIDED != entropy &&
        SC_ENTROPY_CALLBACK      != entropy) {
        return NULL;
    }
#else
    if (SC_ENTROPY_RANDOM        != entropy &&
        SC_ENTROPY_DEV_RANDOM    != entropy &&
        SC_ENTROPY_DEV_URANDOM   != entropy &&
        SC_ENTROPY_DEV_HWRNG     != entropy &&
        SC_ENTROPY_CALLBACK      != entropy &&
        SC_ENTROPY_USER_PROVIDED != entropy) {
        return NULL;
    }
#endif

    if (SC_PRNG_SYSTEM                  != type
#ifdef ENABLE_AES
        && SC_PRNG_AES_CTR_DRBG            != type
#endif
#ifdef ENABLE_ISAAC
        && SC_PRNG_ISAAC                   != type
#endif
#ifdef ENABLE_AES_CTR_STREAM
        && SC_PRNG_AES_CTR                 != type
#endif
#ifdef ENABLE_CHACHA20
        && SC_PRNG_CHACHA                  != type
#endif
#ifdef ENABLE_SALSA20
        && SC_PRNG_SALSA                   != type
#endif
#ifdef ENABLE_KISS
        && SC_PRNG_KISS                    != type
#endif
#ifndef CONSTRAINED_SYSTEM
        && SC_PRNG_HIGH_ENTROPY            != type
        && SC_PRNG_FILE                    != type
#endif
#ifdef ENABLE_HASH_DRBG
        && SC_PRNG_HASH_DRBG_SHA2_256      != type
        && SC_PRNG_HASH_DRBG_SHA2_512      != type
        && SC_PRNG_HASH_DRBG_SHA3_256      != type
        && SC_PRNG_HASH_DRBG_SHA3_512      != type
        && SC_PRNG_HASH_DRBG_BLAKE2_256    != type
        && SC_PRNG_HASH_DRBG_BLAKE2_512    != type
        && SC_PRNG_HASH_DRBG_WHIRLPOOL_512 != type
#endif
        ) {
        return NULL;
    }

    prng_ctx_t *ctx = SC_MALLOC(sizeof(prng_ctx_t));
    if (NULL == ctx) {
        return NULL;
    }

    ctx->random_pool = SC_MALLOC(sizeof(UINT32) * RANDOM_POOL_SIZE);

    // Initialise the PRNG context
    ctx->type = type;
    ctx->entropy = entropy;
    ctx->user_entropy = NULL;
#ifdef HAVE_64BIT
    ctx->rng_cnt = CSPRNG_BUFFER_SIZE/sizeof(UINT64);
#else
    ctx->rng_cnt = CSPRNG_BUFFER_SIZE/sizeof(UINT32);
#endif
#ifdef ENABLE_AES
    ctx->ctr_drbg_ctx = NULL;
#endif
#ifdef ENABLE_KISS
    ctx->kiss_ctx = NULL;
#endif
#ifdef ENABLE_CHACHA20
    ctx->chacha20_ctx = NULL;
#endif
#ifdef ENABLE_SALSA20
    ctx->salsa20_ctx = NULL;
#endif
#ifdef ENABLE_ISAAC
    ctx->isaac_ctx = NULL;
#endif
#ifdef ENABLE_HASH_DRBG
    ctx->hash_drbg_ctx = NULL;
#endif // ENABLE_HASH_DRBG
    ctx->bits   = 0;
    ctx->wr_idx = 0;
    ctx->rd_idx = 0;
    ctx->var_bits = 0;
    ctx->seed_period = seed_period;
    ctx->stats_csprng_bytes = 0;
    ctx->stats_out_bytes = 0;

#if 0
    // Configure multithreaded support
    ctx->mt_enabled = SC_PRNG_THREADING_NONE != mt;
    if (ctx->mt_enabled) {
        ctx->pipe_u32 = pipe_create(sizeof(UINT32), RANDOM_POOL_SIZE);
        ctx->pipe_u16 = pipe_create(sizeof(UINT16), 512);
        ctx->pipe_u8  = pipe_create(sizeof(UINT8), 512);
        ctx->pipe_flt = pipe_create(sizeof(FLOAT), 512);
        ctx->pipe_dbl = pipe_create(sizeof(DOUBLE), 512);
        ctx->pipe_u32_consumer = pipe_consumer_create(ctx->pipe_u32);
        ctx->pipe_u16_consumer = pipe_consumer_create(ctx->pipe_u16);
        ctx->pipe_u8_consumer  = pipe_consumer_create(ctx->pipe_u8);
        ctx->pipe_flt_consumer = pipe_consumer_create(ctx->pipe_flt);
        ctx->pipe_dbl_consumer = pipe_consumer_create(ctx->pipe_dbl);

        ctx->pool = threadpool_create(5, 5);
        threadpool_add(ctx->pool, prng_producer_u32_worker, (void*)ctx);
        /*threadpool_add(ctx->pool, prng_producer_u16_worker, (void*)ctx);
        threadpool_add(ctx->pool, prng_producer_u8_worker, (void*)ctx);
        threadpool_add(ctx->pool, prng_producer_flt_worker, (void*)ctx);
        threadpool_add(ctx->pool, prng_producer_dbl_worker, (void*)ctx);*/
    }
#endif

#ifdef _ENABLE_CSPRNG_FILE
    // Set a default filename for the debug file
    strcpy(ctx->debug_filename, CSPRNG_DEBUG_FILENAME);

    // Set the data to NULL to indicate we haven't loaded it
    ctx->debug_data = NULL;
#endif

    return ctx;
}

SINT32 prng_set_entropy(prng_ctx_t *ctx, const UINT8 *entropy, size_t len)
{
    // Store the user provided entropy 
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

    if (NULL == ctx->user_entropy) {
        ctx->user_entropy = SC_MALLOC(sizeof(user_entropy_t));
        if (NULL == ctx->user_entropy) {
            return SC_FUNC_FAILURE;
        }
    }
    ctx->user_entropy->data = entropy;
    ctx->user_entropy->len  = len;

    return SC_FUNC_SUCCESS;
}

SINT32 prng_set_entropy_callback(prng_entropy_callback cb)
{
    entropy_callback = cb;
    return SC_FUNC_SUCCESS;
}

SINT32 prng_init(prng_ctx_t *ctx, const UINT8 *nonce, size_t len_nonce)
{
    // Configure the entropy source type (and initialise random() if it
    // is being used as a PRNG)
    func_get_random_entropy fn_entropy;
    if (SC_FUNC_FAILURE == config_entropy(ctx->entropy, ctx->type, &fn_entropy)) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the selected PRNG/CSPRNG
    if (SC_FUNC_FAILURE == config_csprng(ctx, fn_entropy, nonce, len_nonce)) {
        return SC_FUNC_FAILURE;
    }

    return SC_FUNC_SUCCESS;
}

safecrypto_prng_e prng_get_type(prng_ctx_t *ctx)
{
    if (NULL == ctx) {
        return SC_PRNG_SYSTEM;
    }
    return ctx->type;
}

SINT32 prng_destroy(prng_ctx_t *ctx)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }

#if 0
    if (ctx->mt_enabled) {
        // Empty all of the pipes
        /*UINT32 u32;
        while (0 != pipe_pull(ctx->pipe_u32_consumer, &u32, 1)) {
            fprintf(stderr, "u32 pipe pull\n");
        }
        fprintf(stderr, "u32 pipe cleared\n");
        UINT16 u16;
        while (pipe_pull_eager(ctx->pipe_u16_consumer, &u16, 1)) {
        }
        UINT8 u8;
        while (pipe_pull_eager(ctx->pipe_u8_consumer, &u8, 1)) {
        }
        FLOAT flt;
        while (pipe_pull_eager(ctx->pipe_flt_consumer, &flt, 1)) {
        }
        DOUBLE dbl;
        while (pipe_pull_eager(ctx->pipe_dbl_consumer, &dbl, 1)) {
        }*/

        // Destroy the pipes
        pipe_pull(ctx->pipe_u32_consumer, ctx->random_pool, RANDOM_POOL_SIZE);// + ctx->wr_idx, RANDOM_POOL_SIZE - ctx->wr_idx);
        pipe_destroy(ctx->pipe_u32);
        pipe_destroy(ctx->pipe_u16);
        pipe_destroy(ctx->pipe_u8);
        pipe_destroy(ctx->pipe_flt);
        pipe_destroy(ctx->pipe_dbl);
        pipe_consumer_destroy(ctx->pipe_u32_consumer);
        pipe_consumer_destroy(ctx->pipe_u16_consumer);
        pipe_consumer_destroy(ctx->pipe_u8_consumer);
        pipe_consumer_destroy(ctx->pipe_flt_consumer);
        pipe_consumer_destroy(ctx->pipe_dbl_consumer);

        // Destroy the threadpool
        //threadpool_wait(ctx->pool);
        threadpool_destroy(ctx->pool, THREADPOOL_GRACEFUL_EXIT);
    }
#endif

    switch (ctx->type)
    {
#ifdef ENABLE_AES
        case SC_PRNG_AES_CTR_DRBG:
        {
            ctr_drbg_destroy(ctx->ctr_drbg_ctx);
        } break;
#endif
#ifdef ENABLE_AES_CTR_STREAM
        case SC_PRNG_AES_CTR:
        {
            aes_ctr_destroy(ctx->aes_ctr_ctx);
        } break;
#endif
#ifdef ENABLE_KISS
        case SC_PRNG_KISS:
        {
            destroy_kiss(ctx->kiss_ctx);
        } break;
#endif
#ifdef ENABLE_ISAAC
        case SC_PRNG_ISAAC:
        {
            destroy_isaac(ctx->isaac_ctx);
        } break;
#endif
#ifdef ENABLE_CHACHA20
        case SC_PRNG_CHACHA:
        {
            destroy_chacha20(ctx->chacha20_ctx);
        } break;
#endif
#ifdef ENABLE_SALSA20
        case SC_PRNG_SALSA:
        {
            destroy_salsa20(ctx->salsa20_ctx);
        } break;
#endif
#ifdef ENABLE_HASH_DRBG
        case SC_PRNG_HASH_DRBG_WHIRLPOOL_512:
        case SC_PRNG_HASH_DRBG_BLAKE2_256:
        case SC_PRNG_HASH_DRBG_BLAKE2_512:
        case SC_PRNG_HASH_DRBG_SHA3_512:
        case SC_PRNG_HASH_DRBG_SHA3_256:
        case SC_PRNG_HASH_DRBG_SHA2_512:
        case SC_PRNG_HASH_DRBG_SHA2_256:
        {
            hash_drbg_destroy(ctx->hash_drbg_ctx);
        } break;
#endif
        default :;
    }

    if (ctx->user_entropy) {
        SC_FREE(ctx->user_entropy, sizeof(user_entropy_t));
    }

    SC_FREE(ctx->random_pool, sizeof(UINT32) * RANDOM_POOL_SIZE);
    SC_FREE(ctx, sizeof(prng_ctx_t));

    return SC_FUNC_SUCCESS;
}

void prng_reset(prng_ctx_t *ctx)
{
    // Reset buffer control variables
    ctx->bits     = 0;
    ctx->wr_idx   = 0;
    ctx->rd_idx   = 0;
    ctx->var_bits = 0;

    // Reset the statistics variables
    ctx->stats_csprng_bytes = 0;
    ctx->stats_out_bytes = 0;

    // Initialise the user selected PRNG/CSPRNG and configure the 32-bit
    // random number GET function
    safecrypto_prng_e type = ctx->type;
    switch (type)
    {
        case SC_PRNG_AES_CTR_DRBG:
            {
                ctr_drbg_reset(ctx->ctr_drbg_ctx);
            } break;

#ifdef ENABLE_AES_CTR_STREAM
        case SC_PRNG_AES_CTR:
            {
                aes_ctr_reset(ctx->aes_ctr_ctx;
            } break;
#endif

#ifdef ENABLE_CHACHA20
        case SC_PRNG_CHACHA:
            {
                reset_chacha20(ctx->chacha20_ctx);
            } break;
#endif

#ifdef ENABLE_SALSA20
        case SC_PRNG_SALSA:
            {
                reset_salsa20(ctx->salsa20_ctx);
            } break;
#endif

#ifdef ENABLE_ISAAC
        case SC_PRNG_ISAAC:
            {
                reset_isaac(ctx->isaac_ctx);
            } break;
#endif

#ifdef ENABLE_KISS
        case SC_PRNG_KISS:
            {
                reset_kiss(ctx->kiss_ctx);
            } break;
#endif

#ifdef ENABLE_HASH_DRBG
        case SC_PRNG_HASH_DRBG_SHA2_256:
        case SC_PRNG_HASH_DRBG_SHA2_512:
        case SC_PRNG_HASH_DRBG_SHA3_256:
        case SC_PRNG_HASH_DRBG_SHA3_512:
        case SC_PRNG_HASH_DRBG_BLAKE2_256:
        case SC_PRNG_HASH_DRBG_BLAKE2_512:
        case SC_PRNG_HASH_DRBG_WHIRLPOOL_512:
            {
                hash_drbg_reset(ctx->hash_drbg_ctx);
            } break;
#endif
        default:;
    }
}

UINT64 prng_get_csprng_bytes(prng_ctx_t *ctx)
{
    return ctx->stats_csprng_bytes;
}

UINT64 prng_get_out_bytes(prng_ctx_t *ctx)
{
    return ctx->stats_out_bytes;
}

SINT32 prng_bit(prng_ctx_t *ctx)
{
    return (SINT32) prng_var(ctx, 1);
}

#if defined(HAVE_128BIT) && defined(__x86_64__)
UINT128 prng_128(prng_ctx_t *ctx)
{
    UINT128 u128;

    u128   = prng_64(ctx);
    u128 <<= 64;
    u128  |= prng_64(ctx);

    return u128;
}
#endif

#ifdef HAVE_64BIT
UINT64 prng_64(prng_ctx_t *ctx)
{
    UINT64 u64;

    update_pool(ctx);
    u64  = ctx->random_pool[ctx->rd_idx];
    u64 <<= 32;
    decrease_pool_bits(ctx);
    update_pool(ctx);
    u64 |= ctx->random_pool[ctx->rd_idx];
    decrease_pool_bits(ctx);

    ctx->stats_out_bytes += 8;

    return u64;
}
#endif

UINT32 prng_32(prng_ctx_t *ctx)
{
    UINT32 u32;

    update_pool(ctx);

    u32  = ctx->random_pool[ctx->rd_idx];
    decrease_pool_bits(ctx);

    ctx->stats_out_bytes += 4;

    return u32;
}

UINT16 prng_16(prng_ctx_t *ctx)
{
    return (UINT16) prng_var(ctx, 16);
}

UINT8 prng_8(prng_ctx_t *ctx)
{
    return (UINT16) prng_var(ctx, 8);
}

FLOAT prng_float(prng_ctx_t *ctx)
{
    return ((FLOAT) prng_32(ctx)) / UINT32_MAX;
}

DOUBLE prng_double(prng_ctx_t *ctx)
{
    UINT32 a = prng_var(ctx, 27);
    UINT32 b = prng_var(ctx, 26);
    return (a * RND_DBL_NUM_SCALE + b) * RND_DBL_DEN_SCALE;
}

UINT32 prng_var(prng_ctx_t *ctx, size_t n)
{
    UINT32 retval;
    UINT32 mask;

    // To prevent shifting out of bounds ...
    if (n >= 32) {
        n = 32;
        mask = 0xFFFFFFFF;
    }
    else {
        mask = (1 << n) - 1;
    }

    // If too few bits are available, re-populate the
    // variable buffer to obtain the outstanding data
    retval = ctx->var_buf;
    if (ctx->var_bits < n) {
        size_t bits = n - ctx->var_bits;
        retval <<= bits;
        ctx->var_buf = prng_32(ctx);
        retval |= ctx->var_buf & ((1 << bits) - 1);
        ctx->var_buf >>= bits;
        ctx->var_bits = 32 - bits;
    }
    else {
        ctx->var_buf >>= n;
        ctx->var_bits -= n;
    }

    return retval & mask;
}

SINT32 prng_mem(prng_ctx_t *ctx, UINT8 *mem, SINT32 length)
{
    // Ignore the input buffer which we use to ensure all generated bits are used and
    // directly obtai =n a block of dta from the CSPRNG. This is to improve the speed
    // by bypassing the interim buffer and allow the copy to use SIMD instrutions.

    UINT8 *p = mem;

    union u {
        UINT64 u64[8];
        UINT32 u32[16];
        UINT8 u8[64];
    };

    SINT32 num_blocks = (length + 63) >> 6;
    union u data;
    while (num_blocks--) {
#ifdef HAVE_64BIT
        data.u64[0] = ctx->get_random_64(ctx);
        data.u64[1] = ctx->get_random_64(ctx);
        data.u64[2] = ctx->get_random_64(ctx);
        data.u64[3] = ctx->get_random_64(ctx);
        data.u64[4] = ctx->get_random_64(ctx);
        data.u64[5] = ctx->get_random_64(ctx);
        data.u64[6] = ctx->get_random_64(ctx);
        data.u64[7] = ctx->get_random_64(ctx);
#else
        data.u32[0] = ctx->get_random_32(ctx);
        data.u32[1] = ctx->get_random_32(ctx);
        data.u32[2] = ctx->get_random_32(ctx);
        data.u32[3] = ctx->get_random_32(ctx);
        data.u32[4] = ctx->get_random_32(ctx);
        data.u32[5] = ctx->get_random_32(ctx);
        data.u32[6] = ctx->get_random_32(ctx);
        data.u32[7] = ctx->get_random_32(ctx);
        data.u32[8] = ctx->get_random_32(ctx);
        data.u32[9] = ctx->get_random_32(ctx);
        data.u32[10] = ctx->get_random_32(ctx);
        data.u32[11] = ctx->get_random_32(ctx);
        data.u32[12] = ctx->get_random_32(ctx);
        data.u32[13] = ctx->get_random_32(ctx);
        data.u32[14] = ctx->get_random_32(ctx);
        data.u32[15] = ctx->get_random_32(ctx);
#endif
        SC_MEMCOPY(p, data.u8, (length >= 64)? 64 : length);
        length -= 64;
        p += 64;
    }

#if 0
    length &= 0x3F;
    while (length--) {
        UINT32 u8 = prng_var(ctx, 8);
        *p++ = (UINT8) u8;
    }
#endif

    return SC_FUNC_SUCCESS;
}

#ifdef _ENABLE_CSPRNG_FILE
SINT32 prng_set_debug_file(prng_ctx_t *ctx, const char *filename)
{
    if (NULL == ctx) {
        fprintf(stderr, "ERROR! ctx pointer is NULL!\n");
        return SC_FUNC_FAILURE;
    }

    if (NULL == filename) {
        fprintf(stderr, "ERROR! filename pointer is NULL!\n");
        return SC_FUNC_FAILURE;
    }
    else if (strlen(filename) >= sizeof(ctx->debug_filename)) {
        fprintf(stderr, "ERROR! filename is too large!\n");
        return SC_FUNC_FAILURE;
    }
    else {
        strcpy(ctx->debug_filename, filename);
        return SC_FUNC_SUCCESS;
    }
}
#endif
