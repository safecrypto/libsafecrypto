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

#include "prng_get_func.h"

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
#include <stdio.h>
#endif
#endif

#ifdef HAVE_64BIT
#include "isaac/isaac64.h"
#else
#include "isaac/rand.h"
#endif
#include "hash_drbg.h"
#include "ctr_drbg.h"
#include "aes_ctr_stream.h"
#include "kiss.h"
#include "chacha20_csprng.h"
#include "salsa20_csprng.h"
#include "isaac_csprng.h"


prng_entropy_callback entropy_callback;

void get_entropy_callback(size_t n, UINT8 *data, user_entropy_t *p)
{
    (void) p;
    entropy_callback(n, data);
}

#if defined(ENABLE_BAREMETAL)
#elif defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
void get_entropy_posix(size_t n, UINT8 *data, user_entropy_t *p)
{
    (void) p;

    UINT32 word = 0;
    size_t i = 0;
    while (i < n) {
        if (0 == (i&3)) {
            word = random() ^ (random() << 1);
        }
        data[i] = word >> (8*(i&3));
        i++;
    }
}

void get_entropy_dev_random(size_t n, UINT8 *data, user_entropy_t *p)
{
    (void) p;

    FILE *fp;
    SINT32 byte_count = n;

    fp = fopen("/dev/random", "r");
    if (NULL == fp) {
        // Fallback to random() when /dev/random can't be opened
        return get_entropy_posix(n, data, NULL);
    }
    while ((byte_count -= fread(data, 1, byte_count, fp)) != 0) {}
    fclose(fp);
}

void get_entropy_dev_urandom(size_t n, UINT8 *data, user_entropy_t *p)
{
    (void) p;

    FILE *fp;
    SINT32 byte_count = n;

    fp = fopen("/dev/urandom", "r");
    if (NULL == fp) {
        // Fallback to random() when /dev/urandom can't be opened
        return get_entropy_posix(n, data, NULL);
    }
    while ((byte_count -= fread(data, 1, byte_count, fp)) != 0) {}
    fclose(fp);
}
#else // WINDOWS
#endif

void get_entropy_user(size_t n, UINT8 *data, user_entropy_t *p)
{
    // Entropy data is obtained from a circular buffer using the user
    // supplied entropy data
    size_t i;
    for (i=0; i<n; i++) {
        data[i] = p->data[p->idx++];
        if (p->idx == p->len) {
            p->idx = 0;
        }
    }
}


#if defined(ENABLE_BAREMETAL)
#elif defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
UINT32 get_random_32_posix(prng_ctx_t *ctx)
{
    ctx->stats_csprng_bytes += 4;
    return random() ^ (random() << 1);
}

#ifdef HAVE_64BIT
UINT64 get_random_64_posix(prng_ctx_t *ctx)
{
    ctx->stats_csprng_bytes += 8;
    return (UINT64)random() | ((UINT64)random() << 31) | ((UINT64)(random() & 0x3) << 62);
}
#endif
#else // WINDOWS
UINT32 get_random_32_windows(prng_ctx_t *ctx)
{
    long rand_buf;
    (void) CryptGenRandom(ctx->hCryptProv, sizeof(rand_buf), (BYTE *)&rand_buf);
    ctx->stats_csprng_bytes += 4;
    return rand_buf;
}

#ifdef HAVE_64BIT
UINT64 get_random_64_windows(prng_ctx_t *ctx)
{
    UINT64 rand_buf;
    (void) CryptGenRandom(ctx->hCryptProv, sizeof(rand_buf), (BYTE *)&rand_buf);
    ctx->stats_csprng_bytes += 8;
    return rand_buf;
}
#endif
#endif


#ifdef ENABLE_AES
UINT32 get_random_32_aes(prng_ctx_t *ctx)
{
    UINT32 temp;

    if ((CSPRNG_BUFFER_SIZE/sizeof(UINT32)) == ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        ctr_drbg_update(ctx->ctr_drbg_ctx, ctx->rng_buffer.b);
    }

    temp = ctx->rng_buffer.w[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 4;
    return temp;
}

#ifdef HAVE_64BIT
UINT64 get_random_64_aes(prng_ctx_t *ctx)
{
#if 1
    UINT64 temp;

    if ((CSPRNG_BUFFER_SIZE/sizeof(UINT64)) == ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        ctr_drbg_update(ctx->ctr_drbg_ctx, ctx->rng_buffer.b);
    }

    temp = ctx->rng_buffer.w64[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 8;
    return temp;
#else
    UINT64 r = get_random_32_aes(ctx);
    r <<= 32;
    r |= get_random_32_aes(ctx);
    return r;
#endif
}
#endif
#endif // ENABLE_AES


#ifdef ENABLE_ISAAC

UINT32 get_random_32_isaac(prng_ctx_t *ctx)
{
    ctx->stats_csprng_bytes += 4;
    return isaac_random_32(ctx->isaac_ctx);
}

#ifdef HAVE_64BIT
UINT64 get_random_64_isaac(prng_ctx_t *ctx)
{
#if 1
	UINT64 temp;

    if ((CSPRNG_BUFFER_SIZE/sizeof(UINT64)) == ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        size_t i;
        for (i=(CSPRNG_BUFFER_SIZE/sizeof(UINT64)); i--;) {
        	ctx->rng_buffer.w64[i] = isaac_random_64(ctx->isaac_ctx);
        }
    }

    temp  = ctx->rng_buffer.w64[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 8;
    return temp;
#else
    ctx->stats_csprng_bytes += 8;
    return isaac_random_64(ctx->isaac_ctx);
#endif
}
#endif

#endif // ENABLE_ISAAC


#ifdef ENABLE_CHACHA20

UINT32 get_random_32_chacha(prng_ctx_t *ctx)
{
    ctx->stats_csprng_bytes += 4;
    return chacha20_random_32(ctx->chacha20_ctx);
}

#ifdef HAVE_64BIT
UINT64 get_random_64_chacha(prng_ctx_t *ctx)
{
#if 0
	UINT64 temp;
	if ((CSPRNG_BUFFER_SIZE/sizeof(UINT64)) - 1 <= ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        size_t i;
        for (i=(CSPRNG_BUFFER_SIZE/sizeof(UINT32)); i--;) {
        	ctx->rng_buffer.w[i] = chacha20_random_32(ctx->chacha20_ctx);
        }
    }

    temp  = ctx->rng_buffer.w64[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 8;
    return temp;
#else
    ctx->stats_csprng_bytes += 8;
    return chacha20_random_64(ctx->chacha20_ctx);
#endif
}
#endif
#endif // ENABLE_CHACHA20


#ifdef ENABLE_SALSA20

UINT32 get_random_32_salsa(prng_ctx_t *ctx)
{
    ctx->stats_csprng_bytes += 4;
    return salsa20_random_32(ctx->salsa20_ctx);
}

#ifdef HAVE_64BIT
UINT64 get_random_64_salsa(prng_ctx_t *ctx)
{
#if 0
	UINT64 temp;
	if ((CSPRNG_BUFFER_SIZE/sizeof(UINT64)) - 1 <= ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        size_t i;
        for (i=(CSPRNG_BUFFER_SIZE/sizeof(UINT32)); i--;) {
        	ctx->rng_buffer.w[i] = salsa20_random_32(ctx->salsa20_ctx);
        }
    }

    temp  = ctx->rng_buffer.w64[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 8;
    return temp;
#else
    ctx->stats_csprng_bytes += 8;
    return salsa20_random_64(ctx->salsa20_ctx);
#endif
}
#endif

#endif // ENABLE_SALSA20


#ifdef ENABLE_AES_CTR_STREAM
UINT32 get_random_32_aes_ctr(prng_ctx_t *ctx)
{
	UINT32 temp;

    if ((CSPRNG_BUFFER_SIZE/sizeof(UINT32)) == ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        aes_ctr_update(ctx->aes_ctr_ctx, ctx->rng_buffer.b, CSPRNG_BUFFER_SIZE);
    }

    temp = ctx->rng_buffer.w[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 4;
    return temp;
}

#ifdef HAVE_64BIT
UINT64 get_random_64_aes_ctr(prng_ctx_t *ctx)
{
#if 0
    UINT64 temp;

    if ((CSPRNG_BUFFER_SIZE/sizeof(UINT64)) - 1 <= ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        aes_ctr_update(ctx->aes_ctr_ctx, ctx->rng_buffer.b, CSPRNG_BUFFER_SIZE);
    }

    temp = ctx->rng_buffer.w64[ctx->rng_cnt];
    ctx->rng_cnt += 2;
    ctx->stats_csprng_bytes += 8;
    return temp;
#else
	UINT64 r = get_random_32_aes_ctr(ctx);
    r <<= 32;
    r |= get_random_32_aes_ctr(ctx);
#endif
}
#endif
#endif // ENABLE_AES_CTR_STREAM


#ifdef ENABLE_KISS
UINT32 get_random_32_kiss(prng_ctx_t *ctx)
{
    ctx->stats_csprng_bytes += 4;
    return kiss_random_32(ctx->kiss_ctx);
}

#ifdef HAVE_64BIT
UINT64 get_random_64_kiss(prng_ctx_t *ctx)
{
#if 0
	UINT64 temp;

    if ((CSPRNG_BUFFER_SIZE/sizeof(UINT64)) - 1 <= ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        size_t i;
        for (i=(CSPRNG_BUFFER_SIZE/sizeof(UINT64)); i--;) {
        	ctx->rng_buffer.w[i] = kiss_random_64(ctx->kiss_ctx);
        }
    }

    temp  = ctx->rng_buffer.w64[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 8;
    return temp;
#else
    ctx->stats_csprng_bytes += 8;
    return kiss_random_64(ctx->kiss_ctx);
#endif
}
#endif
#endif // ENABLE_KISS


#ifdef ENABLE_HASH_DRBG
UINT32 get_random_32_hash_drbg(prng_ctx_t *ctx)
{
    UINT32 temp;

    if ((CSPRNG_BUFFER_SIZE/sizeof(UINT32)) == ctx->rng_cnt) {
        ctx->rng_cnt = 0;
        hash_drbg_update(ctx->hash_drbg_ctx, ctx->rng_buffer.b, CSPRNG_BUFFER_SIZE);
    }

    temp = ctx->rng_buffer.w[ctx->rng_cnt++];
    ctx->stats_csprng_bytes += 4;
    return temp;
}

#ifdef HAVE_64BIT
UINT64 get_random_64_hash_drbg(prng_ctx_t *ctx)
{
    UINT64 r = get_random_32_hash_drbg(ctx);
    r <<= 32;
    r |= get_random_32_hash_drbg(ctx);
    return r;
}
#endif
#endif // ENABLE_HASH_DRBG


#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
UINT32 get_random_32_high_entropy(prng_ctx_t *ctx)
{
    (void) ctx;
    UINT8 data[4];
#if defined(ENABLE_BAREMETAL)
    // Insert a high entropy random number source here ...
    data[0] = 0;
    data[1] = 1;
    data[2] = 2;
    data[3] = 3;
#elif 0
    syscall(SYS_getrandom, data, 4*sizeof(UINT8), GRND_NONBLOCK);
#else
    FILE *fp;
    SINT32 byte_count = 4;
    fp = fopen("/dev/urandom", "r");
    if (NULL == fp) {
        return get_random_32_posix(ctx);
    }
    while ((byte_count -= fread(data, 1, byte_count, fp)) != 0) {}
    fclose(fp);
#endif

    ctx->stats_csprng_bytes += 4;
    return ((UINT32)data[0] << 24) |
           ((UINT32)data[1] << 16) |
           ((UINT32)data[2] <<  8) |
            (UINT32)data[3];
}

#ifdef HAVE_64BIT
UINT64 get_random_64_high_entropy(prng_ctx_t *ctx)
{
    (void) ctx;
    UINT8 data[8];
#if defined(ENABLE_BAREMETAL)
    // Insert a high entropy random number source here ...
    data[0] = 0;
    data[1] = 1;
    data[2] = 2;
    data[3] = 3;
    data[4] = 4;
    data[5] = 5;
    data[6] = 6;
    data[7] = 7;
#elif 0
    syscall(SYS_getrandom, data, 8*sizeof(UINT8), GRND_NONBLOCK);
#else
    FILE *fp;
    SINT32 byte_count = 8;
    fp = fopen("/dev/urandom", "r");
    if (NULL == fp) {
        return get_random_32_posix(ctx);
    }
    while ((byte_count -= fread(data, 1, byte_count, fp)) != 0) {}
    fclose(fp);
#endif

    ctx->stats_csprng_bytes += 8;
    return ((UINT64)data[0] << 56) |
           ((UINT64)data[1] << 48) |
           ((UINT64)data[2] << 40) |
           ((UINT64)data[3] << 32) |
           ((UINT64)data[4] << 24) |
           ((UINT64)data[5] << 16) |
           ((UINT64)data[6] <<  8) |
            (UINT64)data[7];
}
#endif

#ifdef _ENABLE_CSPRNG_FILE
UINT32 get_random_32_file(prng_ctx_t *ctx)
{
    ctx->stats_csprng_bytes += 4;

    // Check if data is available
    if (NULL == ctx->debug_data) {
        fprintf(stderr, "Opening file\n");
        // Find the size of the file
        FILE *fp;
        if (NULL == (fp = fopen(ctx->debug_filename, "rb"))) {
            fprintf(stderr, "Couldn't open file to obtain size\n");
            return 0;
        }
        fseek(fp, 0L, SEEK_END);
        long int sz = ftell(fp);
        fclose(fp);

        fprintf(stderr, "Reading %d bytes\n", sz);

        // Allocate memory for the file contents
        ctx->debug_data = PRNG_MALLOC(sz * sizeof(UINT8));
        if (NULL == ctx->debug_data) {
            fprintf(stderr, "Couldn't allocate memory\n");
            return 0;
        }

        // Read data into memory
        if (NULL == (fp = fopen(ctx->debug_filename, "rb"))) {
            PRNG_FREE(ctx->debug_data, sz * sizeof(UINT8));
            fprintf(stderr, "Couldn't open file for reading\n");
            return 0;
        }
        ctx->debug_length = sz;
        while (0 != (sz -= fread(ctx->debug_data, 1, sz, fp))) {}
        fclose(fp);

        // Reset the read pointer to zero
        ctx->debug_ptr = 0;
    }

    // Read 32 bits from the random data buffer
    UINT32 r = 0;
    for (size_t i=0; i<4; i++) {
        r <<= 8;
        r |= ctx->debug_data[ctx->debug_ptr++];

        // Reset the read pointer at the end of the memory contents
        if (ctx->debug_ptr == ctx->debug_length) {
            ctx->debug_ptr = 0;
        }
    }
    return r;
}

#ifdef HAVE_64BIT
UINT64 get_random_64_file(prng_ctx_t *ctx)
{
    UINT64 r = get_random_32_file(ctx);
    r <<= 32;
    r |= get_random_32_file(ctx);

    ctx->stats_csprng_bytes += 8;
    return r;
}
#endif
#endif
#endif // CONSTRAINED_SYSTEM


