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

#include "prng_types.h"


void get_entropy_callback(size_t n, UINT8 *data, user_entropy_t *p);
#ifndef ENABLE_BAREMETAL
#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
void get_entropy_posix(size_t n, UINT8 *data, user_entropy_t *p);
void get_entropy_dev_random(size_t n, UINT8 *data, user_entropy_t *p);
void get_entropy_dev_urandom(size_t n, UINT8 *data, user_entropy_t *p);
#else // WINDOWS
#endif
#endif

void get_entropy_user(size_t n, UINT8 *data, user_entropy_t *p);


#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
UINT32 get_random_32_posix(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_posix(prng_ctx_t *ctx);
#endif
#else // WINDOWS
UINT32 get_random_32_windows(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_windows(prng_ctx_t *ctx);
#endif
#endif

#ifdef ENABLE_AES
UINT32 get_random_32_aes(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_aes(prng_ctx_t *ctx);
#endif
#endif // ENABLE_AES

#ifdef ENABLE_ISAAC
UINT32 get_random_32_isaac(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_isaac(prng_ctx_t *ctx);
#endif
#endif // ENABLE_ISAAC

#ifdef ENABLE_CHACHA20
UINT32 get_random_32_chacha(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_chacha(prng_ctx_t *ctx);
#endif
#endif // ENABLE_CHACHA20

#ifdef ENABLE_SALSA20
UINT32 get_random_32_salsa(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_salsa(prng_ctx_t *ctx);
#endif
#endif // ENABLE_SALSA20

#ifdef ENABLE_AES_CTR_STREAM
UINT32 get_random_32_aes_ctr(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_aes_ctr(prng_ctx_t *ctx);
#endif
#endif // ENABLE_AES_CTR_STREAM

#ifdef ENABLE_KISS
UINT32 get_random_32_kiss(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_kiss(prng_ctx_t *ctx);
#endif
#endif // ENABLE_KISS

#ifdef ENABLE_HASH_DRBG
UINT32 get_random_32_hash_drbg(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_hash_drbg(prng_ctx_t *ctx);
#endif
#endif

UINT32 get_random_32_high_entropy(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_high_entropy(prng_ctx_t *ctx);
#endif

#ifndef CONSTRAINED_SYSTEM
#ifdef _ENABLE_CSPRNG_FILE
UINT32 get_random_32_file(prng_ctx_t *ctx);
#ifdef HAVE_64BIT
UINT64 get_random_64_file(prng_ctx_t *ctx);
#endif
#endif
#endif // !CONSTRAINED_SYSTEM
