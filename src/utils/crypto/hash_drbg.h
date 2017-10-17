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

#include "hash.h"


// The maximum threshold at which the HASH-DRBG is reseeded
#define HASH_DRBG_MAX_RESEED  0x10000000

// The maximum threshold at which the HASH-DRBG is reseeded
#define HASH_DRBG_MIN_RESEED  0x00000100


typedef struct user_entropy user_entropy_t;
typedef struct _utils_crypto_hash utils_crypto_hash_t;

typedef void (*func_get_random)(size_t, UINT8 *, user_entropy_t *);

/// A struct that stores the HASH-DRBG context
PRNG_STRUCT_PACK_START
typedef struct hash_drbg_t {
    utils_crypto_hash_t *ctx_hash;
    func_get_random      get_random;
    user_entropy_t      *entropy_arg;
    UINT32               reseed_ctr;
    UINT32               seed_period;
    UINT32               counter;
    UINT8                v[1 + (888>>3)];
    UINT8                c[(888>>3)];
    UINT8                df[64];
    UINT8*               temp;
    UINT32               len_nonce;
    UINT8                nonce[32];
} PRNG_STRUCT_PACKED hash_drbg_t;
PRNG_STRUCT_PACK_END


/// Create an instance of the HASH-DRBG
hash_drbg_t* hash_drbg_create(func_get_random func,
    user_entropy_t *user_entropy, crypto_hash_e hash, size_t seed_period,
    const UINT8 *nonce, size_t len_nonce);

/// Free resources associated with the specified HASH-DRBG
SINT32 hash_drbg_destroy(hash_drbg_t *ctx);

/// Reset the HASH-DRBG to its initial state
SINT32 hash_drbg_reset(hash_drbg_t *ctx);

/// Reseed the HASH-DRBG, this is done automatically every seed_period calls
/// to aes_prng_update()
SINT32 hash_drbg_reseed(hash_drbg_t *ctx);

/// Generate another block of random data, reseeding if necessary
SINT32 hash_drbg_update(hash_drbg_t *ctx, UINT8 *bytes, size_t num);
