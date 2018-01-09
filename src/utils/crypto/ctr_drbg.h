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
#include "aes/aes.h"


// The maximum threshold at which the CTR-DRBG is reseeded (2^31 blocks)
#define CTR_DRBG_MAX_RESEED  0x80000000

// The minimum threshold at which the CTR-DRBG is reseeded
// (i.e. 2^19 bits or 2^12 blocks)
#define CTR_DRBG_MIN_RESEED  0x00001000

typedef struct user_entropy user_entropy_t;

typedef void (*func_get_random)(size_t, UINT8 *, user_entropy_t *);

/// A struct that stores the CTR-DRBG context
SC_STRUCT_PACK_START
typedef struct ctx_ctr_drbg_t {
    aes_encrypt_ctx ctx_aes;
    func_get_random get_random;
    user_entropy_t *entropy_arg;
    UINT32          reseed_ctr;
    UINT32          seed_period;
    UINT32          counter;
    UINT8           key[32];
} SC_STRUCT_PACKED ctx_ctr_drbg_t;
SC_STRUCT_PACK_END


/// Create an instance of the CTR-DRBG
ctx_ctr_drbg_t* ctr_drbg_create(func_get_random func,
    user_entropy_t *user_entropy, size_t seed_period);

/// Free resources associated with the specified CTR-DRBG
SINT32 ctr_drbg_destroy(ctx_ctr_drbg_t *ctx);

/// Reset the CTR-DRBG to its initial state
SINT32 ctr_drbg_reset(ctx_ctr_drbg_t *ctx);

/// Reseed the CTR-DRBG, this is done automatically every seed_period calls
/// to aes_prng_update()
SINT32 ctr_drbg_reseed(ctx_ctr_drbg_t *ctx);

/// Generate another 64 bytes of random data, reseeding if necessary
SINT32 ctr_drbg_update(ctx_ctr_drbg_t *ctx, UINT8 *bytes);
