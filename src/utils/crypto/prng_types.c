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

#include "prng_types.h"
#include "safecrypto_private.h"

#include <stdlib.h>
#include <string.h>

const char *safecrypto_prng_names [16] = {
    "SC_PRNG_SYSTEM",
    "SC_PRNG_AES_CTR_DRBG",
    "SC_PRNG_AES_CTR",
    "SC_PRNG_CHACHA",
    "SC_PRNG_SALSA",
    "SC_PRNG_ISAAC",
    "SC_PRNG_KISS",
    "SC_PRNG_HASH_DRBG_SHA2_256",
    "SC_PRNG_HASH_DRBG_SHA2_512",
    "SC_PRNG_HASH_DRBG_SHA3_256",
    "SC_PRNG_HASH_DRBG_SHA3_512",
    "SC_PRNG_HASH_DRBG_BLAKE2_256",
    "SC_PRNG_HASH_DRBG_BLAKE2_512",
    "SC_PRNG_HASH_DRBG_WHIRLPOOL_512",
    "SC_PRNG_FILE",
    "SC_PRNG_HIGH_ENTROPY",
};

