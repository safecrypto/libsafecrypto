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

#include <string.h>


/// A list of the available schemes
#define CRYPTO_HASH_LIST(m) \
   m(CRYPTO_HASH_SHA3_512) \
   m(CRYPTO_HASH_SHA3_384) \
   m(CRYPTO_HASH_SHA3_256) \
   m(CRYPTO_HASH_SHA3_224) \
   m(CRYPTO_HASH_SHA2_512) \
   m(CRYPTO_HASH_SHA2_384) \
   m(CRYPTO_HASH_SHA2_256) \
   m(CRYPTO_HASH_SHA2_224) \
   m(CRYPTO_HASH_BLAKE2_512) \
   m(CRYPTO_HASH_BLAKE2_384) \
   m(CRYPTO_HASH_BLAKE2_256) \
   m(CRYPTO_HASH_BLAKE2_224) \
   m(CRYPTO_HASH_WHIRLPOOL_512) \
   m(CRYPTO_HASH_SHAKE128_256) \
   m(CRYPTO_HASH_SHAKE256_512)


/// An enumerated type for the choice of hash algorithm
GENERATE_ENUM(crypto_hash_e, CRYPTO_HASH_LIST, CRYPTO_HASH_MAX);

/// A list of the hash algorithms in the form of human readable strings
__attribute__((unused))
GENERATE_ENUM_NAMES(crypto_hash_names, CRYPTO_HASH_LIST, CRYPTO_HASH_MAX);


/// Function pointers for a common hash interface
///@{
typedef SINT32 (*hash_func_init)(void *, SINT32);
typedef SINT32 (*hash_func_update)(void *, const void *, size_t);
typedef SINT32 (*hash_func_final)(void *, void *);
///@}

/// A struct used to store an instantiated hash
PRNG_STRUCT_PACK_START
typedef struct _utils_crypto_hash {
    crypto_hash_e     type;
    size_t            length;
    hash_func_init    init;
    hash_func_update  update;
    hash_func_final   final;
    void             *ctx;
} PRNG_STRUCT_PACKED utils_crypto_hash_t;
PRNG_STRUCT_PACK_END

/// Create an instance of the selected hash function
extern utils_crypto_hash_t * utils_crypto_hash_create(crypto_hash_e type);

/// Destroy an instance of a hash and release all memory resources
extern SINT32 utils_crypto_hash_destroy(utils_crypto_hash_t* hash);

/// The common hash API function used to initialise
extern SINT32 hash_init(utils_crypto_hash_t *c);

/// The common hash API function used to update using a specified byte array
extern SINT32 hash_update(utils_crypto_hash_t *c, const void *data, size_t len);

/// The common hash API function used to finalize the hash output
extern SINT32 hash_final(utils_crypto_hash_t *c, void *md);


