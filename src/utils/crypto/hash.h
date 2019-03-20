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


/// Function pointers for a common hash interface
///@{
typedef SINT32 (*hash_func_make_copy)(void *, void*);
typedef SINT32 (*hash_func_init)(void *, SINT32);
typedef SINT32 (*hash_func_update)(void *, const void *, size_t);
typedef SINT32 (*hash_func_final)(void *, void *);
///@}

/// A struct used to store an instantiated hash
SC_STRUCT_PACK_START
typedef struct _utils_crypto_hash {
    sc_hash_e           type;
    size_t              length;
    hash_func_make_copy copy;
    hash_func_init      init;
    hash_func_update    update;
    hash_func_final     final;
    void                *ctx;
} SC_STRUCT_PACKED utils_crypto_hash_t;
SC_STRUCT_PACK_END

/// Create an instance of the selected hash function
extern utils_crypto_hash_t * utils_crypto_hash_create(sc_hash_e type);

/// Destroy an instance of a hash and release all memory resources
extern SINT32 utils_crypto_hash_destroy(utils_crypto_hash_t* hash);

/// The common hash API function used to obtain the type of hash function
/// @return Returns CRYPTO_HASH_MAX upon failure
extern sc_hash_e hash_get_type(utils_crypto_hash_t *c);

/// The common hash API function used to obtain the message digest length in bytes
/// @return Returns 0 on failure, otherwise returns the size in bytes
extern size_t hash_length(utils_crypto_hash_t *c);

/// The common hash API function used to initialise
extern utils_crypto_hash_t * hash_make_copy(utils_crypto_hash_t *c);

/// The common hash API function used to initialise
extern SINT32 hash_init(utils_crypto_hash_t *c);

/// The common hash API function used to update using a specified byte array
extern SINT32 hash_update(utils_crypto_hash_t *c, const void *data, size_t len);

/// The common hash API function used to finalize the hash output
extern SINT32 hash_final(utils_crypto_hash_t *c, void *md);


