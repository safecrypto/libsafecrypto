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

#include "dlp_ibe_params.h"
#include <stdint.h>
#include "safecrypto_private.h"
#include "utils/crypto/hash.h"

#include "utils/arith/arith.h"
#include "utils/sampling/sampling.h"
#include "utils/threading/pipe.h"
#include "utils/threading/threadpool.h"


/// Create an instance of the DLP IBE scheme
SINT32 dlp_ibe_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Destroy the specified instance of DLP IBE
SINT32 dlp_ibe_destroy(safecrypto_t *sc);

/// Generate a key pair for DLP IBE
SINT32 dlp_ibe_keygen(safecrypto_t *sc);

/// Set key-pair lossless compression coding
SINT32 dlp_ibe_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv);

/// Get key-pair lossless compression coding
SINT32 dlp_ibe_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv);

/// Key load and encode functions for storage and transmission
/// @{
SINT32 dlp_ibe_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);
SINT32 dlp_ibe_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);
SINT32 dlp_ibe_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);
SINT32 dlp_ibe_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);
/// @}

/// Load a User Secret Key to be used for decryption purposes
SINT32 dlp_ibe_secret_key(safecrypto_t *sc, size_t sklen, const UINT8 *sk);

/// Extract a User Secret Key for the specified User ID
SINT32 dlp_ibe_extract(safecrypto_t *sc, size_t idlen, const UINT8 *id,
    size_t *sklen, UINT8 **sk);

/// Perform an IBE Encrypt operation with the specified ID
SINT32 dlp_ibe_encrypt(safecrypto_t *sc, size_t idlen, const UINT8* id,
    size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to);

/// Perform an IBE Decrypt operation with the specified ID and a User Secret key
/// loaded using dlp_ibe_secret_key
SINT32 dlp_ibe_decrypt(safecrypto_t *sc, size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to);

/// Obtain a string containing the statistics gathered by the DLP IBE instance
char * dlp_ibe_stats(safecrypto_t *sc);
