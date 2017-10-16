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

#include <stdint.h>
#include "safecrypto_private.h"

/// @todo This makes the scheme implementation specific and will result in compatibility issues
/// Permit the transmission of keys in the NTT "domain"
#define RLWE_ENC_ENABLE_NTT_TRANSMISSION

/// Scheme creation
SINT32 rlwe_enc_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 rlwe_enc_destroy(safecrypto_t *sc);

/// Key pair generation function
SINT32 rlwe_enc_keygen(safecrypto_t *);

/// Public key load function
SINT32 rlwe_enc_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Private key load function
SINT32 rlwe_enc_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Public key encode function used to disseminate the public key
SINT32 rlwe_enc_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Private key encode function used to disseminate the private key
SINT32 rlwe_enc_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Encrypt function that consumes an input message of N bits
SINT32 rlwe_enc_encrypt(safecrypto_t *sc, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to);

/// Decrypt function that re-creates the input message of N bits
SINT32 rlwe_enc_decrypt(safecrypto_t *sc, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to);

/// Return a C-string output detailing the operation of the specified RLWE instance
char * rlwe_enc_stats(safecrypto_t *sc);
