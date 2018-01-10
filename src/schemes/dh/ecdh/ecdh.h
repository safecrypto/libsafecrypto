/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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
#include "hash.h"


typedef struct _ecdh_set_t ecdh_set_t;

SC_STRUCT_PACK_START
typedef struct _ecdh_cfg_t {
    ecdh_set_t *params;
} SC_STRUCT_PACKED ecdh_cfg_t;
SC_STRUCT_PACK_END

/// Scheme creation
SINT32 ecdh_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 ecdh_destroy(safecrypto_t *sc);

/// Key pair generation function
SINT32 ecdh_keygen(safecrypto_t *sc);

/// Set key-pair lossless compression coding
SINT32 ecdh_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv);

/// Get key-pair lossless compression coding
SINT32 ecdh_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv);

/// Public key load function
SINT32 ecdh_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Private key load function
SINT32 ecdh_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Public key encode function used to disseminate the public key
SINT32 ecdh_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Private key encode function used to disseminate the private key
SINT32 ecdh_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Diffie-Hellman message initial exchange
SINT32 ecc_diffie_hellman_init(safecrypto_t *sc, size_t *tlen, UINT8 **to);

/// Diffie-Hellman message final exchange
SINT32 ecc_diffie_hellman_final(safecrypto_t *sc, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to);

/// Return a C-string output detailing the operation of the specified BLISS-B instance
char * ecdh_stats(safecrypto_t *sc);

