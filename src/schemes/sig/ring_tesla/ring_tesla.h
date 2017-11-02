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
#include "ring_tesla_params.h"
#include "safecrypto_private.h"
#include "utils/crypto/hash.h"

#include "utils/arith/arith.h"
#include "utils/sampling/sampling.h"



/// Scheme creation
SINT32 ring_tesla_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 ring_tesla_destroy(safecrypto_t *sc);

/// Key pair generation function
SINT32 ring_tesla_keygen(safecrypto_t *sc);

/// Set key-pair lossless compression coding
SINT32 ring_tesla_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv);

/// Get key-pair lossless compression coding
SINT32 ring_tesla_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv);

/// Public key load function
SINT32 ring_tesla_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Private key load function
SINT32 ring_tesla_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Public key encode function used to disseminate the public key
SINT32 ring_tesla_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Private key encode function used to disseminate the private key
SINT32 ring_tesla_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Sign a message of m_len bytes
SINT32 ring_tesla_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen);

/// Verify a message of m_len bytes
SINT32 ring_tesla_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen);

/// Return a C-string output detailing the operation of the specified Rong-TESLA instance
char * ring_tesla_stats(safecrypto_t *sc);
