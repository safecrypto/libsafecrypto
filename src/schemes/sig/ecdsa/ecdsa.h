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


typedef struct _ec_set_t ec_set_t;
typedef struct _ecdsa_cfg_t ecdsa_cfg_t;


/// Scheme creation
SINT32 ecdsa_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 ecdsa_destroy(safecrypto_t *sc);

/// Key pair generation function
SINT32 ecdsa_keygen(safecrypto_t *sc);

/// Public key load function
SINT32 ecdsa_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Private key load function
SINT32 ecdsa_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Public key encode function used to disseminate the public key
SINT32 ecdsa_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Private key encode function used to disseminate the private key
SINT32 ecdsa_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Sign a message of m_len bytes
SINT32 ecdsa_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen);

/// Verify a message of m_len bytes
SINT32 ecdsa_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen);

/// Return a C-string output detailing the operation of the specified Dilithium/Dilithium-G instance
char * ecdsa_stats(safecrypto_t *sc);
