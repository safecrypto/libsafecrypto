/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

//#define KYBER_KEM_USE_SPARSE_MULTIPLICATION


/// Scheme creation
SINT32 kyber_kem_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 kyber_kem_destroy(safecrypto_t *sc);

/// Key pair generation function
SINT32 kyber_kem_keygen(safecrypto_t *);

/// Public key load function
SINT32 kyber_kem_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Private key load function
SINT32 kyber_kem_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Public key encode function used to disseminate the public key
SINT32 kyber_kem_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Private key encode function used to disseminate the private key
SINT32 kyber_kem_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Encapsulation function
SINT32 kyber_kem_encapsulation(safecrypto_t *sc,
    UINT8 **c, size_t *c_len,
    UINT8 **k, size_t *k_len);

/// Decapsulation function
SINT32 kyber_kem_decapsulation(safecrypto_t *sc,
	const UINT8 *c, size_t c_len,
	UINT8 **k, size_t *k_len);

/// Return a C-string output detailing the operation of the specified KEM instance
char * kyber_kem_stats(safecrypto_t *sc);
