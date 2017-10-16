/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <credentials/builder.h>
#include <credentials/cred_encoding.h>
#include <credentials/keys/public_key.h>
#include "safecrypto.h"

typedef struct sc_public_key_t sc_public_key_t;

/**
 * public_key_t implementation of SAFEcrypto signature algorithms
 */
struct sc_public_key_t {
    /**
     * Implements the public_key_t interface
     */
    public_key_t key;
};

/**
 * Parse and load a SAFEcrypto public key.
 *
 * Accepts BUILD_SAFECRYPTO_* components.
 *
 * @param type        type of the key, must be KEY_SAFECRYPTO
 * @param args        builder_part_t argument list
 * @return            loaded key, NULL on failure
 */
sc_public_key_t *safecrypto_public_key_parse(key_type_t type, va_list args);

/* The following functions are shared with the safecrypto_private_key class */
/**
 * Parse an ASN.1 BIT STRING into an array of public key coefficients
 *
 * @param object    packed subjectPublicKey
 * @param set       SAFEcrypto parameter set for public key vector
 * @param sc        A SAFEcrypto structure
 * @return          TRUE if parsing successful
 */
bool safecrypto_public_key_from_asn1(chunk_t object, const sc_param_set_t *set,
                                safecrypto_t **sc);

/**
 * Encode a raw SAFEcrypto subjectPublicKey in ASN.1 DER format
 *
 * @param sc        A SAFEcrypto structure
 * @param set       SAFEcrypto parameter set for the public key vector
 * @result          ASN.1 encoded subjectPublicKey
 */

chunk_t safecrypto_public_key_extract(safecrypto_t *sc, const sc_param_set_t *set);
/**
 * Encode a SAFEcrypto subjectPublicKeyInfo record in ASN.1 DER format
 *
 * @param oid       SAFEcrypto public key type OID
 * @param sc        A SAFEcrypto structure
 * @param set       SAFEcrypto parameter set for the public key vector
 * @result          ASN.1 encoded subjectPublicKeyInfo record
 */
chunk_t safecrypto_public_key_info_extract(int oid, safecrypto_t *sc,
                                     const sc_param_set_t *set);

/**
 * Generate a SAFEcrypto public key fingerprint
 *
 * @param oid       SAFEcrypto public key type OID
 * @param sc        A SAFEcrypto structure
 * @param set       SAFEcrypto parameter set for the public key vector
 * @param type      type of fingerprint to be generated
 * @param fp        generated fingerprint (must be freed by caller)
 * @result          TRUE if generation was successful
 */
bool safecrypto_public_key_fingerprint(int oid, safecrypto_t *sc,
                                  const sc_param_set_t *set,
                                  cred_encoding_type_t type, chunk_t *fp);

