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

#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "safecrypto_private.h"
#include "utils/crypto/hash.h"


SINT32 safecrypto_ake_2way_init(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    UINT8 **kem, size_t *kem_len, UINT8 **sig, size_t *sig_len)
{
    // A flag indicating if the KEM memory is already allocated
    SINT32 sc_kem_allocation = 0 == *kem_len;

    if (SC_FUNC_SUCCESS != check_safecrypto(sc_sig)) {
    	SC_LOG_ERROR(sc_sig, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    if (SC_FUNC_SUCCESS != check_safecrypto(sc_kem)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Generate KEM Encapsulation and Decapsulation keys
    if (SC_FUNC_SUCCESS != safecrypto_keygen(sc_kem)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Encode the Encapsulation key for transmission to the other party
    if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc_kem, kem, kem_len)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Sign the Encapsulation key
    if (SC_FUNC_SUCCESS != safecrypto_sign(sc_sig, *kem, *kem_len, sig, sig_len)) {
    	SC_LOG_ERROR(sc_sig, SC_ERROR);
        if (sc_kem_allocation) {
            SC_FREE(*kem, *kem_len);
        }
        return SC_FUNC_FAILURE;
    }

    return SC_FUNC_SUCCESS;
}

SINT32 safecrypto_ake_2way_response(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    sc_ake_e ake_type, sc_hash_e hash_type,
    const UINT8 *kem, size_t kem_len, const UINT8 *sig, size_t sig_len,
    UINT8 **md, size_t *md_len, UINT8 **c, size_t *c_len, UINT8 **resp_sig, size_t *resp_sig_len,
    UINT8 **secret, size_t *secret_len)
{
    /// @todo Add further AKE schemes
    (void) ake_type;

    UINT8 *k = NULL;
    size_t k_len = 0;
    utils_crypto_hash_t *hash = NULL;
    UINT32 sc_allocated;

    if (SC_FUNC_SUCCESS != check_safecrypto(sc_sig)) {
    	SC_LOG_ERROR(sc_sig, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    if (SC_FUNC_SUCCESS != check_safecrypto(sc_kem)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    sc_allocated  = (0 == *md_len)? 0x01 : 0x00;
    sc_allocated |= (0 == *c_len)? 0x02 : 0x00;
    sc_allocated |= (0 == *secret_len)? 0x04 : 0x00;

    // Verify the signed Encapsulation Key using A's verification key
    if (SC_FUNC_SUCCESS != safecrypto_verify(sc_sig, kem, kem_len, sig, sig_len)) {
    	SC_LOG_ERROR(sc_sig, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Use the verified Encapsulation Key to encapsulate a random secret key
    if (SC_FUNC_SUCCESS != safecrypto_public_key_load(sc_kem, kem, kem_len)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }
    if (SC_FUNC_SUCCESS != safecrypto_encapsulation(sc_kem, c, c_len, &k, &k_len)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Hash the original signed message with the Encapsulation output and Sign it
    hash = utils_crypto_hash_create(hash_type);
    if (0 == *md_len) {
        *md = SC_MALLOC(hash->length);
        *md_len = hash->length;
    }
    hash_init(hash);
    hash_update(hash, sig, sig_len);
    hash_update(hash, *c, *c_len);
    hash_update(hash, k, k_len);
    hash_final(hash, *md);

    // Sign the hash
    if (SC_FUNC_SUCCESS != safecrypto_sign(sc_sig, *md, *md_len, resp_sig, resp_sig_len)) {
    	SC_LOG_ERROR(sc_sig, SC_ERROR);

        // Upon failure, ensure that allocated memory is released
        if (sc_allocated & 0x01) {
            SC_FREE(*md, *md_len);
        }
        if (sc_allocated & 0x02) {
            SC_FREE(*c, *c_len);
        }
        if (sc_allocated & 0x04) {
            SC_FREE(k, k_len);
        }
        utils_crypto_hash_destroy(hash);
        return SC_FUNC_FAILURE;
    }

    // Form the secret key as the hash of the messages and shared secret
    *secret = SC_MALLOC(hash->length);
    *secret_len = hash->length;
    hash_init(hash);
    hash_update(hash, sig, sig_len);
    hash_update(hash, *resp_sig, *resp_sig_len);
    hash_update(hash, k, k_len);
    hash_final(hash, *secret);
    utils_crypto_hash_destroy(hash);

    return SC_FUNC_SUCCESS;
}

SINT32 safecrypto_ake_2way_final(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    sc_ake_e ake_type, sc_hash_e hash_type,
    const UINT8 *md, size_t md_len, const UINT8 *c, size_t c_len, const UINT8 *resp_sig, size_t resp_sig_len,
    const UINT8 *sig, size_t sig_len,
    UINT8 **secret, size_t *secret_len)
{
    /// @todo Add further AKE schemes
    (void) ake_type;
    
    size_t i;
    UINT8 md2[64];
    utils_crypto_hash_t *hash = NULL;

    if (SC_FUNC_SUCCESS != check_safecrypto(sc_sig)) {
    	SC_LOG_ERROR(sc_sig, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    if (SC_FUNC_SUCCESS != check_safecrypto(sc_kem)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Verify the message from 'B' and obtain (c,Auth)
    if (SC_FUNC_SUCCESS != safecrypto_verify(sc_sig, md, md_len, resp_sig, resp_sig_len)) {
    	SC_LOG_ERROR(sc_sig, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Decapsulate the KEM ciphertext to obtain the shared secret
    UINT8 *k;
    size_t k_len = 0;
    if (SC_FUNC_SUCCESS != safecrypto_decapsulation(sc_kem, c, c_len, &k, &k_len)) {
    	SC_LOG_ERROR(sc_kem, SC_ERROR);
        return SC_FUNC_FAILURE;
    }

    // Check that Auth is correct
    hash = utils_crypto_hash_create(hash_type);
    hash_init(hash);
    hash_update(hash, sig, sig_len);
    hash_update(hash, c, c_len);
    hash_update(hash, k, k_len);
    hash_final(hash, md2);
    for (i=0; i<hash->length; i++) {
        if (md[i] != md2[i]) {
            SC_FREE(k, k_len);
            SC_LOG_ERROR(sc_sig, SC_ERROR);
            SC_LOG_ERROR(sc_kem, SC_ERROR);
            return SC_FUNC_FAILURE;
        }
    }

    // Form the secret key as the hash of the messages and shared secret
    *secret = SC_MALLOC(hash->length);
    *secret_len = hash->length;
    hash_init(hash);
    hash_update(hash, sig, sig_len);
    hash_update(hash, resp_sig, resp_sig_len);
    hash_update(hash, k, k_len);
    hash_final(hash, *secret);
    utils_crypto_hash_destroy(hash);

    SC_FREE(k, k_len);

    return SC_FUNC_SUCCESS;
}


