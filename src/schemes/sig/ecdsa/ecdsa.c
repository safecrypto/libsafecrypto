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

#include "ecdsa.h"

#include "safecrypto_private.h"
#include "safecrypto_error.h"
#include "safecrypto_debug.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/arith/arith.h"
#include "utils/arith/sc_math.h"
#include "utils/arith/sc_mpz.h"
#include "utils/ecc/ecc.h"
#include "utils/entropy/entropy.h"
#include "utils/entropy/packer.h"
#include "utils/sampling/sampling.h"

SINT32 ecdsa_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
	SC_PRINT_DEBUG(sc, "ECDSA algorithm - attempting creation");

    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are freed at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 1, 2, 3, 0, 0, 0)) {
        return SC_FUNC_FAILURE;
    }
    sc->stats.param_set = set;

    sc->coding_pub_key.type   = SC_ENTROPY_NONE;
    sc->coding_priv_key.type  = SC_ENTROPY_NONE;
    sc->coding_signature.type = SC_ENTROPY_NONE;

    // Allocate memory for BLISS configuration
    sc->ec = SC_MALLOC(sizeof(ec_cfg_t));
    if (NULL == sc->ec) {
        return SC_FUNC_FAILURE;
    }
    sc->ec->coord_type = EC_COORD_JACOBIAN;

    // Initialise the SAFEcrypto struct with the specified ECDH parameter set
    switch (set)
    {
        case 0:  sc->ec->params = &param_ec_secp192r1;
                break;
        case 1:  sc->ec->params = &param_ec_secp224r1;
                 break;
        case 2:  sc->ec->params = &param_ec_secp256r1;
                 break;
        case 3:  sc->ec->params = &param_ec_secp384r1;
                 break;
        case 4:  sc->ec->params = &param_ec_secp521r1;
                 break;
        default: SC_FREE(sc->ec, sizeof(ec_cfg_t));
                 return SC_FUNC_FAILURE;
    }

    point_init(&sc->ec->base, sc->ec->params->num_limbs, sc->ec->coord_type);
    sc_mpz_set_str(&sc->ec->base.x, 16, sc->ec->params->g_x);
    sc_mpz_set_str(&sc->ec->base.y, 16, sc->ec->params->g_y);

    SC_PRINT_DEBUG(sc, "ECDSA algorithm - created");

    return SC_FUNC_SUCCESS;
}

SINT32 ecdsa_destroy(safecrypto_t *sc)
{
    size_t num_bytes = sc->ec->params->num_bytes;

    point_clear(&sc->ec->base);

    if (sc->ec) {
        SC_FREE(sc->ec, sizeof(ec_cfg_t));
    }

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * num_bytes);
    }

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, num_bytes);
    }

    SC_PRINT_DEBUG(sc, "ECDSA algorithm - destroyed");

    return SC_FUNC_SUCCESS;
}

SINT32 ecdsa_keygen(safecrypto_t *sc)
{
	return ecc_keygen(sc);
}

SINT32 ecdsa_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t num_limbs, num_bytes;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    num_limbs = sc->ec->params->num_limbs;
    num_bytes = sc->ec->params->num_bytes;

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * num_limbs * sizeof(sc_ulimb_t));
    }
    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(2 * num_limbs * sizeof(sc_ulimb_t));
        if (NULL == sc->pubkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    // Copy the input public key to storage
    SC_MEMCOPY(sc->pubkey->key, key, key_len);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Loaded public key", key, key_len);

    return SC_FUNC_SUCCESS;
}

SINT32 ecdsa_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    size_t num_limbs;

    if (NULL == sc || NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    num_limbs = sc->ec->params->num_limbs;

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, num_limbs * sizeof(sc_ulimb_t));
    }
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(num_limbs * sizeof(sc_ulimb_t));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    // Copy the input private key to storage
    SC_MEMCOPY(sc->privkey->key, key, key_len);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Loaded private key", key, key_len);

    return SC_FUNC_SUCCESS;
}

SINT32 ecdsa_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t num_bytes;

    if (NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    num_bytes = 2 * sc->ec->params->num_bytes;

    if (NULL == sc->pubkey->key) {
        return SC_FUNC_FAILURE;
    }
    if (0 == *key || 0 == *key_len) {
        *key = SC_MALLOC(num_bytes * sizeof(uint8_t));
        if (NULL == *key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    // Copy the input public key to storage
    *key_len = num_bytes;
    SC_MEMCOPY(*key, sc->pubkey->key, num_bytes);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Encoded public key", *key, *key_len);

    return SC_FUNC_SUCCESS;
}

SINT32 ecdsa_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    size_t num_bytes;

    if (NULL == key) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    num_bytes = sc->ec->params->num_bytes;

    if (NULL == sc->privkey->key) {
        return SC_FUNC_FAILURE;
    }
    if (0 == *key || 0 == *key_len) {
        *key = SC_MALLOC(num_bytes * sizeof(uint8_t));
        if (NULL == *key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    // Copy the input public key to storage
    *key_len = num_bytes;
    SC_MEMCOPY(*key, sc->privkey->key, num_bytes);
    SC_PRINT_1D_UINT8(sc, SC_LEVEL_DEBUG, "Encoded private key", *key, *key_len);

    return SC_FUNC_SUCCESS;
}

SINT32 ecdsa_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen)
{
	return ecc_sign(sc, m, m_len, sigret, siglen);
}

SINT32 ecdsa_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen)
{
	return ecc_verify(sc, m, m_len, sigbuf, siglen);
}

char * ecdsa_stats(safecrypto_t *sc)
{
	static char stats[2048];
    snprintf(stats, 2047, "\nECDSA (%s):\n", "Curve");
    return stats;
}
