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
    sc->ecdsa = SC_MALLOC(sizeof(ecdsa_cfg_t));
    if (NULL == sc->ecdsa) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified ECDH parameter set
    switch (set)
    {
        case 0:  sc->ecdsa->params = &param_ec_secp256r1;
                 break;
#ifndef USE_OPT_ECC
        case 1:  sc->ecdsa->params = &param_ec_secp384r1;
                 break;
        case 2:  sc->ecdsa->params = &param_ec_secp521r1;
                 break;
#endif
        default: SC_FREE(sc->ecdsa, sizeof(ecdh_cfg_t));
                 return SC_FUNC_FAILURE;
    }

    sc->ecdsa->base.n = sc->ecdsa->params->num_limbs;
#ifdef USE_OPT_ECC
    mpn_copy(sc->ecdsa->base.x, sc->ecdsa->params->g_x, sc->ecdsa->base.n);
    mpn_copy(sc->ecdsa->base.y, sc->ecdsa->params->g_y, sc->ecdsa->base.n);
#else
    sc_mpz_init2(&sc->ecdsa->base.x, MAX_ECC_BITS);
    sc_mpz_init2(&sc->ecdsa->base.y, MAX_ECC_BITS);
    sc_mpz_set_str(&sc->ecdsa->base.x, 16, sc->ecdsa->params->g_x);
    sc_mpz_set_str(&sc->ecdsa->base.y, 16, sc->ecdsa->params->g_y);
#endif

    SC_PRINT_DEBUG(sc, "ECDSA algorithm - created");

    return SC_FUNC_SUCCESS;
}

SINT32 ecdsa_destroy(safecrypto_t *sc)
{
	size_t num_limbs = sc->ecdsa->params->num_limbs;

#ifndef USE_OPT_ECC
    sc_mpz_clear(&sc->ecdsa->base.x);
    sc_mpz_clear(&sc->ecdsa->base.y);
#endif

    if (sc->ecdsa) {
        SC_FREE(sc->ecdsa, sizeof(ecdsa_cfg_t));
    }

    if (sc->pubkey->key) {
        SC_FREE(sc->pubkey->key, 2 * num_limbs * sizeof(sc_ulimb_t));
    }

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, num_limbs * sizeof(sc_ulimb_t));
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

    num_limbs = sc->ecdsa->params->num_limbs;
    num_bytes = sc->ecdsa->params->num_bytes;

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
    return SC_FUNC_FAILURE;
}

SINT32 ecdsa_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    return SC_FUNC_FAILURE;
}

SINT32 ecdsa_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    return SC_FUNC_FAILURE;
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
