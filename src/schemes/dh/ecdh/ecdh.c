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

#include "ecdh.h"
#include "utils/ecc/ecc.h"
#include "utils/crypto/prng.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"


SINT32 ecdh_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
	SC_PRINT_DEBUG(sc, "ECDH algorithm - attempting creation");

    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    // Configure the statistics resources - these are freed at the interface layer
    if (SC_FUNC_FAILURE == sc_init_stats(sc, 1, 2, 3, 0, 0, 0)) {
        return SC_FUNC_FAILURE;
    }
    sc->stats.param_set = set;

    sc->coding_pub_key.type    = SC_ENTROPY_NONE;
    sc->coding_priv_key.type   = SC_ENTROPY_NONE;
    sc->coding_encryption.type = SC_ENTROPY_NONE;

    // Allocate memory for BLISS configuration
    sc->ecdh = SC_MALLOC(sizeof(ecdh_cfg_t));
    if (NULL == sc->ecdh) {
        return SC_FUNC_FAILURE;
    }

    // Initialise the SAFEcrypto struct with the specified ECDH parameter set
    switch (set)
    {
        case 0:  sc->ecdh->params = &param_ecdh_secp256r1;
                 break;
        case 1:  sc->ecdh->params = &param_ecdh_secp384r1;
                 break;
        case 2:  sc->ecdh->params = &param_ecdh_secp521r1;
                 break;
        default: SC_FREE(sc->ecdh, sizeof(ecdh_cfg_t));
                 return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "ECDH algorithm - created");

    return SC_FUNC_SUCCESS;
}

SINT32 ecdh_destroy(safecrypto_t *sc)
{
    if (sc->ecdh) {
        SC_FREE(sc->ecdh, sizeof(ecdh_cfg_t));
    }

    if (sc->privkey->key) {
        SC_FREE(sc->privkey->key, MAX_ECC_LIMBS * sizeof(sc_ulimb_t));
    }

    SC_PRINT_DEBUG(sc, "ECDH algorithm - destroyed");

    return SC_FUNC_SUCCESS;
}

SINT32 ecdh_diffie_hellman_init(safecrypto_t *sc, size_t *tlen, UINT8 **to)
{
    size_t num_bytes, num_limbs;
    sc_ulimb_t *secret;

    num_bytes = sc->ecdh->params->num_bytes;
    num_limbs = sc->ecdh->params->num_limbs;

    // Allocate key pair memory
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(num_limbs * sizeof(sc_ulimb_t));
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            return SC_FUNC_FAILURE;
        }
    }

    // Generate a random secret and store it as the private key
    secret = (sc_ulimb_t*) sc->privkey->key;
#if 1
    for (size_t i=0; i<num_limbs; i++) {
        secret[i] = 0;
    }
    static sc_ulimb_t val = 0;
    val ^= 1;
    secret[0] = val? 0 : 1;
    secret[1] = val? 0x800000000 : 2;//0xFFFFFFFFFFFFFFFFULL;
    //secret[1] = val;
#else
    prng_mem(sc->prng_ctx[0], (UINT8*) secret, num_bytes);
#endif

	return ecc_diffie_hellman_encapsulate(sc, secret, tlen, to);
}

SINT32 ecdh_diffie_hellman_final(safecrypto_t *sc, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
    sc_ulimb_t *secret;
    secret = (sc_ulimb_t*) sc->privkey->key;
	return ecc_diffie_hellman_decapsulate(sc, secret, flen, from, tlen, to);
}

char * ecdh_stats(safecrypto_t *sc)
{
    static char stats[2048];
    snprintf(stats, 2047, "\nECDH (%s):\n\
    	",
    	"Curve");
    return stats;
}


//
// end of file
//
