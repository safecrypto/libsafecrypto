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

#include "hw_test_kem.h"
#include "safecrypto_private.h"



SINT32 hw_test_kem_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    return SC_FUNC_SUCCESS;
}


SINT32 hw_test_kem_destroy(safecrypto_t *sc)
{
    return SC_FUNC_SUCCESS;
}

SINT32 hw_test_kem_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    return SC_FUNC_SUCCESS;
}

SINT32 hw_test_kem_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len)
{
    return SC_FUNC_SUCCESS;
}

SINT32 hw_test_kem_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    return SC_FUNC_SUCCESS;
}

SINT32 hw_test_kem_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len)
{
    return SC_FUNC_SUCCESS;
}

SINT32 hw_test_kem_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv)
{
    return SC_FUNC_FAILURE;
}

SINT32 hw_test_kem_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv)
{
    return SC_FUNC_FAILURE;
}

SINT32 hw_test_kem_keygen(safecrypto_t *sc)
{
    return SC_FUNC_SUCCESS;
}

SINT32 hw_test_kem_encapsulation(safecrypto_t *sc,
    UINT8 **c, size_t *c_len,
    UINT8 **k, size_t *k_len)
{
    return SC_FUNC_SUCCESS;
}

SINT32 hw_test_kem_decapsulation(safecrypto_t *sc,
    const UINT8 *c, size_t c_len,
    UINT8 **k, size_t *k_len)
{
    return SC_FUNC_SUCCESS;
}

char * hw_test_kem_stats(safecrypto_t *sc)
{
    static char stats[2048];
    snprintf(stats, 2047, "\nHARDWARE TEST\n");
    return stats;
}

