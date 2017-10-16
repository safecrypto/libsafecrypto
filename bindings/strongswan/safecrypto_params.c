/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "safecrypto_params.h"


#include <asn1/oid.h>

ENUM(sc_param_set_id_names, SAFECRYPTO_BLISS_I, SAFECRYPTO_BLISS_B_IV,
    "BLISS-I",
    "BLISS-II",
    "BLISS-III",
    "BLISS-IV"
    "BLISS-B-I",
    "BLISS-B-II",
    "BLISS-B-III",
    "BLISS-B-IV"
);


/**
 * SAFEcrypto parameter set definitions
 */
static const sc_param_set_t safecrypto_param_sets[] = {
    /* BLISS-B-I scheme */
    {
        .id = SAFECRYPTO_BLISS_B_I,
        .oid = OID_BLISS_B_I,
        .strength = 128,
    },
    /* BLISS-B-II scheme */
    {
        .id = SAFECRYPTO_BLISS_B_II,
        .oid = OID_BLISS_B_II,
        .strength = 160,
    },
    /* BLISS-B-III scheme */
    {
        .id = SAFECRYPTO_BLISS_B_III,
        .oid = OID_BLISS_B_III,
        .strength = 160,
    },
    /* BLISS-B-IV scheme */
    {
        .id = SAFECRYPTO_BLISS_B_IV,
        .oid = OID_BLISS_B_IV,
        .strength = 192,
    },
};


/**
 * See header.
 */
const sc_param_set_t* safecrypto_param_set_get_by_id(sc_param_set_id_t id)
{
    int i;

    for (i = 0; i < countof(safecrypto_param_sets); i++)
    {
        if (safecrypto_param_sets[i].id == id)
        {
            return &safecrypto_param_sets[i];
        }
    }

    return NULL;
}

/**
 * See header.
 */
const sc_param_set_t* safecrypto_param_set_get_by_oid(int oid)
{
    int i;

    for (i = 0; i < countof(safecrypto_param_sets); i++)
    {
        if (safecrypto_param_sets[i].oid == oid)
        {
            return &safecrypto_param_sets[i];
        }
    }

    return NULL;
}
