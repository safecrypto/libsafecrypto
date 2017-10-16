/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

typedef enum sc_param_set_id_t sc_param_set_id_t;
typedef struct sc_param_set_t sc_param_set_t;

#include <library.h>

/**
 * SAFECRYPTO parameter set ID list
 */
enum sc_param_set_id_t {
    SAFECRYPTO_BLISS_I     = 1,
    SAFECRYPTO_BLISS_II    = 2,
    SAFECRYPTO_BLISS_III   = 3,
    SAFECRYPTO_BLISS_IV    = 4,
    SAFECRYPTO_BLISS_B_I   = 5,
    SAFECRYPTO_BLISS_B_II  = 6,
    SAFECRYPTO_BLISS_B_III = 7,
    SAFECRYPTO_BLISS_B_IV  = 8
};

extern enum_name_t *safecrypto_param_set_id_names;

/**
 * SAFEcrypto
 */
struct sc_param_set_t {
    /**
     * SAFEcrypto parameter set ID
     */
    const sc_param_set_id_t id;

    /**
     * SAFEcrypto parameter set OID
     */
    const int oid;

    /**
     * Security strength in bits
     */
    const uint16_t strength;
};

/**
 * Get SAFEcrypto parameter set by parameter set ID
 *
 * @param id     SAFEcrypto parameter set ID
 * @return       SAFEcrypto parameter set
*/
const sc_param_set_t* safecrypto_param_set_get_by_id(sc_param_set_id_t id);

/**
 * Get SAFEcrypto parameter set by parameter set OID
 *
 * @param oid    SAFEcrypto parameter set OID
 * @return       SAFEcrypto parameter set
*/
const sc_param_set_t* safecrypto_param_set_get_by_oid(int oid);
