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
#include <credentials/keys/private_key.h>

typedef struct sc_private_key sc_private_key_t;

/**
 * Private_key_t implementation of BLISS signature algorithm.
 */
struct sc_private_key {

    /**
     * Implements private_key_t interface
     */
    private_key_t key;
};

/**
 * Generate a BLISS private key.
 *
 * Accepts the BUILD_KEY_SIZE argument.
 *
 * @param type        type of the key, must be KEY_BLISS
 * @param args        builder_part_t argument list
 * @return            generated key, NULL on failure
 */
sc_private_key_t *safecrypto_private_key_gen(key_type_t type, va_list args);

/**
 * Decode and load a SAFEcrypto private key.
 *
 * Accepts BUILD_BLISS_* components.
 *
 * @param type        type of the key, must be KEY_BLISS
 * @param args        builder_part_t argument list
 * @return            loaded key, NULL on failure
 */
sc_private_key_t *safecrypto_private_key_decode(key_type_t type, va_list args);

