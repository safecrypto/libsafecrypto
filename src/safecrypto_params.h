/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file
 * These variables, functions and preprocessor definitions and macros are
 * not to be exposed to the user. This header file should not be
 * distributed with a pre-built library.
 *
 * @author n.smyth@qub.ac.uk
 * @date 10 Aug 2016
 * @brief Private functions and variables that are not exposed to the user.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */


#pragma once

#include <stdlib.h>
#include "safecrypto.h"


SINT32 params_create(safecrypto_t *sc);
SINT32 params_destroy(safecrypto_t *sc);
SINT32 params_clear(safecrypto_t *sc, const char *alg);
SINT32 params_add(safecrypto_t *sc, const char *alg, const char *name,
    sc_param_type_e type, sc_data_u value);
SINT32 params_add_array(safecrypto_t *sc, const char *alg, const char *name,
    sc_param_type_e type, const void* array, size_t length);
SINT32 params_remove(safecrypto_t *sc, const char *alg, const char *name);
SINT32 params_get(safecrypto_t *sc, const char *alg, const char *name,
    sc_param_type_e *type, sc_data_u *value, size_t *length);

