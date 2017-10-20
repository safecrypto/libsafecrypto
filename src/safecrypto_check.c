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

#include "safecrypto_check.h"
#include "safecrypto_error.h"


/// A helper function used to validate a correct safecrypto_t pointer
SINT32 check_safecrypto(safecrypto_t *sc)
{
    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }
    if (0 == sc->temp_ready) {
        SC_LOG_ERROR(sc, SC_ERROR);
        return SC_FUNC_FAILURE;
    }
    if (sc->alg_index < 0 || sc->alg_index >= ALG_TABLE_MAX) {
        SC_LOG_ERROR(sc, SC_OUT_OF_BOUNDS);
        return SC_FUNC_FAILURE;
    }

    return SC_FUNC_SUCCESS;
}

