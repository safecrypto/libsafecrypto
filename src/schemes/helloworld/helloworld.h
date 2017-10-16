/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
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
#pragma once

#include <stdint.h>

#include "safecrypto_private.h"

int32_t helloworld_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);
int32_t helloworld_destroy(safecrypto_t *sc);

int32_t helloworld_sign(safecrypto_t *sc, const uint8_t *m, size_t m_len,
    uint8_t **sigret, size_t *siglen);
int32_t helloworld_verify(safecrypto_t *sc, const uint8_t *m, size_t m_len,
    const uint8_t *sigbuf, size_t siglen);
