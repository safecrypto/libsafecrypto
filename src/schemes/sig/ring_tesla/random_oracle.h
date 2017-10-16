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

#include "safecrypto_private.h"
#include "safecrypto_types.h"


void poly_rounding(safecrypto_t *sc, UINT16 n, SINT32 *p, SINT32 *r);
void oracle(safecrypto_t *sc, SINT32 *v1, SINT32 *v2,
    SINT32 *temp, UINT16 n,
    const UINT8 *m, size_t m_len, UINT8 *md);
void salsa20_core(const UINT32 *input, UINT8 *output);
void random_stream(UINT8 *md, UINT8 *nonce, UINT8 *r);
void populate_c(safecrypto_t *sc, UINT8 *r, UINT8 *s, SINT32 *c);
void f_function(safecrypto_t *sc, UINT8 *md, SINT32 *temp, SINT32 *c);
