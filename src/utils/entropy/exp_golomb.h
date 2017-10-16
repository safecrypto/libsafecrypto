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

#include "safecrypto_types.h"


void exp_golomb_encode(UINT8 in, UINT32 *code, SINT32 *bits);
void exp_golomb_sign_encode(SINT8 in, UINT32 *code, SINT32 *bits);
UINT8 exp_golomb_decode(UINT32 code);
SINT8 exp_golomb_sign_decode(UINT32 code);
