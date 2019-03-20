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

#pragma once

#include "safecrypto_types.h"
#include "utils/arith/limb.h"

SINT32 roots_of_unity_slimb(sc_slimb_t *fwd, sc_slimb_t *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim);
SINT32 roots_of_unity_s32(SINT32 *fwd, SINT32 *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim);
SINT32 roots_of_unity_s16(SINT16 *fwd, SINT16 *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim);
SINT32 inv_root_square_s16(SINT16 *fwd, size_t n, sc_ulimb_t p, sc_ulimb_t prim);
SINT32 inv_root_square_s32(SINT32 *fwd, size_t n, sc_ulimb_t p, sc_ulimb_t prim);
