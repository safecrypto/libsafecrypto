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
#include "safecrypto_private.h"
#include "utils/sampling/sampling.h"
#include <string.h>

#include "utils/arith/sc_mp.h"


void umul32(UINT32 *hi, UINT32 *lo, UINT32 u, UINT32 v);
void umul64(UINT64 *hi, UINT64 *lo, UINT64 u, UINT64 v);
UINT32 mont_umul32(UINT32 abar, UINT32 bbar, UINT32 m, UINT32 mprime);
UINT64 mont_umul64(UINT64 abar, UINT64 bbar, UINT64 m, UINT64 mprime);

UINT32 udiv32(UINT32 n, UINT32 d);
UINT32 urem32(UINT32 n, UINT32 d);
UINT32 umod32(UINT32 n1, UINT32 n0, UINT32 d);
void udivrem32(UINT32 *q, UINT32 *r, UINT32 n, UINT32 d);

UINT64 udiv64(UINT64 n, UINT64 d);
UINT64 urem64(UINT64 n, UINT64 d);
UINT64 umod64(UINT64 n1, UINT64 n0, UINT64 d);
void udivrem64(UINT64 *q, UINT64 *r, UINT64 n, UINT64 d);

sc_ulimb_t limb_udiv(sc_ulimb_t n, sc_ulimb_t d);
sc_ulimb_t limb_urem(sc_ulimb_t n, sc_ulimb_t d);
sc_ulimb_t limb_umod(sc_ulimb_t n1, sc_ulimb_t n0, sc_ulimb_t d);
void limb_udivrem(sc_ulimb_t *q, sc_ulimb_t *r, sc_ulimb_t n, sc_ulimb_t d);
void limb_umul(sc_ulimb_t *hi, sc_ulimb_t *lo, sc_ulimb_t u, sc_ulimb_t v);
sc_ulimb_t limb_mont_mul(sc_ulimb_t abar, sc_ulimb_t bbar, sc_ulimb_t m, sc_ulimb_t mprime);
