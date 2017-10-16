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

#ifndef NTT_NEEDS_12289
#define NTT_NEEDS_12289
#endif


#include "safecrypto_private.h"
#include "utils/arith/arith.h"


SC_STRUCT_PACK_START
typedef struct ens_kem_set_t {
    const UINT16  set;
    const UINT16  q;
    const UINT16  q_bits;
    const UINT16  n;
    const UINT16  n_bits;
    const FLOAT   sig;
    const FLOAT   sk_norm;
    const UINT16  block_size;
    const UINT16  coeff_rnd[13];
#ifdef USE_RUNTIME_NTT_TABLES
    SINT16       *w;
    SINT16       *r;
#else
    const SINT16 *w;
    const SINT16 *r;
#endif
} SC_STRUCT_PACKED ens_kem_set_t;
SC_STRUCT_PACK_END


extern ens_kem_set_t param_ens_kem_0;
extern ens_kem_set_t param_ens_kem_1;
extern ens_kem_set_t param_ens_kem_2;
extern ens_kem_set_t param_ens_kem_3;

