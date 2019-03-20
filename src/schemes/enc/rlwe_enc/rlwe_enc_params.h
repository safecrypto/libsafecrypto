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

#ifndef NTT_NEEDS_7681
#define NTT_NEEDS_7681
#endif
#ifndef NTT_NEEDS_12289
#define NTT_NEEDS_12289
#endif

#ifndef NEEDS_GAUSSIAN_CDF
#define NEEDS_GAUSSIAN_CDF
#endif


#include "safecrypto_private.h"
#include "utils/arith/arith.h"


SC_STRUCT_PACK_START
typedef struct rlwe_set_t {
    const UINT16  set;
    const UINT16  q;
    const UINT16  q_bits;
    const UINT16  n;
    const UINT16  n_bits;
    const FLOAT   sig;
    const UINT16  m_scale;
    const UINT16  o_scale_0;
    const UINT16  o_scale_1;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT16       *w;
    SINT16       *r;
    SINT16       *w_rev;
    SINT16       *w_inv;
    SINT16       *r_rev;
#else
    const SINT16 *w;
    const SINT16 *r;
    const SINT16 *w_rev;
    const SINT16 *w_inv;
    const SINT16 *r_inv;
#endif
} SC_STRUCT_PACKED rlwe_set_t;
SC_STRUCT_PACK_END

// NOTE: sigma is equivalent to s/sqrt(2*pi), i.e. 11.81 and 12.31 for RLWEenc

extern rlwe_set_t param_rlwe_enc_0;
extern rlwe_set_t param_rlwe_enc_1;
