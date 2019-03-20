/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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
/*#ifndef NTT_NEEDS_18433
#define NTT_NEEDS_18433
#endif*/

#ifndef NEEDS_GAUSSIAN_CDF
#define NEEDS_GAUSSIAN_CDF
#endif


#include "safecrypto_private.h"
#include "utils/arith/arith.h"
#include "utils/crypto/hash.h"


SC_STRUCT_PACK_START
typedef struct falcon_set_t {
    const UINT16    set;
    const sc_hash_e hash_type;
    const UINT16    q;
    const UINT16    q_bits;
    const UINT16    n;
    const UINT16    n_bits;
    const UINT16    kappa;
    const FLOAT     sig;
    const UINT32    fg_bits;
    const UINT32    FG_bits;
    const FLOAT     bd;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT16         *w;
    SINT16         *r;
#else
    const SINT16   *w;
    const SINT16   *r;
#endif
} SC_STRUCT_PACKED falcon_set_t;
SC_STRUCT_PACK_END


extern falcon_set_t param_falcon_0;
//extern falcon_set_t param_falcon_1;
extern falcon_set_t param_falcon_2;
