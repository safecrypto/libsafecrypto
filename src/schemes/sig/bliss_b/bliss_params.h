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

#ifndef NTT_NEEDS_7681
#define NTT_NEEDS_7681
#endif
#ifndef NTT_NEEDS_12289
#define NTT_NEEDS_12289
#endif

#ifdef HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
#ifndef NEEDS_GAUSSIAN_ZIGGURAT
#define NEEDS_GAUSSIAN_ZIGGURAT
#endif
#else
#ifndef NEEDS_GAUSSIAN_CDF
#define NEEDS_GAUSSIAN_CDF
#endif
#endif


#include "safecrypto_types.h"
#include "utils/crypto/hash.h"

/// A struct used to store BLISS parameters
SC_STRUCT_PACK_START
typedef struct bliss_set_t {
    const UINT16      set;
    const UINT16      q;
    const UINT16      q_bits;
    const UINT16      n;
    const UINT16      n_bits;
    const UINT16      d;
    const UINT16      p;
    const UINT16      kappa;
    const UINT16      b_inf;
    const UINT32      b_l2;
    const UINT16      nz[2];
    const UINT16      z1_bits;
    const UINT16      z2_bits;
    const FLOAT       sig;
    const FLOAT       m;
    sc_hash_e         oracle_hash;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT16           *w;
    SINT16           *r;
    SINT16           *w_rev;
    SINT16           *w_inv;
    SINT16           *r_rev;
#else
    const SINT16     *w;
    const SINT16     *r;
    const SINT16     *w_rev;
    const SINT16     *w_inv;
    const SINT16     *r_inv;
#endif
} SC_STRUCT_PACKED bliss_set_t;
SC_STRUCT_PACK_END

extern bliss_set_t param_bliss_b_0;
extern bliss_set_t param_bliss_b_1;
extern bliss_set_t param_bliss_b_2;
extern bliss_set_t param_bliss_b_3;
extern bliss_set_t param_bliss_b_4;

