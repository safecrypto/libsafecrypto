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

#ifndef NTT_NEEDS_8399873
#define NTT_NEEDS_8399873
#endif
#ifndef NTT_NEEDS_51750913
#define NTT_NEEDS_51750913
#endif

#ifndef NEEDS_GAUSSIAN_CDF
#define NEEDS_GAUSSIAN_CDF
#endif


#include "safecrypto_private.h"
#include "utils/crypto/hash.h"
#include "utils/arith/arith.h"
#include "utils/sampling/sampling.h"


/// The length of the random stream to be generated as part of the random oracle
#define RANDOM_STREAM_LENGTH    800


SC_STRUCT_PACK_START
typedef struct ring_tesla_set_t {
    UINT16  set;
    safecrypto_hash_e oracle_hash;
    UINT32  n;
    UINT16  n_bits;
    FLOAT   sig;
    UINT32  q;
    UINT16  q_bits;
    DOUBLE  q_inv;
    UINT32  b;
    UINT16  b_bits;
    UINT16  e_bits;
    UINT16  omega;
    UINT16  d;
    UINT16  bound;
    UINT16  u;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT32 *w;
    SINT32 *r;
    SINT32  prim_root;
#else
    const SINT32 *w;
    const SINT32 *r;
#endif
} SC_STRUCT_PACKED ring_tesla_set_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct ring_tesla_cfg_t {
    ring_tesla_set_t         *params;
    safecrypto_ntt_e          ntt_optimisation;
    ntt_params_t              ntt;
    sc_entropy_type_e         entropy;
    safecrypto_hash_e         oracle_hash;
} SC_STRUCT_PACKED ring_tesla_cfg_t;
SC_STRUCT_PACK_END


extern ring_tesla_set_t param_ring_tesla_0;
extern ring_tesla_set_t param_ring_tesla_1;


extern const SINT32 a1_0[512];

extern const SINT32 a2_0[512];

/// @todo Regenrate for q
extern const SINT32 a1_1[512];

/// @todo Regenrate for q
extern const SINT32 a2_1[512];

