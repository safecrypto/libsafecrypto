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
#include "utils/crypto/hash.h"


SC_STRUCT_PACK_START
typedef struct ens_dlp_sig_set_t {
    const UINT16    set;
    const sc_hash_e hash_type;
    const UINT16    q;
    const UINT16    q_bits;
    const UINT16    n;
    const UINT16    n_bits;
    const UINT32    k_recovery;
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
} SC_STRUCT_PACKED ens_dlp_sig_set_t;
SC_STRUCT_PACK_END


extern ens_dlp_sig_set_t param_ens_sig_0;
extern ens_dlp_sig_set_t param_ens_sig_1;

#if 1
extern ens_dlp_sig_set_t param_dlp_sig_0;
extern ens_dlp_sig_set_t param_dlp_sig_1;
#else
extern ens_dlp_sig_set_t param_dlp_sig_0;
extern ens_dlp_sig_set_t param_dlp_sig_1;
#endif

SC_STRUCT_PACK_START
typedef struct ens_dlp_sig_cfg_t {
    ens_dlp_sig_set_t    *params;
    safecrypto_ntt_e      ntt_optimisation;
    ntt_params_t          ntt;
    sc_entropy_type_e     entropy;
    sc_hash_e             oracle_hash;
    SINT32                keep_matrices;
    SINT32               *b;
#ifdef ENS_DLP_SIG_USE_LONGDOUBLE_PREC_FLOATS
    LONGDOUBLE           *b_gs;
    LONGDOUBLE           *b_gs_inv_norm;
#else
#ifdef ENS_DLP_SIG_USE_DOUBLE_PREC_FLOATS
    DOUBLE               *b_gs;
    DOUBLE               *b_gs_inv_norm;
#else
    FLOAT                *b_gs;
    FLOAT                *b_gs_inv_norm;
#endif
#endif
} SC_STRUCT_PACKED ens_dlp_sig_cfg_t;
SC_STRUCT_PACK_END

