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

#if 0
#ifndef NTT_NEEDS_5767169
#define NTT_NEEDS_5767169
#endif
#ifndef NTT_NEEDS_10223617
#define NTT_NEEDS_10223617
#endif
#ifndef NTT_NEEDS_51750913
#define NTT_NEEDS_51750913
#endif
#else
#ifndef NTT_NEEDS_4206593
#define NTT_NEEDS_4206593
#endif
#endif

#ifndef NEEDS_GAUSSIAN_ZIGGURAT
#define NEEDS_GAUSSIAN_ZIGGURAT
#endif

#ifndef NEEDS_GAUSSIAN_CDF
#define NEEDS_GAUSSIAN_CDF
#endif


#include "safecrypto_private.h"
#include "utils/crypto/hash.h"
#include "utils/arith/ntt.h"
#ifndef DISABLE_IBE_SERVER
#include "utils/arith/gpv.h"
#endif

#define SC_IBE_MESSAGE_LENGTH_N

/// Use FALCON enhanced KeyGen and Extract
#define DLP_IBE_USE_ENHANCED_EXTRACT   0

/// Use a Hash/CSPRNG to provide a random oracle rather than a XOF
//#define DLP_USE_RANDOM_ORACLE_CSPRNG

/// Enable the use of a sub-optimal reference GSO function
//#define DLP_IBE_USE_CLASSICAL_GSO

/// Retain the GSO matrix and vector of norms in memory for re-use
#if DLP_IBE_USE_ENHANCED_EXTRACT == 0
#define DLP_IBE_KEEP_GSO_MATRICES   1
#else
#define DLP_IBE_KEEP_GSO_MATRICES   0
#endif

/// Expand the polynomial basis B, otherwise it is expanded on-the-fly for
/// sampling over a lattice
#define DLP_IBE_EXPAND_BASIS

// Use a Mecciancio and Walter bootstrapped Gaussian sampler
//#define DLP_IBE_GAUSSIAN_SAMPLE_MW_BOOTSTRAP

/// Only re-initialise the Gaussian Sampler every N samples over a 2N polynomial
/// rather than every sample
#ifndef DLP_IBE_GAUSSIAN_SAMPLE_MW_BOOTSTRAP
#define DLP_IBE_EFFICIENT_GAUSSIAN_SAMPLING
#endif

/// Select floating-point precision for the storage type for all GPV calculations
#define DLP_IBE_USE_SINGLE_PREC_FLOATS
//#define DLP_IBE_USE_DOUBLE_PREC_FLOATS

/// Enable the use of sparse multiplication where appropriate
#define DLP_IBE_USE_SPARSE_MULTIPLICATION

#ifdef DLP_IBE_USE_SINGLE_PREC_FLOATS
#define GSO_TYPE    FLOAT
#define gaussian_lattice_sample gaussian_lattice_sample_flt
#else
#ifdef DLP_IBE_USE_DOUBLE_PREC_FLOATS
#define GSO_TYPE    DOUBLE
#define gaussian_lattice_sample gaussian_lattice_sample_dbl
#else
#define GSO_TYPE    LONGDOUBLE
#define gaussian_lattice_sample gaussian_lattice_sample_ldbl
#endif
#endif

/// Assume that the H(id) function returns a poly ring in the NTT domain
#define H_NTT_OPTIMISATION

/// A struct use to store DLP IBE parameter sets
SC_STRUCT_PACK_START
typedef struct dlp_ibe_set_t {
    const UINT32    set;
    const sc_hash_e hash_type;
    const UINT32    q;
    const UINT32    q_bits;
    const UINT32    n;
    const UINT32    n_bits;
    const UINT32    m_scale;
    const UINT32    l;
    const UINT32    nth_root_of_unity;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT32         *w;
    SINT32         *r;
#else
    const SINT32   *w;
    const SINT32   *r;
#endif
} SC_STRUCT_PACKED dlp_ibe_set_t;
SC_STRUCT_PACK_END

extern dlp_ibe_set_t param_dlp_ibe_0;
extern dlp_ibe_set_t param_dlp_ibe_1;
#if 0
extern dlp_ibe_set_t param_dlp_ibe_2;
extern dlp_ibe_set_t param_dlp_ibe_3;
extern dlp_ibe_set_t param_dlp_ibe_4;
extern dlp_ibe_set_t param_dlp_ibe_5;
#endif

#if 0
extern dlp_ibe_set_t param_dlp_ibe_6;
extern dlp_ibe_set_t param_dlp_ibe_7;
extern dlp_ibe_set_t param_dlp_ibe_8;
extern dlp_ibe_set_t param_dlp_ibe_9;
extern dlp_ibe_set_t param_dlp_ibe_10;
#endif

/// A struct used to store DLP IBE scheme variables
SC_STRUCT_PACK_START
typedef struct dlp_ibe_cfg_t {
    dlp_ibe_set_t            *params;
    SINT32                   *user_key;
    safecrypto_ntt_e          ntt_optimisation;
    ntt_params_t              ntt;
    sc_entropy_type_e         entropy;
    DOUBLE                   *master_tree;
    SINT32                    keep_matrices;
    SINT32                   *b;
    GSO_TYPE                 *b_gs SC_DEFAULT_ALIGNED;
    GSO_TYPE                 *b_gs_inv_norm SC_DEFAULT_ALIGNED;
} SC_STRUCT_PACKED dlp_ibe_cfg_t;
SC_STRUCT_PACK_END
