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

#ifndef NTT_NEEDS_8380417
#define NTT_NEEDS_8380417
#endif

#ifndef NEEDS_GAUSSIAN_ZIGGURAT
#define NEEDS_GAUSSIAN_ZIGGURAT
#endif


#include "safecrypto_private.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/xof.h"
#include "utils/arith/arith.h"
#include "utils/sampling/sampling.h"

#define DILITHIUM_USE_CSPRNG_SAM
#define DILITHIUM_USE_H_FUNC_XOF
#define DILITHIUM_XOF_TYPE      SC_XOF_SHAKE128

#define DILITHIUM_USE_SPARSE_MULTIPLIER

/// t1 and NTT(t0) are stored as components of the private key
#ifndef DILITHIUM_USE_SPARSE_MULTIPLIER
#define DILITHIUM_STORE_T_RESIDUALS
#endif

/// Compute the NTT of the input to create_rand_product() as an initial step
#define DILITHIUM_STORE_NTT_MATRIX_INPUT

#ifdef DILITHIUM_STORE_T_RESIDUALS
#define NUM_DILITHIUM_PRIVKEY_K     4
#else
#define NUM_DILITHIUM_PRIVKEY_K     2
#endif


SC_STRUCT_PACK_START
typedef struct dilithium_set_t {
    UINT32        set;
    sc_hash_e     oracle_hash;
    UINT32        n;
    UINT32        n_bits;
    UINT32        q;
    UINT32        q_bits;
    UINT32        k;
    UINT32        l;
    UINT32        d;
    UINT32        max_singular_s;
    UINT32        weight_of_c;
    UINT32        gamma_1;
    UINT32        gamma_1_bits;
    UINT32        gamma_2;
    FLOAT         sigma;
    FLOAT         tailcut;
    UINT32        alpha;
    UINT32        alpha_bits;
    UINT32        eta;
    UINT32        eta_bits;
    UINT32        z_bits;
    UINT32        beta;
    UINT32        omega;
    UINT32        omega_bits;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT32       *w;
    SINT32       *r;
    SINT32        prim_root;
#else
    const SINT32 *w;
    const SINT32 *r;
#endif
} SC_STRUCT_PACKED dilithium_set_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct dilithium_cfg_t {
    dilithium_set_t   *params;
    safecrypto_ntt_e   ntt_optimisation;
    ntt_params_t       ntt;
    ntt_params_t       ntt_alpha;
    sc_entropy_type_e  entropy;
    sc_hash_e          oracle_hash;
    prng_ctx_t        *csprng[2];
} SC_STRUCT_PACKED dilithium_cfg_t;
SC_STRUCT_PACK_END


/// Dilithium Parameter Sets
/// @{
// Parameter Set 0 - Weak
extern dilithium_set_t param_dilithium_0;

// Parameter Set 1 - Medium
extern dilithium_set_t param_dilithium_1;

// Parameter Set 2 - Recommended
extern dilithium_set_t param_dilithium_2;

// Parameter Set 3 - Very High
extern dilithium_set_t param_dilithium_3;
/// @}


/// Dilithium-G Parameter Sets
/// @{
// Parameter Set 0 - Weak
extern dilithium_set_t param_dilithium_g_0;

// Parameter Set 1 - Medium
extern dilithium_set_t param_dilithium_g_1;

// Parameter Set 2 - Recommended
extern dilithium_set_t param_dilithium_g_2;

// Parameter Set 3 - Very High
extern dilithium_set_t param_dilithium_g_3;
/// @}
