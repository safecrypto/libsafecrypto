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

#include "dlp_ibe_params.h"
#include <stdint.h>
#include "safecrypto_private.h"
#include "utils/crypto/hash.h"

#include "utils/arith/arith.h"
#include "utils/sampling/sampling.h"
#include "utils/threading/pipe.h"
#include "utils/threading/threadpool.h"

#define SC_IBE_MESSAGE_LENGTH_N

/// Use a Hash/CSPRNG to provide a random oracle rather than a XOF
//#define DLP_USE_RANDOM_ORACLE_CSPRNG

/// Enable the use of a sub-optimal reference GSO function
//#define DLP_IBE_USE_CLASSICAL_GSO

/// Retain the GSO matrix and vector of norms in memory for re-use
#define DLP_IBE_KEEP_GSO_MATRICES   1

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


/// A struct use to store DLP IBE scheme variables
SC_STRUCT_PACK_START
typedef struct dlp_ibe_cfg_t {
    dlp_ibe_set_t            *params;
    SINT32                   *user_key;
    safecrypto_ntt_e          ntt_optimisation;
    ntt_params_t              ntt;
    sc_entropy_type_e         entropy;
    SINT32                    keep_matrices;
    SINT32                   *b;
    GSO_TYPE                 *b_gs SC_DEFAULT_ALIGNED;
    GSO_TYPE                 *b_gs_inv_norm SC_DEFAULT_ALIGNED;
} SC_STRUCT_PACKED dlp_ibe_cfg_t;
SC_STRUCT_PACK_END

/// Create an instance of the DLP IBE scheme
SINT32 dlp_ibe_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Destroy the specified instance of DLP IBE
SINT32 dlp_ibe_destroy(safecrypto_t *sc);

/// Generate a key pair for DLP IBE
SINT32 dlp_ibe_keygen(safecrypto_t *sc);

/// Key load and encode functions for storage and transmission
/// @{
SINT32 dlp_ibe_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);
SINT32 dlp_ibe_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);
SINT32 dlp_ibe_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);
SINT32 dlp_ibe_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);
/// @}

/// Load a User Secret Key to be used for decryption purposes
SINT32 dlp_ibe_secret_key(safecrypto_t *sc, size_t sklen, const UINT8 *sk);

/// Extract a User Secret Key for the specified User ID
SINT32 dlp_ibe_extract(safecrypto_t *sc, size_t idlen, const UINT8 *id,
    size_t *sklen, UINT8 **sk);

/// Perform an IBE Encrypt operation with the specified ID
SINT32 dlp_ibe_encrypt(safecrypto_t *sc, size_t idlen, const UINT8* id,
    size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to);

/// Perform an IBE Decrypt operation with the specified ID and a User Secret key
/// loaded using dlp_ibe_secret_key
SINT32 dlp_ibe_decrypt(safecrypto_t *sc, size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to);

/// Obtain a string containing the statistics gathered by the DLP IBE instance
char * dlp_ibe_stats(safecrypto_t *sc);
