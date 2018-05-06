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

#include <stdint.h>
#include "safecrypto_private.h"
#include "utils/arith/arith.h"
#include "utils/arith/gpv.h"
#include "utils/crypto/hash.h"
#include "utils/sampling/sampling.h"
#include "utils/arith/falcon.h"


#define FALCON_USE_SINGLE_PREC_FLOATS
//#define FALCON_USE_EFFICIENT_GAUSSIAN_SAMPLING
//#define FALCON_GAUSSIAN_SAMPLE_MW_BOOTSTRAP

/// Use a Hash/CSPRNG to provide a random oracle rather than a XOF
//#define FALCON_USE_RANDOM_ORACLE_CSPRNG

#ifdef FALCON_USE_SINGLE_PREC_FLOATS
#define GSO_TYPE                FLOAT
#define gaussian_lattice_sample gaussian_lattice_sample_flt
#define gpv_precompute_inv      gpv_precompute_inv_flt
#define modified_gram_schmidt   modified_gram_schmidt_fast_flt
#else
#ifdef FALCON_USE_DOUBLE_PREC_FLOATS
#define GSO_TYPE                DOUBLE
#define gaussian_lattice_sample gaussian_lattice_sample_dbl
#define gpv_precompute_inv      gpv_precompute_inv_dbl
#define modified_gram_schmidt   modified_gram_schmidt_fast_dbl
#else
#define GSO_TYPE                LONGDOUBLE
#define gaussian_lattice_sample gaussian_lattice_sample_ldbl
#define gpv_precompute_inv      gpv_precompute_inv_ldbl
#define modified_gram_schmidt   modified_gram_schmidt_fast_ldbl
#endif
#endif



/// Scheme creation
SINT32 falcon_sig_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 falcon_sig_destroy(safecrypto_t *sc);

/// Key pair generation function
SINT32 falcon_sig_keygen(safecrypto_t *sc);

/// Set key-pair lossless compression coding
SINT32 falcon_sig_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv);

/// Get key-pair lossless compression coding
SINT32 falcon_sig_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv);

/// Public key load function
SINT32 falcon_sig_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Private key load function
SINT32 falcon_sig_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Public key encode function used to disseminate the public key
SINT32 falcon_sig_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Private key encode function used to disseminate the private key
SINT32 falcon_sig_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Sign a message of m_len bytes
SINT32 falcon_sig_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen);

/// Verify a message of m_len bytes
SINT32 falcon_sig_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen);

/// Return a C-string output detailing the operation of the specified ENS/DLP instance
char * falcon_sig_stats(safecrypto_t *sc);

