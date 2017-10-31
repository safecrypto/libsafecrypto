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

#include <stdint.h>
#include "safecrypto_private.h"
#include "hash.h"

#include "utils/arith/arith.h"
#include "utils/sampling/sampling.h"

#ifdef HAVE_MULTITHREADING
#include "utils/threading/threadpool.h"
#include "utils/threading/pipe.h"
#endif

/// Enable the used of sparse multiplication rather than an NTT
//#define BLISS_USE_SPARSE_MULTIPLIER

#ifndef BLISS_USE_SPARSE_MULTIPLIER
/// @todo Warning! This will inevitably lead to differences between implementations
/// Allow keys and signatures to be stored/transmitted in the NTT "domain"
#define BLISS_ENABLE_NTT_TRANSMISSION
#endif

typedef struct bliss_set_t bliss_set_t;

SC_STRUCT_PACK_START
typedef struct bliss_cfg_t {
    bliss_set_t              *params;
    safecrypto_ntt_e          ntt_optimisation;
    ntt_params_t              ntt;
    ntt_params_t              ntt_p;
    ntt_params_t              ntt_2q;

#ifdef HAVE_MULTITHREADING
    utils_sampling_t         *sc_gauss_1;
    pipe_t                   *pipe_a;
    pipe_t                   *pipe_b;
    pipe_t                   *pipe_c;
    pipe_producer_t          *pipe_producer_a;
    pipe_producer_t          *pipe_producer_b;
    pipe_producer_t          *pipe_producer_c;
    pipe_consumer_t          *pipe_consumer_a;
    pipe_consumer_t          *pipe_consumer_b;
    pipe_consumer_t          *pipe_consumer_c;
    sc_threadpool_t          *pool_keygen;
    sc_threadpool_t          *pool_sign;
    UINT32                    mt_enable;
#endif

    sc_entropy_type_e         entropy;
    sc_hash_e                 oracle_hash;

} SC_STRUCT_PACKED bliss_cfg_t;
SC_STRUCT_PACK_END

/// Scheme creation
SINT32 bliss_b_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 bliss_b_destroy(safecrypto_t *sc);

/// Key pair generation function
SINT32 bliss_b_keygen(safecrypto_t *sc);

/// Public key load function
SINT32 bliss_b_pubkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Private key load function
SINT32 bliss_b_privkey_load(safecrypto_t *sc, const UINT8 *key, size_t key_len);

/// Public key encode function used to disseminate the public key
SINT32 bliss_b_pubkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Private key encode function used to disseminate the private key
SINT32 bliss_b_privkey_encode(safecrypto_t *sc, UINT8 **key, size_t *key_len);

/// Sign a message of m_len bytes
SINT32 bliss_b_sign(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    UINT8 **sigret, size_t *siglen);

/// Verify a message of m_len bytes
SINT32 bliss_b_verify(safecrypto_t *sc, const UINT8 *m, size_t m_len,
    const UINT8 *sigbuf, size_t siglen);

/// Return a C-string output detailing the operation of the specified BLISS-B instance
char * bliss_b_stats(safecrypto_t *sc);

