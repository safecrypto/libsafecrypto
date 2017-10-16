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

#ifndef NEEDS_GAUSSIAN_CDF
#define NEEDS_GAUSSIAN_CDF
#endif


#include "safecrypto_private.h"
#include "utils/arith/module_lwe.h"


// Use a Hash/CSPRNG rather than a XOF as a random oracle
#define KYBER_ENC_USE_CSPRNG_SAM

// The XOF to be used
#define KYBER_ENC_XOF_TYPE      SC_XOF_SHAKE128

// Use a sparse multiplier where applicable
#define KYBER_ENC_USE_SPARSE_MULTIPLIER

/// NTT(t) is stored as a component of the private key
#define KYBER_ENC_STORE_NTT_T      1

/// NTT(t) is stored as a component of the private key
#define KYBER_ENC_STORE_NTT_S      1


extern kyber_set_t param_kyber_enc_0;
extern kyber_set_t param_kyber_enc_1;
extern kyber_set_t param_kyber_enc_2;

