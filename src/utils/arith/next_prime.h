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

#include "safecrypto_types.h"
#include "utils/arith/limb.h"

#define NUM_MOD_PRIMES      1024
#define NUM_SMALL_PRIMES    172
extern const UINT16 small_primes[NUM_SMALL_PRIMES];


// Determine if a number is prime
SINT32 is_prime(sc_ulimb_t number);

// Obtain the next prime number that proceeds the input number
sc_ulimb_t next_prime(sc_ulimb_t a);
