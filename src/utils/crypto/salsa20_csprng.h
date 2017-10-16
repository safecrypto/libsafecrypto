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

#include "prng_types.h"
#include "salsa/salsa20.h"


typedef struct user_entropy user_entropy_t;

/// Forward declaration of the entropy gathering function pointer
typedef void (*func_get_random)(size_t, UINT8 *, user_entropy_t *);

/// A struct used to store the current state of a SALSA20-CSPRNG
PRNG_STRUCT_PACK_START
typedef struct salsa20_state_t
{
    salsa_ctx_t     ctx;
    func_get_random get_random;
    user_entropy_t *entropy_arg;
    UINT8           data[16];
    size_t          data_count;
    UINT64          ctr;
    UINT32          reseed_ctr;
    UINT32          seed_period;
} PRNG_STRUCT_PACKED salsa20_state_t;
PRNG_STRUCT_PACK_END


/// Create an instance of a SALSA20-CSPRNG
/// @param func A function pointer for the seed entropy source
/// @param seed_period The number of bytes generated before seeding reoccurs
salsa20_state_t* create_salsa20(func_get_random func,
	user_entropy_t *user_entropy, size_t seed_period);

/// Destroy an instance of a SALSA20-CSPRNG
SINT32 destroy_salsa20(salsa20_state_t *state);

/// Reset an instance of a SALSA20-CSPRNG
SINT32 reset_salsa20(salsa20_state_t *state);

/// Obtain 32-bits of randomly generated data
UINT32 salsa20_random_32(salsa20_state_t *state);

#ifdef HAVE_64BIT
/// Obtain 64-bits of randomly generated data
UINT64 salsa20_random_64(salsa20_state_t *state);
#endif
