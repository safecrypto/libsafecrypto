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
#ifdef HAVE_64BIT
#include "isaac/isaac64.h"
#else
#include "isaac/rand.h"
#endif

typedef struct user_entropy user_entropy_t;

/// Forward declaration of the entropy gathering function pointer
typedef void (*func_get_random)(size_t, UINT8 *, user_entropy_t *);

/// A struct used to store the current state of a ISAAC-CSPRNG
SC_STRUCT_PACK_START
typedef struct isaac_state_t
{
    randctx rand_ctx; // Context of ISAAC

    func_get_random get_random;
    user_entropy_t *entropy_arg;
    UINT32          reseed_ctr;
    UINT32          seed_period;
} SC_STRUCT_PACKED isaac_state_t;
SC_STRUCT_PACK_END


/// Create an instance of a ISAAC-CSPRNG
/// @param func A function pointer for the seed entropy source
/// @param seed_period The number of bytes generated before seeding reoccurs
isaac_state_t* create_isaac(func_get_random func,
	user_entropy_t *user_entropy, size_t seed_period);

/// Destroy an instance of a ISAAC-CSPRNG
SINT32 destroy_isaac(isaac_state_t *state);

/// Reset an instance of a ISAAC-CSPRNG to its initial state
SINT32 reset_isaac(isaac_state_t *state);

/// Obtain 32-bits of randomly generated data
UINT32 isaac_random_32(isaac_state_t *state);

#ifdef HAVE_64BIT
/// Obtain 64-bits of randomly generated data
UINT64 isaac_random_64(isaac_state_t *state);
#endif
