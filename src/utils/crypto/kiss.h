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


/// Forward declaration of the Mersenne Twister state
typedef struct mt_state_t mt_state_t;

typedef struct user_entropy user_entropy_t;

/// Forward declaration of the entropy gathering function pointer
typedef void (*func_get_random)(size_t, UINT8 *, user_entropy_t *);

/// A struct used to store the current state of a KISS
SC_STRUCT_PACK_START
typedef struct kiss_state_t
{
    UINT64 x;
    UINT64 y;
    UINT32 z1;
    UINT32 z2;
    UINT32 c1;
    UINT32 c2;
    UINT64 t;
    mt_state_t *mt;

    func_get_random get_random;
    user_entropy_t *entropy_arg;
    UINT32          reseed_ctr;
    UINT32          seed_period;
} SC_STRUCT_PACKED kiss_state_t;
SC_STRUCT_PACK_END


/// Create an instance of a KISS
/// @param func A function pointer for the seed entropy source
/// @param seed_period The number of bytes generated before seeding reoccurs
kiss_state_t* create_kiss(func_get_random func,
    user_entropy_t *user_entropy, size_t seed_period);

/// Destroy an instance of a KISS
SINT32 destroy_kiss(kiss_state_t *state);

/// Reset an instance of a KISS
SINT32 reset_kiss(kiss_state_t *state);

/// Obtain 32-bits of randomly generated data
UINT32 kiss_random_32(kiss_state_t *state);

#ifdef HAVE_64BIT
/// Obtain 64-bits of randomly generated data
UINT64 kiss_random_64(kiss_state_t *state);
#endif
