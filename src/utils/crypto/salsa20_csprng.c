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

#include "salsa20_csprng.h"


static void reseed_salsa20(salsa20_state_t *state)
{
    UINT8 seed[40];
    state->reseed_ctr = 0;
    state->get_random(40, seed, state->entropy_arg); // i.e. 256-bit key and 64-bit IV
    salsa_keysetup(&state->ctx, seed, 256);
    salsa_ivsetup(&state->ctx, seed+32, (const UINT8*)&state->ctr);
    PRNG_MEMZERO(state->data, 16 * sizeof(UINT8));
}

salsa20_state_t * create_salsa20(func_get_random func,
    user_entropy_t *user_entropy, size_t seed_period)
{
    salsa20_state_t *state = PRNG_MALLOC(sizeof(salsa20_state_t));
    if (NULL == state) {
        return NULL;
    }

    state->get_random = func;
    state->entropy_arg = user_entropy;
    state->seed_period = seed_period;
    state->data_count = 0;

    reseed_salsa20(state);

    return state;
}

SINT32 destroy_salsa20(salsa20_state_t *state)
{
    if (NULL == state) {
        return PRNG_FUNC_FAILURE;
    }

    PRNG_FREE(state, sizeof(salsa20_state_t));

    return PRNG_FUNC_SUCCESS;
}

SINT32 reset_salsa20(salsa20_state_t *state)
{
    if (NULL == state) {
        return PRNG_FUNC_FAILURE;
    }

    state->data_count = 0;
    reseed_salsa20(state);

    return PRNG_FUNC_SUCCESS;
}

static inline void update_seed(salsa20_state_t *state)
{
    if (state->seed_period <= state->reseed_ctr) {
        reseed_salsa20(state);
    }
}

static inline UINT32 csprng_get_next_uint32(salsa20_state_t *state)
{
    state->data_count += 4;
    if (16 == state->data_count) {
        state->data_count = 0;
        salsa_encrypt_bytes(&state->ctx, state->data, state->data, 16);
    }
    return ((UINT32)state->data[state->data_count+0] << 24) |
           ((UINT32)state->data[state->data_count+1] << 16) |
           ((UINT32)state->data[state->data_count+2] <<  8) |
           ((UINT32)state->data[state->data_count+3]      );
}

UINT32 salsa20_random_32(salsa20_state_t *state)
{
    state->reseed_ctr += 4;
    update_seed(state);
    return csprng_get_next_uint32(state);
}

#ifdef HAVE_64BIT
UINT64 salsa20_random_64(salsa20_state_t *state)
{
    state->reseed_ctr += 8;
    update_seed(state);
    return ((UINT64)csprng_get_next_uint32(state) << 32) |
            (UINT64)csprng_get_next_uint32(state);
}
#endif
