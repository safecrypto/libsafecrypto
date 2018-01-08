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

#include "chacha20_csprng.h"
#include "safecrypto_private.h"

static void reseed_chacha20(chacha20_state_t *state)
{
    UINT8 seed[40];
    state->reseed_ctr = 0;
    state->get_random(40, seed, state->entropy_arg); // i.e. 256-bit key and 64-bit IV
    chacha_keysetup(&state->ctx, seed, 256);
    chacha_ivsetup(&state->ctx, seed+32, (const UINT8*)&state->ctr);
    SC_MEMZERO(state->data, 16 * sizeof(UINT8));
}

chacha20_state_t * create_chacha20(func_get_random func,
    user_entropy_t *user_entropy, size_t seed_period)
{
    chacha20_state_t *state = SC_MALLOC(sizeof(chacha20_state_t));
    if (NULL == state) {
        return NULL;
    }

    state->get_random = func;
    state->seed_period = seed_period;
    state->data_count = 0;
    state->entropy_arg = user_entropy;

    reseed_chacha20(state);

    return state;
}

SINT32 destroy_chacha20(chacha20_state_t *state)
{
    if (NULL == state) {
        return SC_FUNC_FAILURE;
    }

    state->data_count = 0;
    reseed_chacha20(state);

    return SC_FUNC_SUCCESS;
}

SINT32 reset_chacha20(chacha20_state_t *state)
{
    if (NULL == state) {
        return SC_FUNC_FAILURE;
    }

    SC_FREE(state, sizeof(chacha20_state_t));

    return SC_FUNC_SUCCESS;
}

static inline void update_seed(chacha20_state_t *state)
{
    if (state->seed_period <= state->reseed_ctr) {
        reseed_chacha20(state);
    }
}

static inline UINT32 csprng_get_next_uint32(chacha20_state_t *state)
{
    state->data_count += 4;
    if (16 == state->data_count) {
        state->data_count = 0;
        chacha_encrypt_bytes(&state->ctx, state->data, state->data, 16);
    }
    return ((UINT32)state->data[state->data_count+0] << 24) |
           ((UINT32)state->data[state->data_count+1] << 16) |
           ((UINT32)state->data[state->data_count+2] <<  8) |
           ((UINT32)state->data[state->data_count+3]      );
}

UINT32 chacha20_random_32(chacha20_state_t *state)
{
    state->reseed_ctr += 4;
    update_seed(state);
    return csprng_get_next_uint32(state);
}

#ifdef HAVE_64BIT
UINT64 chacha20_random_64(chacha20_state_t *state)
{
    state->reseed_ctr += 8;
    update_seed(state);
    return ((UINT64)csprng_get_next_uint32(state) << 32) |
            (UINT64)csprng_get_next_uint32(state);
}
#endif
