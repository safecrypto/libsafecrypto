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

#include "isaac_csprng.h"


static void reseed_isaac(isaac_state_t *state)
{
    state->reseed_ctr = 0;

#ifdef CONSTRAINED_SYSTEM
    union u {
        UINT64 u64;
        UINT32 u32[2];
        UINT8  u8[8];
    };
#else
    union u {
        UINT64 u64[16];
        UINT32 u32[2*16];
        UINT8  u8[8*16];
    };
#endif

#ifdef CONSTRAINED_SYSTEM
    for (size_t i=0; i<RANDSIZ; i++) {
        union u seed;
#ifdef HAVE_64BIT
        state->get_random(8, seed.u8, state->entropy_arg);
        state->rand_ctx.randrsl[i] = seed.u64;
#else
        state->get_random(4, seed.u8, state->entropy_arg);
        state->rand_ctx.randrsl[i] = seed.u32[0];
#endif
    }
#else
    for (size_t i=0; i<RANDSIZ>>4; i+=16) {
        union u seed;
#ifdef HAVE_64BIT
        state->get_random(8*16, seed.u8, state->entropy_arg);
        state->rand_ctx.randrsl[i] = seed.u64[0];
        state->rand_ctx.randrsl[i+1] = seed.u64[1];
        state->rand_ctx.randrsl[i+2] = seed.u64[2];
        state->rand_ctx.randrsl[i+3] = seed.u64[3];
        state->rand_ctx.randrsl[i+4] = seed.u64[4];
        state->rand_ctx.randrsl[i+5] = seed.u64[5];
        state->rand_ctx.randrsl[i+6] = seed.u64[6];
        state->rand_ctx.randrsl[i+7] = seed.u64[7];
        state->rand_ctx.randrsl[i+8] = seed.u64[8];
        state->rand_ctx.randrsl[i+9] = seed.u64[9];
        state->rand_ctx.randrsl[i+10] = seed.u64[10];
        state->rand_ctx.randrsl[i+11] = seed.u64[11];
        state->rand_ctx.randrsl[i+12] = seed.u64[12];
        state->rand_ctx.randrsl[i+13] = seed.u64[13];
        state->rand_ctx.randrsl[i+14] = seed.u64[14];
        state->rand_ctx.randrsl[i+15] = seed.u64[15];
#else
        state->get_random(4*16, seed.u8, state->entropy_arg);
        state->rand_ctx.randrsl[i] = seed.u32[0];
        state->rand_ctx.randrsl[i+1] = seed.u32[1];
        state->rand_ctx.randrsl[i+2] = seed.u32[2];
        state->rand_ctx.randrsl[i+3] = seed.u32[3];
        state->rand_ctx.randrsl[i+4] = seed.u32[4];
        state->rand_ctx.randrsl[i+5] = seed.u32[5];
        state->rand_ctx.randrsl[i+6] = seed.u32[6];
        state->rand_ctx.randrsl[i+7] = seed.u32[7];
        state->rand_ctx.randrsl[i+8] = seed.u32[8];
        state->rand_ctx.randrsl[i+9] = seed.u32[9];
        state->rand_ctx.randrsl[i+10] = seed.u32[10];
        state->rand_ctx.randrsl[i+11] = seed.u32[11];
        state->rand_ctx.randrsl[i+12] = seed.u32[12];
        state->rand_ctx.randrsl[i+13] = seed.u32[13];
        state->rand_ctx.randrsl[i+14] = seed.u32[14];
        state->rand_ctx.randrsl[i+15] = seed.u32[15];
#endif
#endif
    }
    randinit(&state->rand_ctx, 1);
}

isaac_state_t * create_isaac(func_get_random func,
    user_entropy_t *user_entropy, size_t seed_period)
{
    isaac_state_t *state = PRNG_MALLOC(sizeof(isaac_state_t));
    if (NULL == state) {
        return NULL;
    }

    state->get_random  = func;
    state->entropy_arg = user_entropy;
    state->seed_period = seed_period;

    reseed_isaac(state);

    return state;
}

SINT32 destroy_isaac(isaac_state_t *state)
{
    if (NULL == state) {
        return PRNG_FUNC_FAILURE;
    }

    PRNG_FREE(state, sizeof(isaac_state_t));

    return PRNG_FUNC_SUCCESS;
}

SINT32 reset_isaac(isaac_state_t *state)
{
    if (NULL == state) {
        return PRNG_FUNC_FAILURE;
    }

    reseed_isaac(state);

    return PRNG_FUNC_SUCCESS;
}

static void update_seed(isaac_state_t *state)
{
    if (state->seed_period <= state->reseed_ctr) {
        reseed_isaac(state);
    }
}

UINT32 isaac_random_32(isaac_state_t *state)
{
    state->reseed_ctr += 4;
    update_seed(state);
    return rand(&state->rand_ctx);
}

#ifdef HAVE_64BIT
UINT64 isaac_random_64(isaac_state_t *state)
{
    state->reseed_ctr += 8;
    update_seed(state);
    return rand(&state->rand_ctx);
}
#endif
