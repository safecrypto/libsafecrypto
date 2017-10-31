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

// Keep It Simple Stupid

#include "kiss.h"
#include "mersenne_twister/mt19937ar.h"
#include "safecrypto_private.h"


#define JKISS (x = 1490024343005336237ULL * x + 123456789, y ^= y << 21, y ^= y >> 17, y ^= y << 30,   \
    t = 4294584393ULL * z1 + c1, c1 = t >> 32, z1 = t, t = 4246477509ULL * z2 + c2, c2 = t >> 32, \
          z2 = t, x + y + z1 + ((UINT64)z2 << 32)) /* Return 64-bit result */

#define U32C(v) (v##U)
#define U32V(v) ((UINT32)(v) & U32C(0xFFFFFFFF))
#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define U64C(v) (v##U)
#define U64V(v) ((UINT64)(v) & U64C(0xFFFFFFFFFFFFFFFF))
#define ROTL64(v, n) (U64V((v) << (n)) | ((v) >> (64 - (n))))

static void reseed_kiss(kiss_state_t *state)
{
    union u {
        UINT8 b[4];
        UINT32 w;
    };
    union u seed;
    state->reseed_ctr = 0;
    state->get_random(4, seed.b, state->entropy_arg);

#ifdef HAVE_64BIT
    // Seed variables
    state->x = 123456789123ULL;
    state->y = 987654321987ULL;
    state->z1 = 43219876;
    state->z2 = 21987643;
    state->c1 = 6543217;
    state->c2 = 1732654;

    state->x  = ROTL64(state->x,  (seed.w >> 26) & 0x3F);
    state->y  = ROTL64(state->y,  (seed.w >> 20) & 0x3F);
    state->z1 = ROTL32(state->z1, (seed.w >> 15) & 0x1F);
    state->z2 = ROTL32(state->z2, (seed.w >> 10) & 0x1F);
    state->c1 = ROTL32(state->c1, (seed.w >>  5) & 0x1F);
    state->c2 = ROTL32(state->c2, (seed.w      ) & 0x1F);
#endif

    init_genrand(state->mt, seed.w);
}

kiss_state_t * create_kiss(func_get_random func,
    user_entropy_t *user_entropy, size_t seed_period)
{
    kiss_state_t *state = SC_MALLOC(sizeof(kiss_state_t));
    if (NULL == state) {
        return NULL;
    }

    state->get_random = func;
    state->entropy_arg = user_entropy;
    state->seed_period = seed_period;

    state->mt = SC_MALLOC(sizeof(mt_state_t));
    if (NULL == state->mt) {
        SC_FREE(state, sizeof(kiss_state_t));
        return NULL;
    }

    reseed_kiss(state);

    return state;
}

SINT32 destroy_kiss(kiss_state_t *state)
{
    if (NULL == state) {
        return SC_FUNC_FAILURE;
    }

    SC_FREE(state->mt, sizeof(mt_state_t));
    SC_FREE(state, sizeof(kiss_state_t));

    return SC_FUNC_SUCCESS;
}

SINT32 reset_kiss(kiss_state_t *state)
{
    if (NULL == state) {
        return SC_FUNC_FAILURE;
    }

    reseed_kiss(state);

    return SC_FUNC_SUCCESS;
}

static inline void update_seed(kiss_state_t *state)
{
    if (state->seed_period <= state->reseed_ctr) {
        reseed_kiss(state);
    }
}

UINT32 kiss_random_32(kiss_state_t *state)
{
    state->reseed_ctr += 4;
    update_seed(state);
    return (UINT32)genrand_int32(state->mt);
}

#ifdef HAVE_64BIT
static UINT64 kiss(kiss_state_t *state)
{
    state->x = 1490024343005336237ULL * state->x + 123456789;
    state->y ^= state->y << 21;
    state->y ^= state->y >> 17;
    state->y ^= state->y << 30;
    state->t = 4294584393ULL * state->z1 + state->c1;
    state->c1 = state->t >> 32;
    state->z1 = state->t;
    state->t = 4246477509ULL * state->z2 + state->c2;
    state->c2 = state->t >> 32;
    state->z2 = state->t;
    return state->x + state->y + state->z1 + ((UINT64)state->z2 << 32);
}

UINT64 kiss_random_64(kiss_state_t *state)
{
    state->reseed_ctr += 8;
    update_seed(state);
    return kiss(state);
}
#endif


#undef U32C
#undef U32V
#undef ROTL32
#undef U64C
#undef U64V
#undef ROTL64
