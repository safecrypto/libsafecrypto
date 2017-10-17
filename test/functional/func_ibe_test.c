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

#include <stdlib.h>
#include "safecrypto.h"
#include "utils/arith/gpv.h"
#include "utils/crypto/prng.h"
#include <math.h>


int main(void)
{
	SINT32 *f, *g, *h, *F, *G;
    size_t n = 512;
    SINT32 q = 1073741824;//51750913;
    utils_sampling_t *sampling;

    f = SC_MALLOC(sizeof(SINT32) * (n+1));
    g = SC_MALLOC(sizeof(SINT32) * (n+1));
    h = SC_MALLOC(sizeof(SINT32) * (n+1));
    F = SC_MALLOC(sizeof(SINT32) * (n+1));
    G = SC_MALLOC(sizeof(SINT32) * (n+1));

    UINT32 flags[1] = {SC_FLAG_NONE};
	safecrypto_t *sc = safecrypto_create(SC_SCHEME_SIG_ENS, 0, flags);

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    FLOAT sigma = sqrtf((1.36 * q / 2) / n);
	sampling = create_sampler(CDF_GAUSSIAN_SAMPLING,
        SAMPLING_64BIT, NORMAL_SAMPLES, n, SAMPLING_DISABLE_BOOTSTRAP,
        prng_ctx, 13.0f, sigma);

	gpv_gen_basis(sc, f, g, h, n, q, sampling, prng_ctx, F, G, 0);

	SC_FREE(f, sizeof(SINT32) * (n+1));
	SC_FREE(g, sizeof(SINT32) * (n+1));
	SC_FREE(h, sizeof(SINT32) * (n+1));
	SC_FREE(F, sizeof(SINT32) * (n+1));
	SC_FREE(G, sizeof(SINT32) * (n+1));

    prng_destroy(prng_ctx);
    safecrypto_destroy(sc);

	return EXIT_SUCCESS;
}


