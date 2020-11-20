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


// A callback function used to generate identical entropy for the CSPRNG on every run
static void prng_entropy_source(size_t n, UINT8 *data)
{
    size_t i;
    for (i=0; i<n; i++) {
        data[i] = i;
    }
}

int main(void)
{
	SINT32 *h, retval;
    FLOAT *b_gs, *b_gs_inv_norm;
    gpv_t gpv;
    size_t i;
    static const size_t n = 1024;
    static const SINT32 q = 0x403001;//12289;//1073741824;//51750913;
    utils_sampling_t *sampling;

    // Configure the GPV struct and allocate memory
    gpv.n = n;
    gpv.f = SC_MALLOC(sizeof(SINT32) * (n+1));
    gpv.g = SC_MALLOC(sizeof(SINT32) * (n+1));
    gpv.F = SC_MALLOC(sizeof(SINT32) * (n+1));
    gpv.G = SC_MALLOC(sizeof(SINT32) * (n+1));
    gpv.b = SC_MALLOC(sizeof(SINT32) * 4*n*n);
    h     = SC_MALLOC(sizeof(SINT32) * (n+1));
    b_gs  = SC_MALLOC(sizeof(FLOAT) * (4*n*n + 2*n));
    b_gs_inv_norm = b_gs + 4*n*n;

    // Create an instance of the ENS signature scheme
    UINT32 flags[1] = {SC_FLAG_NONE};
	safecrypto_t *sc = safecrypto_create(SC_SCHEME_IBE_DLP, 0, flags);

    // Create a CSPRNG with a reasonably larger buffer size
#if 0
    // This will generate random Master Keys
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
#else
    // This will generate the same Master Key every time (modify prng_entropy_source() to suit)
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_CALLBACK, SC_PRNG_ISAAC,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_set_entropy_callback((void*)prng_entropy_source);
#endif
    prng_init(prng_ctx, NULL, 0);

    // Create a CDT Gaussian sampler
    FLOAT sigma = sqrtf((1.36 * q / 2) / n);
	sampling = create_sampler(CDF_GAUSSIAN_SAMPLING,
        SAMPLING_64BIT, NORMAL_SAMPLES, n, SAMPLING_DISABLE_BOOTSTRAP,
        prng_ctx, 13.0f, sigma);

    // Generate the master key
	retval = gpv_gen_basis(sc, gpv.f, gpv.g, h, n, q, sampling, prng_ctx, gpv.F, gpv.G, 0);
    if (retval < 0) {
        fprintf(stderr, "Basis generation failed!\n");
        goto finish;
    }

    // Print out the Master Key
    fprintf(stdout, "q = %d, n = %zu\n", q, n);
    fprintf(stdout, "f = ");
    for (i=0; i<n; i++) {
        fprintf(stdout, "%5d ", gpv.f[i]);
        if (15 == (i&15)) fprintf(stdout, "\n    ");
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "g = ");
    for (i=0; i<n; i++) {
        fprintf(stdout, "%5d ", gpv.g[i]);
        if (15 == (i&15)) fprintf(stdout, "\n    ");
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "F = ");
    for (i=0; i<n; i++) {
        fprintf(stdout, "%6d ", gpv.F[i]);
        if (15 == (i&15)) fprintf(stdout, "\n    ");
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "G = ");
    for (i=0; i<n; i++) {
        fprintf(stdout, "%6d ", gpv.G[i]);
        if (15 == (i&15)) fprintf(stdout, "\n    ");
    }
    fprintf(stdout, "\n");

    // Expand the basic input polynomials to form the polynomial basis matrix
    retval = gpv_expand_basis(&gpv);
    if (SC_FUNC_SUCCESS != retval) {
        fprintf(stderr, "Basis expansion failed!\n");
        goto finish;
    }

    // Gram-Schmidt orthogonolisation of the polynomial basis
    // and precompute the norm of each row of b_gs
    modified_gram_schmidt_fast_flt(&gpv, b_gs, q);
    gpv_precompute_inv_flt(b_gs, b_gs_inv_norm, 2*n);

finish:
    // Free resources
	SC_FREE(gpv.f, sizeof(SINT32) * (n+1));
	SC_FREE(gpv.g, sizeof(SINT32) * (n+1));
	SC_FREE(gpv.F, sizeof(SINT32) * (n+1));
	SC_FREE(gpv.G, sizeof(SINT32) * (n+1));
    SC_FREE(gpv.b, sizeof(SINT32) * 4*n*n);
    SC_FREE(h, sizeof(SINT32) * (n+1));
    SC_FREE(b_gs, sizeof(FLOAT) * (4*n*n + 2*n));

    prng_destroy(prng_ctx);
    safecrypto_destroy(sc);

	return EXIT_SUCCESS;
}


