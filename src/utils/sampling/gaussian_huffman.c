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

#include "utils/sampling/gaussian_huffman.h"
#include "utils/sampling/sampling.h"
#include "safecrypto_private.h"
#include "utils/crypto/prng.h"
#include "utils/entropy/huffman.h"

#include <math.h>

SC_STRUCT_PACK_START
typedef struct _gauss_huffman {
    huffman_table_t *table;
    SINT32 bits;
    SINT32 sign_bit;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_huffman_t;
SC_STRUCT_PACK_END


void * gaussian_huffman_create(prng_ctx_t *prng_ctx,
    FLOAT tail, FLOAT sigma, size_t dummy, sample_blinding_e blinding)
{
    (void) dummy;

    SINT32 bits = ceil(log2(tail * sigma));

    // Allocate memory for the structure to be passed as a void *
    gauss_huffman_t *gauss = SC_MALLOC(sizeof(gauss_huffman_t));
    if (NULL == gauss) {
        return NULL;
    }

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sigma *= 0.7071067811865475244008443621L;
    }

#if 0
    gauss->table    = create_huffman_gaussian_sampler(bits-3, sigma/8);
    gauss->sign_bit = 1 << (bits - 3);
#else
    gauss->table    = create_huffman_gaussian_sampler(bits, sigma);
    gauss->sign_bit = 1 << bits;
#endif
    gauss->bits     = bits;
    gauss->prng_ctx = prng_ctx;

    return (void *) gauss;
}

SINT32 gaussian_huffman_destroy(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_huffman_t *gauss = (gauss_huffman_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    destroy_huffman(&gauss->table);
    SC_FREE(*sampler, sizeof(gauss_huffman_t));

    return SC_FUNC_SUCCESS;
}

prng_ctx_t * gaussian_huffman_get_prng(void *sampler)
{
    gauss_huffman_t *gauss = (gauss_huffman_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}

SINT32 gaussian_huffman_sample(void *sampler)
{
    SINT32 value;
    gauss_huffman_t *gauss = (gauss_huffman_t *) sampler;

    sample_huffman(gauss->prng_ctx, gauss->table, &value);
#if 0
    if (value & gauss->sign_bit) {
        // Generate the remaining LSBs using uniform random bits
        UINT32 bits = prng_32();
        value |= bits & 0x7;
    }
#endif

    return value;
}

