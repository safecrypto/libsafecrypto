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

#include "gaussian_bac.h"
#include "sampling.h"
#include "safecrypto_private.h"
#include "utils/crypto/prng.h"
#include "utils/entropy/bac.h"

#include <math.h>


#define BYTE_MASK             0xFF
#define BYTE_UPPER_LIMIT      0x100

#define BAC_64_LOWER_BOUND    0x0000000000000000
#define BAC_64_RANGE          0xFFFFFFFFFFFFFFFF
#define BAC_64_RANGE_MSB      0x8000000000000000
#define BAC_64_MID_LSB_MASK   0xFFFFFFFE

#define BAC_32_LOWER_BOUND    0x00000000
#define BAC_32_RANGE          0xFFFFFFFF
#define BAC_32_RANGE_MSB      0x80000000
#define BAC_32_MID_LSB_MASK   0xFFFFFFFE


#ifdef HAVE_64BIT
SC_STRUCT_PACK_START
typedef struct _gauss_bac_64 {
    UINT64 *bac;
    SINT32 bac_size;
    UINT64 v;
    SINT32 bits;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_bac_64_t;
SC_STRUCT_PACK_END
#endif

#ifdef HAVE_64BIT
void * gaussian_bac_create_64(prng_ctx_t *prng_ctx,
    FLOAT tail, FLOAT sigma, size_t dummy, sample_blinding_e blinding)
{
    (void) dummy;

    SINT32 bits = ceil(log2(tail * sigma));

    // Allocate memory for the structure to be passed as a void *
    gauss_bac_64_t *gauss = SC_MALLOC(sizeof(gauss_bac_64_t));
    if (NULL == gauss) {
        return NULL;
    }

    // Allocate memory for the pre-computed Gaussian distribution
    gauss->bac = SC_MALLOC((1 << bits) * sizeof(UINT64));
    if (NULL == gauss->bac) {
        SC_FREE(gauss, sizeof(gauss_bac_64_t));
        return NULL;
    }

    // Store the size of the distribution
    gauss->bac_size = (1 << bits);

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sigma *= 0.7071067811865475244008443621L;
    }

    gauss->v = prng_64(prng_ctx);
    gauss->bits = bits;
    gauss->prng_ctx = prng_ctx;

    gauss_freq_bac_64(gauss->bac, sigma, 1 << bits);

    return (void *) gauss;
}

SINT32 gaussian_bac_destroy_64(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_bac_64_t *gauss = (gauss_bac_64_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->bac, gauss->bac_size * sizeof(UINT64));
    SC_FREE(*sampler, sizeof(gauss_bac_64_t));

    return SC_FUNC_SUCCESS;
}

prng_ctx_t * gaussian_bac_get_prng_64(void *sampler)
{
    gauss_bac_64_t *gauss = (gauss_bac_64_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}

SINT32 gaussian_bac_sample_64(void *sampler)
{
    SINT32 icnt, ocnt;
    UINT64 b, l, c;
    UINT32 ibyt = 0; // Will be initialised in the while loop upon
                     // first entry as icnt is 0, this squashes compiler warning
    UINT32 owrd;
    gauss_bac_64_t *gauss = (gauss_bac_64_t *) sampler;
    prng_ctx_t *prng_ctx = gauss->prng_ctx;

    b = BAC_64_LOWER_BOUND;                    // lower bound
    l = BAC_64_RANGE;                          // range

    icnt = 0;
    owrd = 0;
    for (ocnt = gauss->bits - 1; ocnt >= 0; ocnt--) {

        // midpoint split
        c = gauss->bac[(owrd & (BAC_64_MID_LSB_MASK << ocnt)) | (1 << ocnt)];
        c = mul64hi(l, c);              // scale to range

        if (gauss->v - b < c) {         // compare
            l = c;                      // 0 bit; lower part
        }
        else {
            b += c;                     // 1 bit; higher part
            l -= c;                     // flip range to upper half
            owrd |= 1 << ocnt;          // set the bit
        }

        while (l < BAC_64_RANGE_MSB) {

            icnt--;                     // fetch a new bit
            if (icnt < 0) {
                ibyt = prng_8(prng_ctx);
                icnt = 7;
            }
            gauss->v <<= 1;             // add bit to v
            gauss->v += (ibyt >> icnt) & 1;

            b <<= 1;                    // shift left
            l <<= 1;                    // double range
        }
    }

    return owrd - (1 << (gauss->bits-1));
}
#endif

