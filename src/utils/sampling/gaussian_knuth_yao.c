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

#include "gaussian_knuth_yao.h"
#include "sampling.h"
#include "safecrypto_private.h"
#include "utils/crypto/prng.h"

#include <math.h>
#include "utils/arith/sc_math.h"


SC_STRUCT_PACK_START
typedef struct _gauss_knuth_yao {
    SINT32 num_rows;
    SINT32 num_cols;
    FLOAT  tailcut;
    SINT32 bound;
    UINT8  *prelut;
    SINT32 *hamming;
    UINT8  *pmat;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_knuth_yao_t;
SC_STRUCT_PACK_END


prng_ctx_t * gaussian_knuth_yao_get_prng(void *sampler)
{
    gauss_knuth_yao_t *gauss = (gauss_knuth_yao_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}


#ifdef HAVE_128BIT
void create_knuth_yao_table_128(gauss_knuth_yao_t * gauss, FLOAT sigma, sample_blinding_e blinding)
{
    SINT32 row, col;
    LONGDOUBLE d, e;

    // (1/sqrt(2*Pi)) / sigma
    d = 0.7978845608028653558798L / sigma;

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    e = -0.5L / (sigma * sigma);
    for (col=0; col<gauss->num_cols; col++) {
        UINT128 p;
        if (0 == col) {
            p = get_binary_expansion_fraction_128(d);
        }
        else {
            p = get_binary_expansion_fraction_128(d * expl(e * ((LONGDOUBLE) (col*col))));
        }
        for (row=0; row<gauss->num_rows; row++) {
            gauss->pmat[row*gauss->num_cols + col] = (p >> (127 - row)) & 0x1;
        }
    }
}
#endif

SINT32 gaussian_knuth_yao_sample_internal(void *sampler);

#ifdef HAVE_64BIT
void create_knuth_yao_table_64(gauss_knuth_yao_t * gauss, FLOAT sigma, sample_blinding_e blinding)
{
    SINT32 row, col;
    LONGDOUBLE d, e;

    // (1/sqrt(2*Pi)) / sigma
    d = 0.7978845608028653558798L / sigma;

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    e = -0.5L / (sigma * sigma);
    for (col=0; col<gauss->num_cols; col++) {
        UINT64 p;
        if (0 == col) {
            p = get_binary_expansion_fraction_64(d);
        }
        else {
            p = get_binary_expansion_fraction_64(d * expl(e * ((LONGDOUBLE) (col*col))));
        }

        for (row=0; row<gauss->num_rows; row++) {
            gauss->pmat[row*gauss->num_cols + col] = (p >> (63 - row)) & 0x1;
        }
    }
}
#endif

void create_knuth_yao_table_32(gauss_knuth_yao_t * gauss, FLOAT sigma, sample_blinding_e blinding)
{
    SINT32 row, col;
    LONGDOUBLE d, e;

    // (1/sqrt(2*Pi)) / sigma
    d = 0.7978845608028653558798L / sigma;

    // Fill the distribution from 0 to maximum, ensuring that overflow
    // is dealt with
    e = -0.5L / (sigma * sigma);
    for (col=0; col<gauss->num_cols; col++) {
        UINT32 p;
        if (0 == col) {
            p = get_binary_expansion_fraction_32(d);
        }
        else {
            p = get_binary_expansion_fraction_32(d * expl(e * ((LONGDOUBLE) (col*col))));
        }
        for (row=0; row<gauss->num_rows; row++) {
            gauss->pmat[row*gauss->num_cols + col] = (p >> (31 - row)) & 0x1;
        }
    }
}

void * gaussian_knuth_yao_create(prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma,
    sample_blinding_e blinding, SINT32 bitwidth)
{
    SINT32 row, col;

    // Allocate memory for the structure to be passed as a void *
    gauss_knuth_yao_t *gauss = SC_MALLOC(sizeof(gauss_knuth_yao_t));
    if (NULL == gauss) {
        return NULL;
    }

    if (bitwidth != 32 && bitwidth != 64 && bitwidth != 128) {
        return NULL;
    }

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sigma *= 0.7071067811865475244008443621L;
    }

    gauss->prng_ctx = prng_ctx;

    // Store the size of the distribution
    gauss->tailcut  = tail;
    gauss->bound    = (SINT32) ceil(gauss->tailcut * sigma);
    gauss->num_rows = bitwidth;//(1 << bits);
    gauss->num_cols = gauss->bound + 1;

    // Allocate memory for the pre-computed DDG
    gauss->pmat = SC_MALLOC(gauss->num_cols * gauss->num_rows);
    if (NULL == gauss->pmat) {
        SC_FREE(gauss, sizeof(gauss_knuth_yao_t));
        return NULL;
    }

    // Allocate memory for the Hamming distance table
    gauss->prelut = SC_MALLOC(256 * sizeof(UINT8));
    if (NULL == gauss->prelut) {
        SC_FREE(gauss->pmat, gauss->num_cols * gauss->num_rows);
        SC_FREE(gauss, sizeof(gauss_knuth_yao_t));
        return NULL;
    }

    gauss->hamming = SC_MALLOC(gauss->num_cols * sizeof(SINT32));
    if (NULL == gauss->hamming) {
        SC_FREE(gauss->prelut, 256 * sizeof(UINT8));
        SC_FREE(gauss->pmat, gauss->num_cols * gauss->num_rows);
        SC_FREE(gauss, sizeof(gauss_knuth_yao_t));
        return NULL;
    }

    // Create the table
    switch (bitwidth)
    {
#ifdef HAVE_128BIT
        case 128: create_knuth_yao_table_128(gauss, sigma, blinding); break;
#endif
#ifdef HAVE_64BIT
        case 64:  create_knuth_yao_table_64(gauss, sigma, blinding); break;
#endif
        default:  create_knuth_yao_table_32(gauss, sigma, blinding);
    }

    // Calculating the Hamming distance matrix
    for (col=0; col<gauss->num_cols; col++) {
        for (row=0; row<gauss->num_rows; row++) {
            gauss->hamming[col] += gauss->pmat[row * gauss->num_cols + col];
        }
    }

    return (void *) gauss;
}

#ifdef HAVE_128BIT
void * gaussian_knuth_yao_create_128(prng_ctx_t *prng_ctx,
    FLOAT tail, FLOAT sigma, size_t dummy, sample_blinding_e blinding)
{
    (void) dummy;
    return gaussian_knuth_yao_create(prng_ctx, tail, sigma, blinding, 128);
}
#endif

#ifdef HAVE_64BIT
void * gaussian_knuth_yao_create_64(prng_ctx_t *prng_ctx,
    FLOAT tail, FLOAT sigma, size_t dummy, sample_blinding_e blinding)
{
    (void) dummy;
    return gaussian_knuth_yao_create(prng_ctx, tail, sigma, blinding, 64);
}
#endif

void * gaussian_knuth_yao_create_32(prng_ctx_t *prng_ctx,
    FLOAT tail, FLOAT sigma, size_t dummy, sample_blinding_e blinding)
{
    (void) dummy;
    return gaussian_knuth_yao_create(prng_ctx, tail, sigma, blinding, 32);
}

SINT32 gaussian_knuth_yao_destroy(void **sampler)
{
    if (NULL == sampler)
        return SC_FUNC_FAILURE;

    // Obtain a pointer to the CDF Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_knuth_yao_t *gauss = (gauss_knuth_yao_t *) *sampler;
    if (NULL == gauss)
        return SC_FUNC_FAILURE;

    // Free the memory resources
    SC_FREE(gauss->hamming, gauss->num_cols * sizeof(SINT32));
    SC_FREE(gauss->prelut, 256 * sizeof(UINT8));
    SC_FREE(gauss->pmat, gauss->num_rows & gauss->num_cols);
    SC_FREE(*sampler, sizeof(gauss_knuth_yao_t));

    return SC_FUNC_SUCCESS;
}

static inline SINT32 ky_select(SINT32 a, SINT32 b, SINT32 mask)
{
    SINT32 output;
    output = mask & (a ^ b);
    output = output ^ a;
    return output;
}

SINT32 gaussian_knuth_yao_sample_internal(void *sampler)
{
    if (NULL == sampler)
        return 0;

    // Return a random gaussian sample from a pre-computed distribution
    gauss_knuth_yao_t *gauss = (gauss_knuth_yao_t *) sampler;

    SINT32 col, row;   // col and row number
    SINT32 dist, hit, S;
    SINT32 invalid_sample = gauss->bound;
    UINT32 rand;
    UINT8 *pmat;
    prng_ctx_t *prng_ctx = gauss->prng_ctx;
    
restart:
    dist = 0;
    hit = 0;
    pmat = gauss->pmat;
    S = 0;

    rand = prng_32(prng_ctx);

    for (row=0; row<gauss->num_rows; row++) {
        dist = 2 * dist + (rand & 1);
        rand >>= 1;
        if ((row&0x1F) == 0x1F) rand = prng_32(prng_ctx);
        for (col=0; col<gauss->num_cols; col++) {
            dist -= *pmat++;
            SINT32 uhit = (hit == 0 && dist < 0)? 1 : 0;
            S += ky_select(invalid_sample, col, uhit);
            hit += uhit;
        }
    }

    rand = prng_32(prng_ctx);
    S %= invalid_sample;
    if (0 == S && (rand & 0x1)) goto restart;

    return S;
}

SINT32 gaussian_knuth_yao_sample(void *sampler)
{
    if (NULL == sampler)
        return 0;

    // Return a random gaussian sample from a pre-computed distribution
    gauss_knuth_yao_t *gauss = (gauss_knuth_yao_t *) sampler;
    prng_ctx_t *prng_ctx = gauss->prng_ctx;

    SINT32 col, row;   // col and row number
    SINT32 dist, sample;
    SINT32 invalid_sample = gauss->bound;
    UINT32 rand;
    UINT8 *pmat;
    
restart:
    dist = 0;
    pmat = gauss->pmat;

    // NS: Would like to precompute the narrow central band
    // that occurs with most likelihood
    /*rand = (UINT32)prng_8();
    sample = gauss->prelut[rand];
    if (0 == (sample & 0x10)) {
        sample = (prng_bit())? sample : -sample;
        return sample;
    }*/

    rand = prng_32(prng_ctx);
    //dist = sample & 0xF;
    //sample &= 0xF;
    //pmat += 4 * gauss->num_cols;
    sample = 0;

    for (row=0; row<gauss->num_rows; row++) {
        dist = 2 * dist + (rand & 1);
        
        // Update the random number variable for later use
        rand >>= 1;
        if ((row&0x1F) == 0x1F) {
            rand = prng_32(prng_ctx);
        }

        // Update the sample based on the zero crossing
        for (col=0; col<gauss->num_cols; col++) {
            dist -= *pmat++;
            if (dist < 0) {
                sample += col;
                break;
            }
        }
    }

    // Make sure the value is within range. If it is a zero
    // then with 0.5 probability redo the sampling so
    // that zero is not oversampled. Also randomly convert to a
    // negative number.
    rand = prng_32(prng_ctx);
    sample = sample % invalid_sample;
    if (0 == sample && (rand & 0x1)) goto restart;
    sample = (rand & 0x2)? sample : -sample;

    return sample;
}

