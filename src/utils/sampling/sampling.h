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

#include "safecrypto_types.h"
#include "safecrypto_private.h"

#ifndef CONSTRAINED_SYSTEM
#define HAVE_CDF_GAUSSIAN_SAMPLING
//#define HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
#else
#define HAVE_CDF_GAUSSIAN_SAMPLING
//#define HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
#define HAVE_BERNOULLI_GAUSSIAN_SAMPLING
#define HAVE_BAC_GAUSSIAN_SAMPLING
#define HAVE_HUFFMAN_GAUSSIAN_SAMPLING
#define HAVE_KNUTH_YAO_GAUSSIAN_SAMPLING
#define HAVE_KNUTH_YAO_FAST_GAUSSIAN_SAMPLING
#endif

/// An enumerated type used to describe the desired sample precision
typedef enum sample_precision {
    SAMPLING_32BIT  = 32,
    SAMPLING_64BIT  = 64,
    SAMPLING_128BIT = 128,
    SAMPLING_192BIT = 192,
    SAMPLING_256BIT = 256,
} sample_precision_e;

/// An enumerated type describing the use of a bootstrapped gaussian sampler
typedef enum sample_bootstrap {
    SAMPLING_DISABLE_BOOTSTRAP = 0,
    SAMPLING_MW_BOOTSTRAP,
} sample_bootstrap_e;

// Forward declaration of the struct used to define sampling
typedef struct _utils_sampling utils_sampling_t;

/// Type definitions for the Gaussian sampler function pointers
/// @{
typedef void * (*utils_sampling_create)(prng_ctx_t*, FLOAT, FLOAT,
    size_t, sample_blinding_e);
typedef SINT32 (*utils_sampling_destroy)(void **);
typedef prng_ctx_t * (*utils_sampling_get_prng)(void *);
typedef SINT32 (*utils_sampling_sample)(void *);
typedef SINT32 (*utils_sampling_vector_sample_16)(prng_ctx_t *,
    const utils_sampling_t *, void *, SINT16 *, size_t);
typedef SINT32 (*utils_sampling_vector_sample_32)(prng_ctx_t *,
    const utils_sampling_t *, void *, SINT32 *, size_t);
typedef SINT32 (*utils_sampling_vector_sample_flt)(prng_ctx_t *,
    const utils_sampling_t *, void *, FLOAT *, size_t);
typedef SINT32 (*utils_sampling_vector_sample_dbl)(prng_ctx_t *,
    const utils_sampling_t *, void *, DOUBLE *, size_t);
typedef SINT32 (*utils_sampling_vector_sample_ldbl)(prng_ctx_t *,
    const utils_sampling_t *, void *, LONGDOUBLE *, size_t);
/// @}

/// A struct defining the configuration of the Gaussian sampler and all
/// associated function pointers
SC_STRUCT_PACK_START
typedef struct _utils_sampling {
    utils_sampling_create             create;
    utils_sampling_destroy            destroy;
    utils_sampling_get_prng           get_prng;
    utils_sampling_sample             sample;
    utils_sampling_vector_sample_16   vector_16;
    utils_sampling_vector_sample_32   vector_32;
    utils_sampling_vector_sample_flt  vector_flt;
    utils_sampling_vector_sample_dbl  vector_dbl;
    utils_sampling_vector_sample_ldbl vector_long_dbl;
    sample_precision_e                precision;
    SINT32                            dimension;
    sample_bootstrap_e                bootstrapped;
    FLOAT                             sigma2;
    void                             *gauss;
    void                             *bootstrap;
} SC_STRUCT_PACKED utils_sampling_t;
SC_STRUCT_PACK_END

/// Create an instance of a Gaussian sampler
extern utils_sampling_t * create_sampler(random_sampling_e type,
    sample_precision_e precision, sample_blinding_e blinding,
    SINT32 dimension, sample_bootstrap_e bootstrapped,
    prng_ctx_t *prng_ctx, FLOAT tail, FLOAT sigma);

/// Destroy an instance of a Gaussian sampler and set the pointer to NULL
extern SINT32 destroy_sampler(utils_sampling_t **sampler);

/// Return a sample using the specified Gaussian sampler
extern SINT32 get_sample(utils_sampling_t *sampler);

/// Return a sample using the specified Gaussian sampler (if a bootstrapped method is used)
extern SINT32 get_bootstrap_sample(utils_sampling_t *sampler, FLOAT sigma, FLOAT centre);

/// Obtain a vector of 16-bit Gaussian samples
extern SINT32 get_vector_16(utils_sampling_t *sampler, SINT16 *v, size_t n, FLOAT centre);

/// Obtain a vector of 32-bit Gaussian samples
extern SINT32 get_vector_32(utils_sampling_t *sampler, SINT32 *v, size_t n, FLOAT centre);

