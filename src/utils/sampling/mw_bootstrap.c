/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

#include "mw_bootstrap.h"
#include "sampling.h"
#include "utils/arith/sc_math.h"
#include "utils/crypto/prng.h"
#include <math.h>


/// A struct used to store the configuration of a Gauss combiner level
SC_STRUCT_PACK_START
typedef struct _mw_gauss_combiner_t {
    const utils_sampling_t *sc_gauss;
    void *gauss;
    struct _mw_gauss_combiner_t *gc;
    SINT32 z1;
    SINT32 z2;
    SINT32 is_base;
} SC_STRUCT_PACKED mw_gauss_combiner_t;
SC_STRUCT_PACK_END

/// A truct used to store the configuration of the M&W bootstrap
SC_STRUCT_PACK_START
typedef struct _mw_gaussian_bootstrap_t {
    const utils_sampling_t *sc_gauss;
    prng_ctx_t *sc_prng;
    mw_gauss_combiner_t **combiners;
    void *base_sampler;
    FLOAT *base_centre;
    size_t max_slevels;
    size_t k;
    size_t flips;
    size_t log_base;
    UINT64 mask;
    LONGDOUBLE wide_sigma2;
    LONGDOUBLE inv_wide_sigma2;
    LONGDOUBLE rr_sigma2;
} SC_STRUCT_PACKED mw_gaussian_bootstrap_t;
SC_STRUCT_PACK_END


/// Create a single level of a Gauss combiner, with the base sampler at the bottom
/// of the network of combiners
static mw_gauss_combiner_t * gauss_combiner_create(const utils_sampling_t *sc_gauss,
    void *sampler, SINT32 z1, SINT32 z2, SINT32 is_base)
{
    // Allocate memory resources for this combiner
    mw_gauss_combiner_t *combiner = SC_MALLOC(sizeof(mw_gauss_combiner_t));
    if (NULL == combiner) {
        return NULL;
    }

    // Set all of the configuration parameters associated with this combiner
    combiner->sc_gauss = sc_gauss;
    combiner->gauss    = (is_base)? sampler : NULL;
    combiner->gc       = (is_base)? NULL : (mw_gauss_combiner_t*) sampler;
    combiner->z1       = z1;
    combiner->z2       = z2;
    combiner->is_base  = is_base;

    // Return a pointer to an instance of a Gauss combiner
    return combiner;
}

/// Free all resources associated with a Gauss combiner
static SINT32 gauss_combiner_destroy(mw_gauss_combiner_t **combiner)
{
    // If the pointer is NULL return with an error
    if (NULL == combiner) {
        return SC_FUNC_FAILURE;
    }

    // Free the memory resources
    SC_FREE(*combiner, sizeof(mw_gauss_combiner_t));

    return SC_FUNC_SUCCESS;
}

// A recursive function used to create a sample from a base sampler
static SINT32 gauss_combiner_sample(mw_gauss_combiner_t *combiner)
{
    SINT32 x;
    if (combiner->is_base) {
        x = combiner->z1 * combiner->sc_gauss->sample(combiner->gauss) +
            combiner->z2 * combiner->sc_gauss->sample(combiner->gauss);
    }
    else {
        x = combiner->z1 * gauss_combiner_sample(combiner->gc) +
            combiner->z2 * gauss_combiner_sample(combiner->gc);
    }

    return x;
}


/// The create function associated with the M&W bootstrap Gaussian sampler
void * mw_bootstrap_create(const utils_sampling_t *sc_gauss, void *base_sampler, FLOAT base_sigma,
    size_t max_slevels, size_t log_base, size_t precision, size_t max_flips, FLOAT eta)
{
    size_t i;
    LONGDOUBLE t, s, base_sigma2;
    DOUBLE inv_two_eta_2 = 1.0 / (2.0 * eta * eta);
    mw_gaussian_bootstrap_t *sampler;

    sampler = SC_MALLOC(sizeof(mw_gaussian_bootstrap_t));
    if (NULL == sampler) {
        return NULL;
    }

    // Allocate memory for each of the wide noise samplers
    sampler->combiners = SC_MALLOC(sizeof(mw_gauss_combiner_t*) * (max_slevels - 1) + sizeof(FLOAT)*(1 << log_base));
    sampler->log_base = log_base;
    sampler->sc_gauss = sc_gauss;
    sampler->base_centre = (FLOAT*)(sampler->combiners + (max_slevels - 1));
    double step = 1.0/pow(2, log_base);
    for (i=0; i<1 << log_base; i++) {
        sampler->base_centre[i] = i * step;
    }

    // Build a recursive structure for the wide noise samplers
    void *gauss_sampler   = base_sampler;
    sampler->base_sampler = base_sampler;
    sampler->max_slevels  = max_slevels;
    sampler->sc_prng      = sc_gauss->get_prng(gauss_sampler);
    sampler->wide_sigma2  = (LONGDOUBLE) base_sigma * (LONGDOUBLE) base_sigma;
    base_sigma2           = sampler->wide_sigma2;
    for (i=0; i<max_slevels-1; i++) {
        SINT32 z1, z2;
        z1 = (SINT32) floor(sqrt(sampler->wide_sigma2 * inv_two_eta_2));
        z2 = SC_MAX(z1 - 1, 1);
        sampler->combiners[i] = gauss_combiner_create(sc_gauss, gauss_sampler, z1, z2, 0 == i);
        sampler->wide_sigma2  = (z1*z1 + z2*z2) * sampler->wide_sigma2;
        gauss_sampler         = sampler->combiners[i];
    }
    sampler->inv_wide_sigma2 = 1 / sampler->wide_sigma2;

    // Ensure that (precision - flips) is divisable by b by reducing the number of flips
    sampler->k     = (SINT32) ceil((DOUBLE)(precision - max_flips) / log_base);
    sampler->flips = precision - log_base * sampler->k;
    sampler->mask  = (1UL << log_base) - 1;

    sampler->rr_sigma2 = 1;
    t = 1.0 / (1UL << (2*log_base));
    s = 1.0;
    for (i=sampler->k-1; i--;) {
        s *= t;
        sampler->rr_sigma2 += s;
    }
    sampler->rr_sigma2 *= base_sigma2;

    return sampler;
}

SINT32 mw_bootstrap_destroy(void **sampler)
{
    size_t i;
    mw_gaussian_bootstrap_t *bootstrap;

    if (NULL == sampler) {
        return SC_FUNC_FAILURE;
    }
    bootstrap = (mw_gaussian_bootstrap_t *) *sampler;
    if (NULL == bootstrap) {
        return SC_FUNC_FAILURE;
    }

    for (i=0; i<bootstrap->max_slevels-1; i++) {
        gauss_combiner_destroy(&bootstrap->combiners[i]);
    }
    SC_FREE(bootstrap->combiners, sizeof(mw_gauss_combiner_t*) * (bootstrap->max_slevels - 1));
    SC_FREE(*sampler, sizeof(mw_gaussian_bootstrap_t));

    return SC_FUNC_SUCCESS;
}

// Round a sample generated at the base sigma and the specified center
static SINT32 mw_round(mw_gaussian_bootstrap_t *bootstrap, SINT64 center)
{
    size_t i, j;
    SINT32 sample;

    for (i=0; i<bootstrap->k; i++) {
        sample = bootstrap->base_centre[bootstrap->mask & center] +
                 bootstrap->sc_gauss->sample(bootstrap->base_sampler);
        if ((bootstrap->mask & center) > 0 && center < 0) {
            sample--;
        }
        for (j=0; j<bootstrap->log_base; j++) {
            center /= 2;
        }
        center += sample;
    }
    return center;
}

/// Round center up or down depending on biased coin flip
static SINT32 mw_flip_and_round(mw_gaussian_bootstrap_t *bootstrap, DOUBLE center)
{
    size_t i, j;
    size_t precision = bootstrap->flips + bootstrap->log_base * bootstrap->k;
    SINT64 c      = (SINT64) (center * (1UL << precision));
    SINT64 base_c = (c >> bootstrap->flips);
    SINT64 rbit;
    UINT64 rbits;
    
    for (i=bootstrap->flips-1, j=0; i>=0; i--, j++) {
        // Generate 64 random bits rather than sequentially generating
        // individual random bits
        if (0 == (j & 63)) {
            rbits = prng_64(bootstrap->sc_prng);
        }

        // Obtain a random bits and modify the random bit buffer
        rbit    = rbits & 0x1;
        rbits >>= 1;

        // If the indexed bit position of the scaled center indicates
        // the correct rounding position then round towards zero
        if (rbit > ((c >> i) & 1))
            return mw_round(bootstrap, base_c);
        if (rbit < ((c >> i) & 1))
            return mw_round(bootstrap, base_c + 1);
    }
    return mw_round(bootstrap, base_c + 1);
}

SINT32 mw_bootstrap_sample(void *sampler, DOUBLE sigma2, DOUBLE centre)
{
    DOUBLE x, c, ci;
    mw_gaussian_bootstrap_t *bootstrap = (mw_gaussian_bootstrap_t *) sampler;
    mw_gauss_combiner_t *gauss = bootstrap->combiners[bootstrap->max_slevels - 2];

    // Use the Gauss combiner network to obtain a sample
    x  = gauss_combiner_sample(gauss);

    // Modify the sample according to the center position
    c  = centre + x*(sqrt((sigma2 - bootstrap->rr_sigma2) * bootstrap->inv_wide_sigma2));
    ci = floor(c);
    c -= ci;
    
    // Return the centered sample (floored) added to the rounded
    // fractional difference
    return (SINT32)ci + mw_flip_and_round(bootstrap, c);
}
