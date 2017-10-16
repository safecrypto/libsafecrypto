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

#include "gaussian_bernoulli.h"
#include "safecrypto_private.h"
#include "safecrypto_types.h"
#include "utils/crypto/prng.h"

#include <math.h>
#include "utils/arith/sc_math.h"

SC_STRUCT_PACK_START
typedef struct _gauss_ber {
    UINT16  max_gauss_val;
    UINT16  max_gauss_log;
    FLOAT   sigma;
    UINT16  max_ber_entries;
    UINT16  max_ber_bytes;
    SINT32  bits;
    UINT8 **ber_table;
    SINT32  reject_counter;
    prng_ctx_t *prng_ctx;
} SC_STRUCT_PACKED gauss_ber_t;
SC_STRUCT_PACK_END

static UINT64 * generate_table_64(size_t max_val, FLOAT sigma)
{
    size_t i;

    UINT64 *table = SC_MALLOC(max_val * sizeof(UINT64));
    if (NULL == table) {
        return NULL;
    }

    for (i=0; i<max_val; i++) {
        DOUBLE temp = expf(-powf(2, i) / (2 * sigma * sigma));
        //fprintf(stderr, "temp = %3.6f, ", temp);
        table[i] = get_binary_expansion_fraction_64(temp);
        //fprintf(stderr, "res = %08X%08X\n", (UINT32)(table[i] >> 32), (UINT32)table[i]);
    }

    return table;
}

static SINT32 gen_ber_table_64(gauss_ber_t *gauss, FLOAT sigma, FLOAT tailcut, SINT32 precision)
{
    size_t i, j;

    FLOAT max_gauss_val = ceil(tailcut * sigma);
    gauss->max_gauss_val = (SINT32) max_gauss_val;
    gauss->max_gauss_log = (SINT32) ceil(log2f(max_gauss_val));
    gauss->sigma         = sigma;

    // Generate a table to be decomposed
    size_t max_val = ceil(log2f(tailcut * tailcut * sigma * sigma));
    UINT64 *table = generate_table_64(max_val, sigma);

    gauss->max_ber_entries = max_val;
    gauss->max_ber_bytes   = 8;//(precision+7) >> 3;

    // Allocate memory for the LUT
    gauss->ber_table = SC_MALLOC(gauss->max_ber_entries * sizeof(UINT8 *));
    if (NULL == gauss->ber_table) {
        SC_FREE(table, max_val * sizeof(UINT64));
        return SC_FUNC_FAILURE;
    }
    UINT8 *heap =  SC_MALLOC(sizeof(UINT8) * gauss->max_ber_entries * gauss->max_ber_bytes);
    if (NULL == heap) {
        SC_FREE(table, max_val * sizeof(UINT64));
        SC_FREE(gauss->ber_table, gauss->max_ber_entries * sizeof(UINT8 *));
        return SC_FUNC_FAILURE;
    }
    for (i=0; i<gauss->max_ber_entries; i++) {
        gauss->ber_table[i] = heap;
        heap += gauss->max_ber_bytes;
    }

    // Generate the LUT to be used by the sampler at runtime
    for (i=0; i<gauss->max_ber_entries; i++) {
        for (j=0; j<gauss->max_ber_bytes; j++) {
            gauss->ber_table[i][j] = table[i] >> (56 - 8*j);
        }
    }

    SC_FREE(table, max_val * sizeof(UINT64));

    return SC_FUNC_SUCCESS;
}

void * bernoulli_create_64(prng_ctx_t *prng_ctx, FLOAT tail, float sigma, size_t dummy, sample_blinding_e blinding)
{
    (void) dummy;

    // Allocate memory for the structure to be passed as a void *
    gauss_ber_t *gauss = SC_MALLOC(sizeof(gauss_ber_t));
    if (NULL == gauss) {
        return NULL;
    }

    gauss->prng_ctx = prng_ctx;

    gauss->bits = ceil(log2(tail * sigma));
    gauss->reject_counter = 0;
    if (SC_FUNC_FAILURE == gen_ber_table_64(gauss, sigma, tail, 64)) {
        SC_FREE(gauss, sizeof(gauss_ber_t));
        return NULL;
    }

    // If blinding is enabled the sigma variable must be scaled
    if (BLINDING_SAMPLES == blinding) {
        sigma *= 0.7071067811865475244008443621L;
    }

    return gauss;
}

SINT32 bernoulli_destroy_64(void **sampler)
{
    if (NULL == sampler) {
        return SC_FUNC_FAILURE;
    }

    // Obtain a pointer to the Ziggurat Gaussian Sampler, return failure if
    // the pointer is NULL
    gauss_ber_t *gauss = (gauss_ber_t *) *sampler;
    if (NULL == gauss) {
        return SC_FUNC_FAILURE;
    }

    // Free the memory resources
    SC_FREE(gauss->ber_table[0], gauss->max_ber_entries * gauss->max_ber_bytes * sizeof(UINT8));
    SC_FREE(gauss->ber_table, gauss->max_ber_entries * sizeof(UINT8 *));
    SC_FREE(*sampler, sizeof(gauss_ber_t));

    return SC_FUNC_SUCCESS;
}

prng_ctx_t * bernoulli_get_prng(void *sampler)
{
    gauss_ber_t *gauss = (gauss_ber_t *) sampler;
    if (NULL == gauss) {
        return NULL;
    }
    return gauss->prng_ctx;
}

static SINT32 sample_rejection_independent_time(gauss_ber_t *gauss) {
    //Bernoulli rejection sampling which can be made independent time- 
    //Reads out the whole table in case of a sucessfull sampling
    //Rejections if stuff does not work
    UINT32 val =0, x;
    UINT32 j, accept_mask;
    SINT32 i;
    UINT8  r,reject;
    UINT16 smaller;
    UINT16 larger;
    prng_ctx_t *prng_ctx = gauss->prng_ctx;


    //Use break an continue to escape from this loop
    while(1) {

        i = 0;

        //sample a candidate
        /*while (val < gauss->max_gauss_val) {
            val |= ((UINT32)prng_8())<<(8*i);
            i++;
        }*/
        val = prng_var(prng_ctx, gauss->max_gauss_log);

        //mask the candidate and reject when necessary
        //val = val & ((1<<gauss->max_gauss_log)-1);
        if (val >= gauss->max_gauss_val){
            continue;
        }

        //Check the table if we can accept this value
        //In case of a rejection we just abort
        //Otherwise the whole table has to be checked
        accept_mask = 0;
        reject = 0;
        x = val * val; //Have to evaluate exp(x^2/f). Keep val for later use (in case of success).
        for(j=0; j<gauss->max_ber_bytes; j++) {
            //From zero to one would be naive - we want to weed out the large values quickly, thus
            //we operate from max downto 0. Thus we can reject very early
            for(i=gauss->max_ber_entries; i--;) {
                //Sample a uniform byte

                r = prng_8(prng_ctx);

                //We check wether the random value is smaller than the one in the table
                smaller = 0;
                larger = 0;
                if (r < gauss->ber_table[i][j]) {
                  smaller = 1;
                }
                if (r > gauss->ber_table[i][j]) {
                  larger = 1;
                }

                //If the random value r is (a) smaller and (b) we havent accepted it so far,
                //then we mark the index as accepted
                if ((smaller == 1) && (((accept_mask >> i)&1) == 0)) {
                  accept_mask |= (1<<i);
                }

                //When the sampled value is larger, we check
                //a) is the bit set in x. If not we do not care and do no need to reject
                //b) has the index already been accepted? If yes the larger value does not matter
                //   as the comparision has already been evaluated
                if ((larger == 1) && (((x >> i)&1)==1) && ((accept_mask >> i)&1) == 0 ) {
                  //Break from the loop and restart again
                  reject = 1;
                  gauss->reject_counter++;
                  break;
                }
            }
            if (reject == 1) {
                break;
            }
        }

        if (reject == 0){
          //loop is finished - no reject
          //break the loop and output the value
          break;
        }
    }

    return val;
}

SINT32 bernoulli_sample_64(void *sampler)
{
    SINT32 val;
    UINT32 rnd;

    gauss_ber_t *gauss = (gauss_ber_t *) sampler;
    prng_ctx_t *prng_ctx = gauss->prng_ctx;

    while (1) {
        // Obtain a sample from positive half of Gaussian
        val = sample_rejection_independent_time(gauss);
        rnd = prng_var(prng_ctx, 2);

        // Check for a zero value and reject half of them
        if (val == 0) {
            if (rnd < 2) {//((rnd>>1) &1) == 0) {
                // Restart sampling procedure
                continue;
            }
            else {
                return val;
            }
        }

        // Sample a sign
        if (rnd & 1) {
            return -val;
        }
        else {
            return val;
        }
    }
}
