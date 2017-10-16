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
#include "safecrypto_debug.h"
#include "safecrypto_private.h"
#include "utils/sampling/sampling.h"
#include "utils/crypto/prng.h"

#include <string.h>


#define MAX_ITER    1048576

static const UINT8 nonce[16] = "SAFEcrypto nonce";

void show_progress(char *msg, int32_t count, int32_t max)
{
    int i;
    int barWidth = 50;
    double progress = (double) count / max;

    printf("%-20s [", msg);
    int pos = barWidth * progress;
    for (i = 0; i < barWidth; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %4d/%4d (%3d %%)\r", count, max, (int)(progress * 100.0f));
    if (count == max) printf("\n");
    fflush(stdout);
}

#define NUM_SAMPLERS    6


int main(void)
{
    int i, j, k;

    for (i=0; i<2; i++) {
        float sigma = (0 == i)? 4.5f : (1 == i)? 215.0f : 19600.0f;
        /*float sigma = (0 == i)? 4 :
                      (1 == i)? 8 :
                      (2 == i)? 16 :
                      (3 == i)? 32 :
                      (4 == i)? 64 :
                      (5 == i)? 128 :
                      (6 == i)? 256 :
                      (7 == i)? 512 :
                      (8 == i)? 1024 :
                      (9 == i)? 2048 :
                      (10 == i)? 4096 :
                      (11 == i)? 8192 :
                      (12 == i)? 16384 :
                                 32768;*/
        fprintf(stderr, "\nSigma = %f\n", sigma);

        SC_TIMER_INSTANCE(sampler_timer);
        SC_TIMER_CREATE(sampler_timer);
    
#if 0
        UINT32 *dist[NUM_SAMPLERS];
        for (j=0; j<NUM_SAMPLERS; j++) {
            dist[j] = SC_MALLOC(sizeof(UINT32) * 4096 * 2);
        }
#endif
    
        size_t out_bytes[NUM_SAMPLERS];
        double elapsed[NUM_SAMPLERS];
        for (j=0; j<NUM_SAMPLERS; j++) {
            char disp_msg[128];
            snprintf(disp_msg, 128, "%-32s", sc_sampler_names[j]);
    
            prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_DEV_URANDOM,
                SC_PRNG_AES_CTR_DRBG,
                SC_PRNG_THREADING_NONE, 0x00100000);
            prng_init(prng_ctx, nonce, 16);
    
            const utils_sampling_t *sampler;
            random_sampling_e sampler_type;
            switch (j) {
#ifdef HAVE_CDF_GAUSSIAN_SAMPLING
                case 0: sampler_type = CDF_GAUSSIAN_SAMPLING; break;
#else
                case 0: elapsed[j] = elapsed[j-1]; continue;
#endif
#ifdef HAVE_KNUTH_YAO_GAUSSIAN_SAMPLING
                case 1: sampler_type = KNUTH_YAO_GAUSSIAN_SAMPLING; break;
#else
                case 1: elapsed[j] = elapsed[j-1]; continue;
#endif
#ifdef HAVE_BAC_GAUSSIAN_SAMPLING
                case 2: sampler_type = BAC_GAUSSIAN_SAMPLING; break;
#else
                case 2: elapsed[j] = elapsed[j-1]; continue;
#endif
#ifdef HAVE_HUFFMAN_GAUSSIAN_SAMPLING
                case 3: sampler_type = HUFFMAN_GAUSSIAN_SAMPLING; break;
#else
                case 3: elapsed[j] = elapsed[j-1]; continue;
#endif
#ifdef HAVE_ZIGGURAT_GAUSSIAN_SAMPLING
                case 4: sampler_type = ZIGGURAT_GAUSSIAN_SAMPLING; break;
#else
                case 4: elapsed[j] = elapsed[j-1]; continue;
#endif
#ifdef HAVE_BERNOULLI_GAUSSIAN_SAMPLING
                case 5: sampler_type = BERNOULLI_GAUSSIAN_SAMPLING; break;
#else
                case 5: elapsed[j] = elapsed[j-1]; continue;
#endif
            }

            sampler = create_sampler(sampler_type, SAMPLING_64BIT, NORMAL_SAMPLES, 256,
                SAMPLING_DISABLE_BOOTSTRAP, prng_ctx, 13, 16.0f);
    
            void *gauss = sampler->create(prng_ctx, 13, sigma, 1024, NORMAL_SAMPLES);
            if (NULL == gauss) {
                fprintf(stderr, "ERROR! Could not create sampler for %s\n", sc_sampler_names[j]);
                prng_destroy(prng_ctx);
                return EXIT_FAILURE;
            }
    
            SC_TIMER_START(sampler_timer);
            for (k=0; k<MAX_ITER; k++) {
    
                SINT32 sample = sampler->sample(gauss);
                sample += 4096;
#if 0
                dist[j][sample]++;
#endif
    
                if ((k & 0x1FF) == 0x1FF) {
                    SC_TIMER_STOP(sampler_timer);
                    show_progress(disp_msg, k, MAX_ITER);
                    SC_TIMER_START(sampler_timer);
                }
            }
            SC_TIMER_STOP(sampler_timer);
    
            show_progress(disp_msg, MAX_ITER, MAX_ITER);
    
            sampler->destroy(&gauss);
            elapsed[j] = SC_TIMER_GET_ELAPSED(sampler_timer);
            out_bytes[j] = prng_get_out_bytes(prng_ctx);
    
            prng_destroy(prng_ctx);
        }
    
        double acc = elapsed[0];
        for (j=1; j<NUM_SAMPLERS; j++) {
            elapsed[j] -= acc;
            acc += elapsed[j];
        }
    
        for (j=0; j<NUM_SAMPLERS; j++) {
            printf("%-32s elapsed time: %f, random bytes = %zu\n",
                sc_sampler_names[j], elapsed[j], out_bytes[j]);
        }
    
        printf("\n");
    
#if 0
        FILE *fp = fopen("gaussian_dist.dat", "w");
        if (fp) {
            for (k=0; k<NUM_SAMPLERS; k++) {
                for (j=0; j<4096*2; j++) {
                    fprintf(fp, "%5d ", dist[k][j]);
                    if ((j&15)==15) fprintf(fp, "\n");
                }
                fprintf(fp, "\n");
            }
    
            fclose(fp);
        }
    
        for (j=0; j<NUM_SAMPLERS; j++) {
            SC_FREE(dist[j], sizeof(UINT32) * 4096 * 2);
        }
#endif
    
        SC_TIMER_DESTROY(sampler_timer);
    }

    return EXIT_SUCCESS;
}

