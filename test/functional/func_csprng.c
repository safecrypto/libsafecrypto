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
#include "utils/crypto/prng.h"

#include <string.h>
#include <math.h>

#define NUM_BINS        16
#define NUM_BINS_SHIFT  4
#define NUM_ITER        128
#define NUM_SAMPLES     (1048576UL)

#ifdef CONSTRAINED_SYSTEM
#define NUM_CSPRNG      1
#else
#ifdef _ENABLE_CSPRNG_FILE
#define NUM_CSPRNG      14
#else
#define NUM_CSPRNG      13
#endif
#endif

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

double chi_square(UINT64 *O, UINT64 *E)
{
    size_t i;
    double cs = 0;
#if 0
    for (i=0; i<NUM_BINS; i++) {
        double diff = (double)O[i] - (double)E[i];
        cs += (diff * diff);// / (double)E[i];
    }
    cs /= (NUM_ITER * NUM_SAMPLES) / NUM_BINS;
#else
    for (i=0; i<NUM_BINS; i++) {
        double diff = (double)O[i] - (double)E[i];
        cs += (diff * diff) / (double)E[i];
    }
#endif
    return cs;
}

int main(void)
{
    SC_TIMER_INSTANCE(rnd_timer);
    SC_TIMER_CREATE(rnd_timer);

    UINT64 i, j, k;
    UINT8 *data = malloc(NUM_SAMPLES);

    UINT64 E[NUM_BINS];
    for (i=0; i<NUM_BINS; i++) {
        E[i] = (NUM_ITER * NUM_SAMPLES) / NUM_BINS;
    }

#ifdef _ENABLE_ENTROPY_ARRAY
    static const UINT8 null_entropy[128] = {0};
#endif

    for (j=0; j<NUM_CSPRNG; j++) {
        SINT32 failure[3] = {0};
        double mean_sd = (256 - 0) / sqrtf(12.0f);
        double var_mean = mean_sd * mean_sd;
        double var_var  = (2 * mean_sd * mean_sd * mean_sd * mean_sd) / (NUM_SAMPLES - 1.0f);
        double var_sd   = sqrtf(var_var);
        UINT64 O[NUM_BINS];
        for (i=0; i<NUM_BINS; i++) {
            O[i] = 0;
        }

        SC_TIMER_RESET(rnd_timer);

#ifdef _ENABLE_ENTROPY_ARRAY
        safecrypto_entropy_e source = SC_ENTROPY_ARRAY;
#else
        safecrypto_entropy_e source = SC_ENTROPY_RANDOM;
#endif

        UINT32 reseed_period = 0x001000000;
        prng_ctx_t *prng_ctx = NULL;
        char msg[32];
        switch (j) {
            case 0: prng_ctx = prng_create(source, SC_PRNG_AES_CTR_DRBG,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "AES-CTR-DRBG");
                prng_init(prng_ctx, NULL, 0);
                break;
            case 1: prng_ctx = prng_create(source, SC_PRNG_ISAAC,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "ISAAC");
                prng_init(prng_ctx, NULL, 0);
                break;
            case 2: prng_ctx = prng_create(source, SC_PRNG_CHACHA,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "CHACHA");
                prng_init(prng_ctx, NULL, 0);
                break;
            case 3: prng_ctx = prng_create(source, SC_PRNG_SALSA,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "SALSA");
                prng_init(prng_ctx, NULL, 0);
                break;
            case 4: prng_ctx = prng_create(source, SC_PRNG_KISS,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "KISS");
                prng_init(prng_ctx, NULL, 0);
                break;
            case 5: prng_ctx = prng_create(source, SC_PRNG_SYSTEM,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "SYSTEM");
                prng_init(prng_ctx, NULL, 0);
                break;
            case 6: prng_ctx = prng_create(source, SC_PRNG_HASH_DRBG_SHA2_256,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "HASH-DRBG-SHA-256");
                prng_init(prng_ctx, nonce, 8);
                break;
            case 7: prng_ctx = prng_create(source, SC_PRNG_HASH_DRBG_SHA2_512,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "HASH-DRBG-SHA-512");
                prng_init(prng_ctx, nonce, 16);
                break;
            case 8: prng_ctx = prng_create(source, SC_PRNG_HASH_DRBG_SHA3_256,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "HASH-DRBG-SHA3-256");
                prng_init(prng_ctx, nonce, 8);
                break;
            case 9: prng_ctx = prng_create(source, SC_PRNG_HASH_DRBG_SHA3_512,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "HASH-DRBG-SHA3-512");
                prng_init(prng_ctx, nonce, 16);
                break;
            case 10: prng_ctx = prng_create(source, SC_PRNG_HASH_DRBG_BLAKE2_256,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "HASH-DRBG-BLAKE2-256");
                prng_init(prng_ctx, nonce, 8);
                break;
            case 11: prng_ctx = prng_create(source, SC_PRNG_HASH_DRBG_BLAKE2_512,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "HASH-DRBG-BLAKE2-512");
                prng_init(prng_ctx, nonce, 16);
                break;
            case 12: prng_ctx = prng_create(source, SC_PRNG_HASH_DRBG_WHIRLPOOL_512,
                SC_PRNG_THREADING_NONE, reseed_period); strcpy(msg, "HASH-DRBG-WHIRLPOOL-512");
                prng_init(prng_ctx, nonce, 16);
                break;
#ifdef _ENABLE_CSPRNG_FILE
            case 13: prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_FILE,
                SC_PRNG_THREADING_NONE, reseed_period);   strcpy(msg, "FILE");
                break;
#endif
            default:;
        }

        if (NULL == prng_ctx) {
            SC_TIMER_DESTROY(rnd_timer);
            free(data);
            return EXIT_FAILURE;
        }

#ifdef _ENABLE_ENTROPY_ARRAY
        prng_set_entropy_array(null_entropy, sizeof(null_entropy));
#endif

        for (k=0; k<NUM_ITER; k++) {
            UINT64 sum = 0;
            double sum_var = 0;

            SC_TIMER_START(rnd_timer);
            prng_mem(prng_ctx, data, NUM_SAMPLES);
            SC_TIMER_STOP(rnd_timer);

            for (i=0; i<NUM_SAMPLES; i++) {
                sum += (UINT64)data[i];
                size_t val = data[i]>>NUM_BINS_SHIFT;
                O[val & (NUM_BINS-1)]++;
            }

            double mean = (double) sum / NUM_SAMPLES;

            for (i=0; i<NUM_SAMPLES; i++) {
                double diff = mean - (double)data[i];
                sum_var += diff * diff;
            }

            double var  = sum_var / NUM_SAMPLES;
            //printf("mean = %3.6f, var = %3.6f\n", mean, var);

            if (((mean < (127.5 - 2*mean_sd)) || (mean > (127.5 + 2*mean_sd)))) failure[0]++;
            if (((var < (var_mean - 2*var_sd)) || (var > (var_mean + 2*var_sd)))) failure[1]++;

            show_progress(msg, k, NUM_ITER);
        }

        show_progress(msg, NUM_ITER, NUM_ITER);

        double elapsed = SC_TIMER_GET_ELAPSED(rnd_timer);
        printf("CSPRNG time: %f (%3.3f Mbyte per sec)\n", elapsed, (double)NUM_ITER * (double)NUM_SAMPLES / (1048576UL * elapsed));

        printf("CSPRNG bytes: %lu\n", prng_get_csprng_bytes(prng_ctx));
        printf("Output bytes: %lu\n", prng_get_out_bytes(prng_ctx));
        printf("Expected bytes: %ld\n", NUM_ITER * NUM_SAMPLES);

        printf("mean SD = %3.6f, var SD = %3.6f, var mean = %3.6f\n",
            mean_sd, var_sd, var_mean);
        double cs = chi_square(O, E);
        double chi_mean = NUM_BINS;
        double chi_sd = sqrtf(NUM_BINS);
        printf("chi-square = %3.6f [mean=%3.6f, sd=%3.6f] [%3.6f to %3.6f]\n", cs, chi_mean, chi_sd,
            chi_mean - 2*chi_sd, chi_mean + 2*chi_sd);
        if (((cs < (chi_mean - 2*chi_sd)) || (cs > (chi_mean + 2*chi_sd)))) failure[2]++;

        printf("%s  [%d/%d, %d/%d, %d/%d]\n\n",
            (failure[0] >= (double)NUM_ITER*1.05 ||
             failure[1] >= (double)NUM_ITER*1.05 ||
             failure[2] > 0)? "FAILURE" : "SUCCESS",
            NUM_ITER - failure[0], NUM_ITER,
            NUM_ITER - failure[1], NUM_ITER,
            1 - failure[2], 1);

        prng_destroy(prng_ctx);
    }

    SC_TIMER_DESTROY(rnd_timer);
    free(data);

    return EXIT_SUCCESS;
}

