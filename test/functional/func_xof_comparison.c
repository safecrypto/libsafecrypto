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

#include <stdlib.h>
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/crypto/xof.h"
#include "utils/crypto/prng.h"

#include <string.h>


#define MAX_ITER    16384


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

#define NUM_XOF_FUNCTIONS    2


int main(void)
{
    int i, j, k;
    UINT8 message[8192];
    UINT8 md[8192];

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SC_TIMER_INSTANCE(xof_timer);
    SC_TIMER_CREATE(xof_timer);

    size_t length = 128;
    for (i=0; i<4; i++) {
        double elapsed[NUM_XOF_FUNCTIONS];
        printf("Message length: %6d bytes\n", (int)length);

        for (j=0; j<NUM_XOF_FUNCTIONS; j++) {
            char disp_msg[128];
            snprintf(disp_msg, 128, "%-20s", crypto_xof_names[j]);
            
            utils_crypto_xof_t *xof;
            switch (j) {
                case 0:  xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128); break;
                case 1:  xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE256); break;
            }

            SC_TIMER_RESET(xof_timer);

            for (k=0; k<MAX_ITER; k++) {
    
                // Generate a random message
                prng_mem(prng_ctx, message, length);
    
                SC_TIMER_START(xof_timer);
                xof_init(xof);
                xof_absorb(xof, message, length);
                xof_final(xof);
                xof_squeeze(xof, md, 64);
                SC_TIMER_STOP(xof_timer);
    
                if ((k & 0x1F) == 0x1F) show_progress(disp_msg, k, MAX_ITER);
            }

            show_progress(disp_msg, MAX_ITER, MAX_ITER);

            utils_crypto_xof_destroy(xof);

            elapsed[j] = SC_TIMER_GET_ELAPSED(xof_timer);
        }

        for (j=0; j<NUM_XOF_FUNCTIONS; j++) {
            printf("%-20s elapsed time: %f (%f bytes per sec)\n",
                crypto_xof_names[j], elapsed[j], (double)length * (double)MAX_ITER / elapsed[j]);
        }
        printf("\n");

        length <<= 2;
    }

    length = 128;
    for (i=0; i<4; i++) {
        double elapsed[NUM_XOF_FUNCTIONS];
        printf("Output length: %6d bytes\n", (int)length);

        for (j=0; j<NUM_XOF_FUNCTIONS; j++) {
            char disp_msg[128];
            snprintf(disp_msg, 128, "%-20s", crypto_xof_names[j]);
            
            utils_crypto_xof_t *xof;
            switch (j) {
                case 0:  xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE128); break;
                case 1:  xof = utils_crypto_xof_create(CRYPTO_XOF_SHAKE256); break;
            }

            SC_TIMER_RESET(xof_timer);

            for (k=0; k<MAX_ITER; k++) {
    
                // Generate a random message
                prng_mem(prng_ctx, message, length);
    
                SC_TIMER_START(xof_timer);
                xof_init(xof);
                xof_absorb(xof, message, 128);
                xof_final(xof);
                xof_squeeze(xof, md, length);
                SC_TIMER_STOP(xof_timer);
    
                if ((k & 0x1F) == 0x1F) show_progress(disp_msg, k, MAX_ITER);
            }

            show_progress(disp_msg, MAX_ITER, MAX_ITER);

            utils_crypto_xof_destroy(xof);

            elapsed[j] = SC_TIMER_GET_ELAPSED(xof_timer);
        }

        for (j=0; j<NUM_XOF_FUNCTIONS; j++) {
            printf("%-20s elapsed time: %f (%f bytes per sec)\n",
                crypto_xof_names[j], elapsed[j], (double)length * (double)MAX_ITER / elapsed[j]);
        }
        printf("\n");

        length <<= 2;
    }

    prng_destroy(prng_ctx);
    SC_TIMER_DESTROY(xof_timer);

    return EXIT_SUCCESS;
}

