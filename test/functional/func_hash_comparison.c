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
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"

#include <string.h>


#define MAX_ITER    4096


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

#define NUM_HASH_FUNCIONS    13


int main(void)
{
    int i, j, k;
    UINT8 message[8192];
    UINT8 md[64];

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    SC_TIMER_INSTANCE(hash_timer);
    SC_TIMER_CREATE(hash_timer);

    size_t length = 128;
    for (i=0; i<4; i++) {
        double elapsed[NUM_HASH_FUNCIONS];
        printf("Message length: %6d bytes\n", (int)length);

        for (j=0; j<NUM_HASH_FUNCIONS; j++) {
            char disp_msg[128];
            snprintf(disp_msg, 128, "%-20s", crypto_hash_names[j]);
            
            utils_crypto_hash_t *hash;
            switch (j) {
                case 0:  hash = utils_crypto_hash_create(SC_HASH_SHA3_224); break;
                case 1:  hash = utils_crypto_hash_create(SC_HASH_SHA3_256); break;
                case 2:  hash = utils_crypto_hash_create(SC_HASH_SHA3_384); break;
                case 3:  hash = utils_crypto_hash_create(SC_HASH_SHA3_512); break;
                case 4:  hash = utils_crypto_hash_create(SC_HASH_SHA2_224); break;
                case 5:  hash = utils_crypto_hash_create(SC_HASH_SHA2_256); break;
                case 6:  hash = utils_crypto_hash_create(SC_HASH_SHA2_384); break;
                case 7:  hash = utils_crypto_hash_create(SC_HASH_SHA2_512); break;
                case 8:  hash = utils_crypto_hash_create(SC_HASH_BLAKE2_224); break;
                case 9:  hash = utils_crypto_hash_create(SC_HASH_BLAKE2_256); break;
                case 10: hash = utils_crypto_hash_create(SC_HASH_BLAKE2_384); break;
                case 11: hash = utils_crypto_hash_create(SC_HASH_BLAKE2_512); break;
                case 12: hash = utils_crypto_hash_create(SC_HASH_WHIRLPOOL_512); break;
            }

            SC_TIMER_RESET(hash_timer);

            for (k=0; k<MAX_ITER; k++) {
    
                // Generate a random message
                prng_mem(prng_ctx, message, length);
    
                SC_TIMER_START(hash_timer);
                hash_init(hash);
                hash_update(hash, message, length);
                hash_final(hash, md);
                SC_TIMER_STOP(hash_timer);
    
                if ((k & 0x1F) == 0x1F) show_progress(disp_msg, k, MAX_ITER);
            }

            show_progress(disp_msg, MAX_ITER, MAX_ITER);

            utils_crypto_hash_destroy(hash);

            elapsed[j] = SC_TIMER_GET_ELAPSED(hash_timer);
        }

        for (j=0; j<NUM_HASH_FUNCIONS; j++) {
            printf("%-20s elapsed time: %f (%f bytes per sec)\n",
                crypto_hash_names[j], elapsed[j], (double)length * (double)MAX_ITER / elapsed[j]);
        }
        printf("\n");

        length <<= 2;
    }

    prng_destroy(prng_ctx);
    SC_TIMER_DESTROY(hash_timer);

    return EXIT_SUCCESS;
}

