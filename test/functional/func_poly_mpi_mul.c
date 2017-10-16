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
#include "utils/arith/sc_poly_mpz.c"
#include "utils/crypto/prng.h"

#include <string.h>
#include <math.h>


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
    printf("] %4d / %4d (%3d %%)\r", count, max, (int)(progress * 100.0f));
    if (count == max) printf("\n");
    fflush(stdout);
}

int main(void)
{
    #define NUM_ITER      (1 << 4)

    SC_TIMER_INSTANCE(mul_timer_0);
    SC_TIMER_CREATE(mul_timer_0);

    UINT64 i, j, k, l, m;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    for (m=0; m<3; m++) {
        char msg[32];
        if (0 == m) {
            sprintf(msg, "Gradeschool:");
        }
        else if (1 == m) {
            sprintf(msg, "Karatsuba:  ");
        }
        else {
            sprintf(msg, "Kronecker:  ");
        }
        
        double speed[5][9];
        for (j=0; j<4; j++) {
            for (l=0; l<9; l++) {
                SC_TIMER_RESET(mul_timer_0);
            
                const size_t n = 2048>>l;
                sc_ulimb_t temp;
                sc_poly_mpz_t out, a, b;
                sc_poly_mpz_init(&out, 2*n);
                sc_poly_mpz_init(&a, n);
                sc_poly_mpz_init(&b, n);
        
                SC_TIMER_START(mul_timer_0);
                SC_TIMER_STOP(mul_timer_0);
                for (k=0; k<NUM_ITER; k++) {
                    for (i=0; i<n; i++) {
                        temp = prng_32(prng_ctx);
                        sc_poly_mpz_set_ui(&a, i, temp);
                        temp = prng_32(prng_ctx);
                        sc_poly_mpz_set_ui(&b, i, temp);
                    }
        
                    SC_TIMER_CONTINUE(mul_timer_0);
                    switch (m)
                    {
                        case 0:  sc_poly_mpz_mul_gradeschool(&out, &a, &b); break;
                        case 1:  sc_poly_mpz_mul_karatsuba(&out, &a, &b); break;
                        default: sc_poly_mpz_mul_kronecker(&out, &a, &b); break;
                    }
                    SC_TIMER_STOP(mul_timer_0);
        
                    if ((k & ((NUM_ITER>>3)-1)) == (NUM_ITER>>3) - 1) show_progress(msg, (j*9+l)*NUM_ITER+k, 4*9*NUM_ITER);
                }
        
                speed[j][l] = SC_TIMER_GET_ELAPSED(mul_timer_0);

                sc_poly_mpz_clear(&out);
                sc_poly_mpz_clear(&a);
                sc_poly_mpz_clear(&b);
            }
        }

        show_progress(msg, 4*9*NUM_ITER, 4*9*NUM_ITER);

        for (j=0; j<5; j++) {
            for (l=0; l<9; l++) {
                printf("%9.2f, ", speed[j][l]);
            }
            printf("\n");
        }
    }

    SC_TIMER_DESTROY(mul_timer_0);
    prng_destroy(prng_ctx);

    return EXIT_SUCCESS;
}

