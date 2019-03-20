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
#include "utils/arith/poly_limb.c"
#include "utils/arith/next_prime.h"
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
    #define NUM_ITER      (1 << 6)

    SC_TIMER_INSTANCE(mul_timer_0);
    SC_TIMER_CREATE(mul_timer_0);

    UINT64 i, j, k, l, m;

    sc_mod_t mod;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    double speed[4][8][9];
    for (m=0; m<4; m++) {
        char msg[32];
        if (0 == m) {
            sprintf(msg, "Gradeschool:   ");
        }
        else if (1 == m) {
            sprintf(msg, "Karatsuba:     ");
        }
        else if (2 == m) {
            sprintf(msg, "Kronecker:     ");
        }
        else {
            sprintf(msg, "Kronecker KS4: ");
        }
        
        for (j=0; j<8; j++) {
            for (l=0; l<9; l++) {
                SC_TIMER_RESET(mul_timer_0);
            
                const size_t n = 2048>>l;
                sc_ulimb_t out[2*n], a[n], b[n];
        
                SC_TIMER_START(mul_timer_0);
                SC_TIMER_STOP(mul_timer_0);
                for (k=0; k<NUM_ITER; k++) {
                    limb_mod_init(&mod, (SC_LIMB_WORD(1) << ((SC_LIMB_BITS - j*(SC_LIMB_BITS>>3))-1)) + 1);
        
                    for (i=0; i<n; i++) {
                        a[i] = prng_32(prng_ctx) % mod.m;
                        b[i] = prng_32(prng_ctx) % mod.m;
                    }
        
                    SC_TIMER_CONTINUE(mul_timer_0);
                    switch (m)
                    {
                        case 0:  poly_limb_mul_mod_gradeschool(out, a, n, b, n, &mod); break;
                        case 1:  poly_limb_mul_mod_karatsuba(out, a, n, b, n, &mod); break;
                        case 2:  poly_limb_mul_mod_kronecker(out, a, n, b, n, &mod); break;
                        default: poly_limb_mul_mod_kronecker_ks4(out, a, n, b, n, &mod); break;
                    }
                    SC_TIMER_STOP(mul_timer_0);
        
                    if ((k & ((NUM_ITER>>4)-1)) == (NUM_ITER>>4) - 1) show_progress(msg, (j*9+l)*NUM_ITER+k, 8*9*NUM_ITER);
                }
        
                speed[m][j][l] = SC_TIMER_GET_ELAPSED(mul_timer_0) / NUM_ITER;
                if (m > 0) {
                    speed[m][j][l] = (speed[0][j][l] > speed[m][j][l])?
                        speed[0][j][l] / speed[m][j][l] :
                        -speed[m][j][l] / speed[0][j][l];
                }
            }
        }

        show_progress(msg, 8*9*NUM_ITER, 8*9*NUM_ITER);

        for (j=0; j<8; j++) {
            printf("%d-bit modulus: ", (int)(SC_LIMB_BITS - j*(SC_LIMB_BITS>>3)));
            for (l=0; l<9; l++) {
                printf("%9.6f, ", speed[m][j][l]);
            }
            printf("\n");
        }
    }

    SC_TIMER_DESTROY(mul_timer_0);
    prng_destroy(prng_ctx);

    return EXIT_SUCCESS;
}

