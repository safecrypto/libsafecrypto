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
    #define NUM_ITER      (1 << 12)

    SC_TIMER_INSTANCE(mul_timer_0);
    SC_TIMER_CREATE(mul_timer_0);

    UINT64 i, j, k, l, m;

    sc_mod_t mod;

    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    double speed[3][4][9];

    /*printf("deg(a) == deg(b) + 1\n");
    for (m=0; m<3; m++) {
        char msg[32];
        if (0 == m) {
            sprintf(msg, "normal:             ");
        }
        else if (1 == m) {
            sprintf(msg, "divrem+1:           ");
        }
        else {
            sprintf(msg, "divide-and-conquer: ");
        }
        
        for (j=0; j<4; j++) {
            for (l=0; l<9; l++) {
                SC_TIMER_RESET(mul_timer_0);
            
                const size_t n = 4096>>l;
                size_t len_q, len_r;
                sc_ulimb_t q[2*n], r[2*n], a[n], b[n];

                SC_TIMER_START(mul_timer_0);
                SC_TIMER_STOP(mul_timer_0);
                for (k=0; k<NUM_ITER; k++) {
                    mod.m     = next_prime(SC_LIMB_WORD(1) << ((SC_LIMB_BITS >> j*8)-1));
                    mod.m_inv = limb_inverse(mod.m);
                    mod.norm  = limb_clz(mod.m);
        
                    SINT32 depth = poly_limb_divrem_mod_limbcount(n, n-1, mod.norm);
                    sc_ulimb_t *w = SC_MALLOC(depth * sizeof(sc_ulimb_t));

                    for (i=0; i<n-1; i++) {
                        a[i] = prng_32(prng_ctx) % mod.m;
                        b[i] = prng_32(prng_ctx) % mod.m;
                    }
                    a[n-1] = prng_32(prng_ctx) % mod.m;
                    b[n-1] = 0;
        
                    SC_TIMER_CONTINUE(mul_timer_0);
                    switch (m)
                    {
                        case 0:  poly_limb_divrem_mod_normal(q, &len_q, r, &len_r, w, a, n, b, n-1, &mod); break;
                        case 1:  poly_limb_divrem_mod_diff_1(q, &len_q, r, &len_r, a, n, b, n-1, &mod); break;
                        default: poly_limb_divrem_divconquer(q, &len_q, r, &len_r, a, n, b, n-1, &mod); break;
                    }
                    SC_TIMER_STOP(mul_timer_0);

                    SC_FREE(w, depth * sizeof(sc_ulimb_t));
        
                    if ((k & ((NUM_ITER>>7)-1)) == (NUM_ITER>>7) - 1) show_progress(msg, (j*9+l)*NUM_ITER+k, 4*9*NUM_ITER);
                }

                speed[m][j][l] = SC_TIMER_GET_ELAPSED(mul_timer_0) / NUM_ITER;
                if (m > 0) {
                    speed[m][j][l] = (speed[0][j][l] > speed[m][j][l])?
                        speed[0][j][l] / speed[m][j][l] :
                        -speed[m][j][l] / speed[0][j][l];
                }
            }
        }

        show_progress(msg, 4*9*NUM_ITER, 4*9*NUM_ITER);

        if (m > 0) {
            for (j=0; j<4; j++) {
                for (l=0; l<9; l++) {
                    printf("%9.6f, ", speed[m][j][l]);
                }
                printf("\n");
            }
        }
    }

    printf("deg(a) == deg(b)\n");
    for (m=0; m<3; m++) {
        char msg[32];
        if (0 == m) {
            sprintf(msg, "normal:             ");
        }
        else if (1 == m) {
            sprintf(msg, "divrem+0:           ");
        }
        else {
            sprintf(msg, "divide-and-conquer: ");
        }
        
        for (j=0; j<4; j++) {
            for (l=0; l<9; l++) {
                SC_TIMER_RESET(mul_timer_0);
            
                const size_t n = 4096>>l;
                size_t len_q, len_r;
                sc_ulimb_t q[2*n], r[2*n], a[n], b[n];

                SC_TIMER_START(mul_timer_0);
                SC_TIMER_STOP(mul_timer_0);
                for (k=0; k<NUM_ITER; k++) {
                    mod.m     = next_prime(SC_LIMB_WORD(1) << ((SC_LIMB_BITS >> j*8)-1));
                    mod.m_inv = limb_inverse(mod.m);
                    mod.norm  = limb_clz(mod.m);
        
                    SINT32 depth = poly_limb_divrem_mod_limbcount(n, n, mod.norm);
                    sc_ulimb_t *w = SC_MALLOC(depth * sizeof(sc_ulimb_t));

                    for (i=0; i<n; i++) {
                        a[i] = prng_32(prng_ctx) % mod.m;
                        b[i] = prng_32(prng_ctx) % mod.m;
                    }
        
                    SC_TIMER_CONTINUE(mul_timer_0);
                    switch (m)
                    {
                        case 0:  poly_limb_divrem_mod_normal(q, &len_q, r, &len_r, w, a, n, b, n, &mod); break;
                        case 1:  poly_limb_divrem_mod_diff_0(q, &len_q, r, &len_r, a, n, b, &mod); break;
                        default: poly_limb_divrem_divconquer(q, &len_q, r, &len_r, a, n, b, n, &mod); break;
                    }
                    SC_TIMER_STOP(mul_timer_0);

                    SC_FREE(w, depth * sizeof(sc_ulimb_t));
        
                    if ((k & ((NUM_ITER>>7)-1)) == (NUM_ITER>>7) - 1) show_progress(msg, (j*9+l)*NUM_ITER+k, 4*9*NUM_ITER);
                }

                speed[m][j][l] = SC_TIMER_GET_ELAPSED(mul_timer_0) / NUM_ITER;
                if (m > 0) {
                    speed[m][j][l] = (speed[0][j][l] > speed[m][j][l])?
                        speed[0][j][l] / speed[m][j][l] :
                        -speed[m][j][l] / speed[0][j][l];
                }
            }
        }

        show_progress(msg, 4*9*NUM_ITER, 4*9*NUM_ITER);

        if (m > 0) {
            for (j=0; j<4; j++) {
                for (l=0; l<9; l++) {
                    printf("%9.6f, ", speed[m][j][l]);
                }
                printf("\n");
            }
        }
    }*/

    printf("deg(b) == deg(b) + 16\n");
    for (m=0; m<2; m++) {
        char msg[32];
        if (0 == m) {
            sprintf(msg, "normal:             ");
        }
        else {
            sprintf(msg, "divide-and-conquer: ");
        }
        
        for (j=0; j<4; j++) {
            for (l=0; l<9; l++) {
                SC_TIMER_RESET(mul_timer_0);
            
                const size_t n = 4096>>l;
                if (n <= 4) continue;

                size_t len_q, len_r;
                sc_ulimb_t q[2*n], r[2*n], a[n], b[n];

                SC_TIMER_START(mul_timer_0);
                SC_TIMER_STOP(mul_timer_0);
                for (k=0; k<NUM_ITER; k++) {
                    mod.m     = next_prime(SC_LIMB_WORD(1) << ((SC_LIMB_BITS >> j*8)-1));
                    mod.m_inv = limb_inverse(mod.m);
                    mod.norm  = limb_clz(mod.m);
        
                    SINT32 depth = poly_limb_divrem_mod_limbcount(n, n-4, mod.norm);
                    sc_ulimb_t *w = SC_MALLOC(depth * sizeof(sc_ulimb_t));

                    for (i=0; i<n; i++) {
                        a[i] = prng_32(prng_ctx) % mod.m;
                        b[i] = prng_32(prng_ctx) % mod.m;
                    }
        
                    SC_TIMER_CONTINUE(mul_timer_0);
                    switch (m)
                    {
                        case 0:  poly_limb_divrem_mod_normal(q, &len_q, r, &len_r, w, a, n, b, n-4, &mod); break;
                        default: poly_limb_divrem_divconquer(q, &len_q, r, &len_r, a, n, b, n-4, &mod); break;
                    }
                    SC_TIMER_STOP(mul_timer_0);

                    SC_FREE(w, depth * sizeof(sc_ulimb_t));
        
                    if ((k & ((NUM_ITER>>7)-1)) == (NUM_ITER>>7) - 1) show_progress(msg, (j*9+l)*NUM_ITER+k, 4*9*NUM_ITER);
                }

                speed[m][j][l] = SC_TIMER_GET_ELAPSED(mul_timer_0) / NUM_ITER;
                if (m > 0) {
                    speed[m][j][l] = (speed[0][j][l] > speed[m][j][l])?
                        speed[0][j][l] / speed[m][j][l] :
                        -speed[m][j][l] / speed[0][j][l];
                }
            }
        }

        show_progress(msg, 4*9*NUM_ITER, 4*9*NUM_ITER);

        if (m > 0) {
            for (j=0; j<4; j++) {
                for (l=0; l<9; l++) {
                    printf("%9.6f, ", speed[m][j][l]);
                }
                printf("\n");
            }
        }
    }

    printf("deg(b) == 64\n");
    for (m=0; m<2; m++) {
        char msg[32];
        if (0 == m) {
            sprintf(msg, "normal:             ");
        }
        else {
            sprintf(msg, "divide-and-conquer: ");
        }
        
        for (j=0; j<4; j++) {
            for (l=0; l<9; l++) {
                SC_TIMER_RESET(mul_timer_0);
            
                const size_t n = 4096>>l;
                if (n < 64) continue;

                size_t len_q, len_r;
                sc_ulimb_t q[2*n], r[2*n], a[n], b[n];

                SC_TIMER_START(mul_timer_0);
                SC_TIMER_STOP(mul_timer_0);
                for (k=0; k<NUM_ITER; k++) {
                    mod.m     = next_prime(SC_LIMB_WORD(1) << ((SC_LIMB_BITS >> j*8)-1));
                    mod.m_inv = limb_inverse(mod.m);
                    mod.norm  = limb_clz(mod.m);
        
                    SINT32 depth = poly_limb_divrem_mod_limbcount(n, 64, mod.norm);
                    sc_ulimb_t *w = SC_MALLOC(depth * sizeof(sc_ulimb_t));

                    for (i=0; i<n; i++) {
                        a[i] = prng_32(prng_ctx) % mod.m;
                        b[i] = prng_32(prng_ctx) % mod.m;
                    }
        
                    SC_TIMER_CONTINUE(mul_timer_0);
                    switch (m)
                    {
                        case 0:  poly_limb_divrem_mod_normal(q, &len_q, r, &len_r, w, a, n, b, 64, &mod); break;
                        default: poly_limb_divrem_divconquer(q, &len_q, r, &len_r, a, n, b, 64, &mod); break;
                    }
                    SC_TIMER_STOP(mul_timer_0);

                    SC_FREE(w, depth * sizeof(sc_ulimb_t));
        
                    if ((k & ((NUM_ITER>>7)-1)) == (NUM_ITER>>7) - 1) show_progress(msg, (j*9+l)*NUM_ITER+k, 4*9*NUM_ITER);
                }

                speed[m][j][l] = SC_TIMER_GET_ELAPSED(mul_timer_0) / NUM_ITER;
                if (m > 0) {
                    speed[m][j][l] = (speed[0][j][l] > speed[m][j][l])?
                        speed[0][j][l] / speed[m][j][l] :
                        -speed[m][j][l] / speed[0][j][l];
                }
            }
        }

        show_progress(msg, 4*9*NUM_ITER, 4*9*NUM_ITER);

        if (m > 0) {
            for (j=0; j<4; j++) {
                for (l=0; l<9; l++) {
                    printf("%9.6f, ", speed[m][j][l]);
                }
                printf("\n");
            }
        }
    }

    printf("deg(b) == 128\n");
    for (m=0; m<2; m++) {
        char msg[32];
        if (0 == m) {
            sprintf(msg, "normal:             ");
        }
        else {
            sprintf(msg, "divide-and-conquer: ");
        }
        
        for (j=0; j<4; j++) {
            for (l=0; l<9; l++) {
                SC_TIMER_RESET(mul_timer_0);
            
                const size_t n = 4096>>l;
                if (n < 128) continue;

                size_t len_q, len_r;
                sc_ulimb_t q[2*n], r[2*n], a[n], b[n];

                SC_TIMER_START(mul_timer_0);
                SC_TIMER_STOP(mul_timer_0);
                for (k=0; k<NUM_ITER; k++) {
                    mod.m     = next_prime(SC_LIMB_WORD(1) << ((SC_LIMB_BITS >> j*8)-1));
                    mod.m_inv = limb_inverse(mod.m);
                    mod.norm  = limb_clz(mod.m);
        
                    SINT32 depth = poly_limb_divrem_mod_limbcount(n, 128, mod.norm);
                    sc_ulimb_t *w = SC_MALLOC(depth * sizeof(sc_ulimb_t));

                    for (i=0; i<n; i++) {
                        a[i] = prng_32(prng_ctx) % mod.m;
                        b[i] = prng_32(prng_ctx) % mod.m;
                    }
        
                    SC_TIMER_CONTINUE(mul_timer_0);
                    switch (m)
                    {
                        case 0:  poly_limb_divrem_mod_normal(q, &len_q, r, &len_r, w, a, n, b, 128, &mod); break;
                        default: poly_limb_divrem_divconquer(q, &len_q, r, &len_r, a, n, b, 128, &mod); break;
                    }
                    SC_TIMER_STOP(mul_timer_0);

                    SC_FREE(w, depth * sizeof(sc_ulimb_t));
        
                    if ((k & ((NUM_ITER>>7)-1)) == (NUM_ITER>>7) - 1) show_progress(msg, (j*9+l)*NUM_ITER+k, 4*9*NUM_ITER);
                }

                speed[m][j][l] = SC_TIMER_GET_ELAPSED(mul_timer_0) / NUM_ITER;
                if (m > 0) {
                    speed[m][j][l] = (speed[0][j][l] > speed[m][j][l])?
                        speed[0][j][l] / speed[m][j][l] :
                        -speed[m][j][l] / speed[0][j][l];
                }
            }
        }

        show_progress(msg, 4*9*NUM_ITER, 4*9*NUM_ITER);

        if (m > 0) {
            for (j=0; j<4; j++) {
                for (l=0; l<9; l++) {
                    printf("%9.6f, ", speed[m][j][l]);
                }
                printf("\n");
            }
        }
    }

    SC_TIMER_DESTROY(mul_timer_0);
    prng_destroy(prng_ctx);

    return EXIT_SUCCESS;
}

