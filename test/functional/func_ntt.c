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
#include "utils/arith/ntt.h"

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
    printf("] %4d//%4d (%3d %%)\r", count, max, (int)(progress * 100.0f));
    if (count == max) printf("\n");
    fflush(stdout);
}

typedef SINT32 (*modn)(SINT32, const ntt_params_t *);
typedef SINT32 (*muln)(SINT32, SINT32, const ntt_params_t *);
typedef SINT32 (*sqrn)(SINT32, const ntt_params_t *);

int main(void)
{
    #define NUM_ITER      0x40000000

    modn modnut;
    muln mulnut;
    sqrn sqrnut;

    ntt_params_t ntt;
    ntt.n = 512;
    ntt.u.ntt32.q = 12289;
    ntt.u.ntt32.m = 87374;
    ntt.u.ntt32.k = 30;
    ntt.q_dbl = ntt.u.ntt32.q;
    ntt.inv_q_dbl = 1.0f / ntt.q_dbl;

    SC_TIMER_INSTANCE(rnd_timer);
    SC_TIMER_CREATE(rnd_timer);

    UINT64 j, k;

    for (j=0; j<3; j++) {
        SC_TIMER_RESET(rnd_timer);

        char msg[32];
        switch (j) {
            case 0:  modnut = ntt32_modn_reference; strcpy(msg, "Reference"); break;
            case 1:  modnut = ntt32_modn_barrett;   strcpy(msg, "Barrett");   break;
            default: modnut = ntt32_modn_fp;        strcpy(msg, "Floating Point");
        }

        SINT32 ivalue = 0;
        SINT32 ovalue = 0;
        SC_TIMER_START(rnd_timer);
        for (k=0; k<NUM_ITER; k++) {
            SINT32 result = modnut(ivalue, &ntt);
            if (result != ovalue) {
                SC_TIMER_DESTROY(rnd_timer);
                return EXIT_FAILURE;
            }

            ivalue++;
            ovalue++;
            if (ntt.u.ntt32.q == ovalue) {
                ovalue = 0;
            }
    
            if ((k & 0x1FFFFF) == 0x1FFFFF) show_progress(msg, k, NUM_ITER);
        }
        SC_TIMER_STOP(rnd_timer);

        show_progress(msg, NUM_ITER, NUM_ITER);

        double elapsed = SC_TIMER_GET_ELAPSED(rnd_timer);
        printf("modn time: %f\n\n", elapsed);
    }

    for (j=0; j<3; j++) {
        SC_TIMER_RESET(rnd_timer);

        char msg[32];
        switch (j) {
            case 0:  mulnut = ntt32_muln_reference; strcpy(msg, "Reference"); break;
            case 1:  mulnut = ntt32_muln_barrett;   strcpy(msg, "Barrett");   break;
            default: mulnut = ntt32_muln_fp;        strcpy(msg, "Floating Point");
        }

        SINT32 ivalue = 0;
        SINT32 jvalue = 0x80000000;
        SC_TIMER_START(rnd_timer);
        for (k=0; k<NUM_ITER; k++) {
            (void)mulnut(ivalue, jvalue, &ntt);

            ivalue++;
            jvalue--;
    
            if ((k & 0x1FFFFF) == 0x1FFFFF) show_progress(msg, k, NUM_ITER);
        }
        SC_TIMER_STOP(rnd_timer);

        show_progress(msg, NUM_ITER, NUM_ITER);

        double elapsed = SC_TIMER_GET_ELAPSED(rnd_timer);
        printf("muln time: %f\n\n", elapsed);
    }

    for (j=0; j<3; j++) {
        SC_TIMER_RESET(rnd_timer);

        char msg[32];
        switch (j) {
            case 0:  sqrnut = ntt32_sqrn_reference; strcpy(msg, "Reference"); break;
            case 1:  sqrnut = ntt32_sqrn_barrett;   strcpy(msg, "Barrett");   break;
            default: sqrnut = ntt32_sqrn_fp;        strcpy(msg, "Floating Point");
        }

        SINT32 ivalue = 0;
        SC_TIMER_START(rnd_timer);
        for (k=0; k<NUM_ITER; k++) {
            (void)sqrnut(ivalue, &ntt);

            ivalue++;
    
            if ((k & 0x1FFFFF) == 0x1FFFFF) show_progress(msg, k, NUM_ITER);
        }
        SC_TIMER_STOP(rnd_timer);

        show_progress(msg, NUM_ITER, NUM_ITER);

        double elapsed = SC_TIMER_GET_ELAPSED(rnd_timer);
        printf("sqrn time: %f\n\n", elapsed);
    }

    SC_TIMER_DESTROY(rnd_timer);

    return EXIT_SUCCESS;
}

