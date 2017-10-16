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
#include "utils/arith/sc_math.h"

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

typedef DOUBLE (*exp_func)(DOUBLE);

int main(void)
{
    #define NUM_ITER      1048576UL

    exp_func exput;

    SC_TIMER_INSTANCE(rnd_timer);
    SC_TIMER_CREATE(rnd_timer);

    UINT64 j, k;

    for (j=0; j<3; j++) {
        SC_TIMER_RESET(rnd_timer);

        char msg[32];
        switch (j) {
            case 0:  exput = exp;               strcpy(msg, "exp()"); break;
            case 1:  exput = sc_exp_dbl_coarse; strcpy(msg, "coarse"); break;
            default: exput = sc_exp_dbl_taylor; strcpy(msg, "taylor");
        }

        DOUBLE ivalue = 0.0f;
        for (k=0; k<NUM_ITER; k++) {
            SC_TIMER_START(rnd_timer);
            (void)exput(ivalue);
            SC_TIMER_STOP(rnd_timer);

            ivalue += (1 / NUM_ITER);
    
            if ((k & 0x1FFF) == 0x1FFF) show_progress(msg, k, NUM_ITER);
        }

        show_progress(msg, NUM_ITER, NUM_ITER);

        double elapsed = SC_TIMER_GET_ELAPSED(rnd_timer);
        printf("EXP time: %f\n", elapsed);
    }

    SC_TIMER_DESTROY(rnd_timer);

    return EXIT_SUCCESS;
}

