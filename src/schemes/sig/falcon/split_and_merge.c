/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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

#include "split_and_merge.h"




static void cycle(double *y, size_t n)
{
    double temp = y[n-1];
    for (size_t i=1; i<n; i++) {
        y[i]=y[i-1];
    }
    
    y[0]=temp;
}
    
/*void splitfft2(double *F, double *f_0, double *f_1, size_t n)
{
    for (i=0; i++; i<n) {
        if (***fwd[i] AND fwd[i]***) { //roots of unity---check conditions?
            f_0[[i]]=(1/2)*(f[i]+f(-[i]);
            f_1[[i]]=(1/(2*fwd[i]))(f[i])-f(-[i]));
        }
    }
} //this can be replaced with subroutine of reverse_fft_step...???*/


