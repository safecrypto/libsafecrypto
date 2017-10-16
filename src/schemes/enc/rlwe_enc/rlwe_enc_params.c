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

#include "rlwe_enc_params.h"
#include "utils/arith/arith.h"



// NOTE: sigma is equivalent to s/sqrt(2*pi), i.e. 11.81 and 12.31 for RLWEenc

rlwe_set_t param_rlwe_enc_0 = {
    0, 7681, 13, 256, 8, 4.51f, 3840, 1920, 5760,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, NULL, NULL, NULL
#else
    w7681_n256, r7681_n256, rev_w7681_n256, inv_w7681_n256, inv_r7681_n256
#endif
};

rlwe_set_t param_rlwe_enc_1 = {
    1, 12289, 14, 512, 9, 4.86f, 6144, 3072, 9216,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, NULL, NULL, NULL
#else
    w12289_n512, r12289_n512, rev_w12289_n512, inv_w12289_n512, inv_r12289_n512
#endif
};
