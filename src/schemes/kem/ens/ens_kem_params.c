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

#include "ens_kem_params.h"
#include "safecrypto_private.h"
#include "utils/arith/arith.h"


ens_kem_set_t param_ens_kem_0 = {
    0, 12289, 14, 512, 9, 4.151f, 93.21f, 487,
    {1, 1, 3, 5, 8, 12, 17, 24, 31, 38, 44, 47/*48*/, 48},
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n512, r12289_n512
#endif
};

ens_kem_set_t param_ens_kem_1 = {
    1, 12289, 14, 512, 9, 2.991f, 67.17f, 438,
    {0, 0, 0, 1, 2, 4, 9, 17, 28, 41, 55, 64/*65*/, 68},
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n512, r12289_n512
#endif
};

ens_kem_set_t param_ens_kem_2 = {
    2, 12289, 14, 1024, 10, 3.467f, 110.42f, 1026,
    {0, 1, 2, 4, 8, 15, 26, 42, 61, 81, 100, 112/*113*/, 118},
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n1024, r12289_n1024
#endif
};

ens_kem_set_t param_ens_kem_3 = {
    3, 12289, 14, 1024, 10, 2.510f, 79.54f, 939,
    {0, 0, 0, 0, 1, 3, 9, 22, 46, 80, 118, 150, 166},
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n1024, r12289_n1024
#endif
};
