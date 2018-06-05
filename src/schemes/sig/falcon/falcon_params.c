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

#include "falcon_params.h"
#include "utils/arith/arith.h"
#include "utils/arith/ntt_tables.h"


falcon_set_t param_falcon_0 = {
    0, SC_HASH_SHA3_512, 12289, 14, 512, 9, 5, 215.0f, 6, 9,
    6598, // 1.2*1.55*sqrt(q)*sqrt(2*N)
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n512, r12289_n512
#endif
};

/*falcon_set_t param_falcon_1 = {
    1, SC_HASH_SHA3_768, 18433, 14, 1024, 10, 10, 271.0f, 6, 9,
    66407, // 0.5 * n * 1.17 * sqrtl(q)
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n1024, r12289_n1024
#endif
};*/

falcon_set_t param_falcon_2 = {
    0, SC_HASH_SHA3_512, 12289, 13, 1024, 10, 5, 100.0f, 6, 9,
    13131, // 0.5 * n * 1.17 * sqrtl(q)
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n1024, r12289_n1024
#endif
};

