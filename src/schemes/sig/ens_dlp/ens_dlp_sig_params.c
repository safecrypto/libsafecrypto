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

#include "ens_dlp_sig_params.h"
#include "utils/arith/arith.h"
#include "utils/arith/ntt_tables.h"


ens_dlp_sig_set_t param_ens_sig_0 = {
    0, CRYPTO_HASH_SHA3_512, 12289, 14, 512, 9, 19, 5, 215.0f, 6, 9,
    33203, // 0.5 * n * 1.17 * sqrtl(q)
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n512, r12289_n512
#endif
};

ens_dlp_sig_set_t param_ens_sig_1 = {
    1, CRYPTO_HASH_SHA3_512, 12289, 14, 1024, 10, 19, 10, 271.0f, 6, 9,
    66407, // 0.5 * n * 1.17 * sqrtl(q)
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n1024, r12289_n1024
#endif
};

#if 1
ens_dlp_sig_set_t param_dlp_sig_0 = {
    0, CRYPTO_HASH_SHA3_512, 7681, 13, 256, 8, 20, 5, 100.0f, 6, 9,
    13131, // 0.5 * n * 1.17 * sqrtl(q)
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w7681_n256, r7681_n256
#endif
};

ens_dlp_sig_set_t param_dlp_sig_1 = {
    1, CRYPTO_HASH_SHA3_512, 12289, 14, 512, 9, 19, 10, 100.0f, 6, 9,
    60000,//26263, // 0.5 * n * 1.17 * sqrtl(q)
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n512, r12289_n512
#endif
};
#else
ens_dlp_sig_set_t param_dlp_sig_0 = {
    0, CRYPTO_HASH_SHA3_512, 999, 10, 256, 8, 26, 5, 100.0f, 5, 8,
    3996, // 0.5 * sqrt(0.25*q*q*N)
    NULL, NULL
};

ens_dlp_sig_set_t param_dlp_sig_1 = {
    1, CRYPTO_HASH_SHA3_512, 999, 10, 512, 9, 26, 10, 110.0f, 5, 8,
    5651, // 0.5 * sqrt(0.25*q*q*N)
    NULL, NULL
};
#endif
