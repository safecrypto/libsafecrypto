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

#include "dlp_ibe_params.h"
#include "utils/arith/arith.h"


dlp_ibe_set_t param_dlp_ibe_0 = {
    0, SC_HASH_SHA3_512, 5767169, 23, 512, 9,
    2883584, 19, 971,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w5767169_n512, r5767169_n512
#endif
};

dlp_ibe_set_t param_dlp_ibe_1 = {
    1, SC_HASH_SHA3_512, 10223617, 24, 512, 9,
    5111808, 20, 3981,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w10223617_n512, r10223617_n512
#endif
};

dlp_ibe_set_t param_dlp_ibe_2 = {
    2, SC_HASH_SHA3_512, 51750913, 26, 512, 9,
    25875456, 23, 115658,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w51750913_n512, r51750913_n512
#endif
};

dlp_ibe_set_t param_dlp_ibe_3 = {
    3, SC_HASH_SHA3_512, 5767169, 23, 1024, 10,
    2883584, 18, 19484,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w5767169_n1024, r5767169_n1024
#endif
};

dlp_ibe_set_t param_dlp_ibe_4 = {
    4, SC_HASH_SHA3_512, 10223617, 24, 1024, 10,
    5111808, 20, 6877,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w10223617_n1024, r10223617_n1024
#endif
};

dlp_ibe_set_t param_dlp_ibe_5 = {
    5, SC_HASH_SHA3_512, 51750913, 26, 1024, 10,
    25875456, 22, 36945,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w51750913_n1024, r51750913_n1024
#endif
};

#if 0
dlp_ibe_set_t param_dlp_ibe_6 = {
    6, SC_HASH_SHA3_512, 16813057, 25, 512, 9,
    8406528, 21, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w16813057_n512, r16813057_n512
#endif
};

dlp_ibe_set_t param_dlp_ibe_7 = {
    7, SC_HASH_SHA3_512, 134348801, 28, 1024, 10,
    67174400, 24, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w134348801_n1024, r134348801_n1024
#endif
};

dlp_ibe_set_t param_dlp_ibe_8 = {
    8, SC_HASH_SHA3_512, 7681, 13, 256, 8,
    3840, 0, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w7681_n256, r7681_n256
#endif
};

dlp_ibe_set_t param_dlp_ibe_9 = {
    9, SC_HASH_SHA3_512, 12289, 14, 512, 9,
    6144, 0, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n512, r12289_n512
#endif
};

dlp_ibe_set_t param_dlp_ibe_10 = {
    10, SC_HASH_SHA3_512, 12289, 14, 1024, 10,
    6144, 0, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w12289_n1024, r12289_n1024
#endif
};
#endif
