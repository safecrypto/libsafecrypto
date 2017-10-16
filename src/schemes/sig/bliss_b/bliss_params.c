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

#include "bliss_params.h"
#include "utils/arith/arith.h"
#ifndef USE_RUNTIME_NTT_TABLES
#include "utils/arith/ntt_tables.h"
#endif


bliss_set_t param_bliss_b_0 = {
    0, 7681, 13, 256, 8, 5, 480, 12, 530, 2492 * 2492,
    {38, 140}, 11, 5, 100.0f, 2.44f, SC_HASH_SHA3_512,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, NULL, NULL, NULL
#else
    w7681_n256, r7681_n256, rev_w7681_n256, inv_w7681_n256, inv_r7681_n256
#endif
};

bliss_set_t param_bliss_b_1 = {
    1, 12289, 14, 512, 9, 10, 24, 23, 2100, 12872 * 12872,
    {0, 154}, 12, 3, 215.0f, 1.21f, SC_HASH_SHA3_512,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, NULL, NULL, NULL
#else
    w12289_n512, r12289_n512, rev_w12289_n512, inv_w12289_n512, inv_r7681_n256
#endif
};

bliss_set_t param_bliss_b_2 = {
    2, 12289, 14, 512, 9, 10, 24, 23, 1563, 11074 * 11074,
    {0, 154}, 12, 2, 107.0f, 2.18f, SC_HASH_SHA3_512,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, NULL, NULL, NULL
#else
    w12289_n512, r12289_n512, rev_w12289_n512, inv_w12289_n512, inv_r7681_n256
#endif
};

bliss_set_t param_bliss_b_3 = {
    3, 12289, 14, 512, 9, 9, 48, 30, 1760, 10206 * 10206,
    {16, 216}, 12, 3, 250.0f, 1.40f, SC_HASH_SHA3_512,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, NULL, NULL, NULL
#else
    w12289_n512, r12289_n512, rev_w12289_n512, inv_w12289_n512, inv_r7681_n256
#endif
};

bliss_set_t param_bliss_b_4 = {
    4, 12289, 14, 512, 9, 8, 96, 39, 1613, 9901 * 9901,
    {31, 231}, 12, 4, 271.0f, 1.61f, SC_HASH_SHA3_512,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, NULL, NULL, NULL
#else
    w12289_n512, r12289_n512, rev_w12289_n512, inv_w12289_n512, inv_r7681_n256
#endif
};
