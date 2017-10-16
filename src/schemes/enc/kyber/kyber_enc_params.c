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

#include "kyber_enc_params.h"
#include "safecrypto_private.h"
#include "utils/arith/arith.h"
#include "utils/arith/module_lwe.h"


kyber_set_t param_kyber_enc_0 = {
    0, SC_HASH_SHA3_512, 7681, 13, 0x88840000, 12, 256, 8, 2, 5, 4, 11, 3, 11, 2E-169,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w7681_n256, r7681_n256
#endif
};

kyber_set_t param_kyber_enc_1 = {
    1, SC_HASH_SHA3_512, 7681, 13, 0x88840000, 12, 256, 8, 3, 4, 4, 11, 3, 11, 2E-142,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w7681_n256, r7681_n256
#endif
};

kyber_set_t param_kyber_enc_2 = {
    2, SC_HASH_SHA3_512, 7681, 13, 0x88840000, 12, 256, 8, 4, 3, 3, 11, 3, 11, 2E-145,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL
#else
    w7681_n256, r7681_n256
#endif
};
