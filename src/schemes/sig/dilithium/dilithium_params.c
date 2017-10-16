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

#include "dilithium_params.h"

/// Dilithium Parameter Sets
/// @{
// Parameter Set 0 - Weak
dilithium_set_t param_dilithium_0 = {
    0, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    3, 2, 14, 0, 60, 523776, 19, 261888, 0.0f, 0.0f, 0, 0, 7, 3, 20, 330, 64, 7,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};

// Parameter Set 1 - Medium
dilithium_set_t param_dilithium_1 = {
    1, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    4, 3, 14, 0, 60, 523776, 19, 261888, 0.0f, 0.0f, 0, 0, 6, 3, 20, 285, 80, 7,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};

// Parameter Set 2 - Recommended
dilithium_set_t param_dilithium_2 = {
    2, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    5, 4, 14, 0, 60, 523776, 19, 261888, 0.0f, 0.0f, 0, 0, 5, 3, 20, 235, 96, 7,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};

// Parameter Set 3 - Very High
dilithium_set_t param_dilithium_3 = {
    3, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    6, 5, 14, 0, 60, 523776, 19, 261888, 0.0f, 0.0f, 0, 0, 3, 2, 20, 145, 120, 7,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};
/// @}


/// Dilithium-G Parameter Sets
/// @{
// Parameter Set 0 - Weak
dilithium_set_t param_dilithium_g_0 = {
    0, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    2, 2, 11, 230, 60, 523776, 19, 261888, 19600.0f, 1225.0f, 16368, 14, 7, 3, 20, 750000, 0, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};

// Parameter Set 1 - Medium
dilithium_set_t param_dilithium_g_1 = {
    1, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    3, 3, 11, 225, 60, 523776, 19, 261888, 19200.0f, 1200.0f, 16368, 14, 6, 3, 20, 904000, 0, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};

// Parameter Set 2 - Recommended
dilithium_set_t param_dilithium_g_2 = {
    2, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    4, 4, 11, 210, 60, 523776, 19, 261888, 17900.0f, 1118.0f, 16368, 14, 5, 3, 20, 990000, 0, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};

// Parameter Set 3 - Very High
dilithium_set_t param_dilithium_g_3 = {
    3, SC_HASH_SHA3_512, 256, 8, 8380417, 23,
    5, 5, 11, 145, 60, 523776, 19, 261888, 12400.0f, 775.0f, 16368, 14, 3, 2, 20, 870000, 0, 0,
#ifdef USE_RUNTIME_NTT_TABLES
    NULL, NULL, 1753
#else
    w8380417_n256, r8380417_n256
#endif
};
/// @}
