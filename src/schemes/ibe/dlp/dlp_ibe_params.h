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

#pragma once

#ifndef NTT_NEEDS_5767169
#define NTT_NEEDS_5767169
#endif
#ifndef NTT_NEEDS_10223617
#define NTT_NEEDS_10223617
#endif
#ifndef NTT_NEEDS_51750913
#define NTT_NEEDS_51750913
#endif

#ifndef NEEDS_GAUSSIAN_ZIGGURAT
#define NEEDS_GAUSSIAN_ZIGGURAT
#endif

#ifndef NEEDS_GAUSSIAN_CDF
#define NEEDS_GAUSSIAN_CDF
#endif


#include "safecrypto_private.h"
#include "utils/crypto/hash.h"


/// A struct use to store DLP IBE parameter sets
SC_STRUCT_PACK_START
typedef struct dlp_ibe_set_t {
    const UINT32  set;
    const crypto_hash_e hash_type;
    const UINT32  q;
    const UINT32  q_bits;
    const UINT32  n;
    const UINT32  n_bits;
    const UINT32  m_scale;
    const UINT32  l;
    const UINT32  nth_root_of_unity;
#ifdef USE_RUNTIME_NTT_TABLES
    SINT32       *w;
    SINT32       *r;
#else
    const SINT32 *w;
    const SINT32 *r;
#endif
} SC_STRUCT_PACKED dlp_ibe_set_t;
SC_STRUCT_PACK_END

extern dlp_ibe_set_t param_dlp_ibe_0;
extern dlp_ibe_set_t param_dlp_ibe_1;
extern dlp_ibe_set_t param_dlp_ibe_2;
extern dlp_ibe_set_t param_dlp_ibe_3;
extern dlp_ibe_set_t param_dlp_ibe_4;
extern dlp_ibe_set_t param_dlp_ibe_5;

#if 0
extern dlp_ibe_set_t param_dlp_ibe_6;
extern dlp_ibe_set_t param_dlp_ibe_7;
extern dlp_ibe_set_t param_dlp_ibe_8;
extern dlp_ibe_set_t param_dlp_ibe_9;
extern dlp_ibe_set_t param_dlp_ibe_10;
#endif
