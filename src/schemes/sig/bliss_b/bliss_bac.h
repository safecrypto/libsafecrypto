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

#include "safecrypto_types.h"
#include "utils/entropy/packer.h"


/**
 * Defines the BAC coding parameters for the optimum encoding of a BLISS signature
 */
SC_STRUCT_PACK_START
typedef struct _bliss_bac_code {
    size_t n_z1;         ///< Range of z1:  0..n_z1-1
    size_t n_z2;         ///< Range of z2:  -n_z2..n_z2
    size_t n_g;
    void *z1_dist;       ///< Table of z1 symbol distribution
    void *z2_dist;       ///< Table of z2 symbol distribution
    void *g_dist;        ///< Table of g symbol distribution
    size_t n;            ///< Size of symbol arrays
    FLOAT z1_sig;        ///< Standard deviation of z1 distribution
    FLOAT z2_sig;        ///< Standard deviation of z2 distribution
    SINT32 initialized;  ///< A flag used to indicate if the BAC coder has been initialised
} SC_STRUCT_PACKED bliss_bac_code_t;
SC_STRUCT_PACK_END


static bliss_bac_code_t bliss_bac_code_0 = {
    .n_z1 = 11,
    .n_z2 = 5,
    .n_g = 3,
    .z1_dist = NULL,
    .z2_dist = NULL,
    .g_dist = NULL,
    .n = 256,
    .z1_sig = 100.0f,
    .z2_sig = 0.5,
    .initialized = 0
};

static bliss_bac_code_t bliss_bac_code_1 = {
    .n_z1 = 12,
    .n_z2 = 3,
    .n_g = 2,
    .z1_dist = NULL,
    .z2_dist = NULL,
    .g_dist = NULL,
    .n = 512,
    .z1_sig = 215.0f,
    .z2_sig = 0.4792,
    .initialized = 0
};

static bliss_bac_code_t bliss_bac_code_2 = {
    .n_z1 = 12,
    .n_z2 = 2,
    .n_g = 2,
    .z1_dist = NULL,
    .z2_dist = NULL,
    .g_dist = NULL,
    .n = 512,
    .z1_sig = 107.0f,
    .z2_sig = 0.4352,
    .initialized = 0
};

static bliss_bac_code_t bliss_bac_code_3 = {
    .n_z1 = 12,
    .n_z2 = 3,
    .n_g = 3,
    .z1_dist = NULL,
    .z2_dist = NULL,
    .g_dist = NULL,
    .n = 512,
    .z1_sig = 250.0f,
    .z2_sig = 0.6460,
    .initialized = 0
};

static bliss_bac_code_t bliss_bac_code_4 = {
    .n_z1 = 12,
    .n_z2 = 4,
    .n_g = 3,
    .z1_dist = NULL,
    .z2_dist = NULL,
    .g_dist = NULL,
    .n = 512,
    .z1_sig = 271.0f,
    .z2_sig = 0.625,//1.136,
    .initialized = 0
};

SINT32 bliss_privkey_encode_bac(sc_packer_t *packer, SINT32 n,
    SINT16 *f, SINT16 *g, SINT32 bits);
SINT32 bliss_privkey_decode_bac(sc_packer_t *packer, SINT32 n,
    SINT16 *f, SINT16 *g, SINT32 bits);

SINT32 bliss_pubkey_encode_bac(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits);
SINT32 bliss_pubkey_decode_bac(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits);

SINT32 bliss_sig_create_bac(bliss_bac_code_t *bac_code);
SINT32 bliss_sig_destroy_bac(bliss_bac_code_t *bac_code);
SINT32 bliss_sig_encode_bac(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits);
SINT32 bliss_sig_decode_bac(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits);

SINT32 bliss_sig_encode_bac_expg(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits);
SINT32 bliss_sig_decode_bac_expg(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits);

