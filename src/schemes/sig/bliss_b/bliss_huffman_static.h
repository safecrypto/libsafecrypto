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


SINT32 bliss_sig_encode_huffman_static(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits);
SINT32 bliss_sig_decode_huffman_static(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits);

SINT32 bliss_pubkey_encode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits);
SINT32 bliss_pubkey_decode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits);

SINT32 bliss_privkey_encode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *f,
    SINT16 *g, SINT32 bits);
SINT32 bliss_privkey_decode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *f,
    SINT16 *g, SINT32 bits);
