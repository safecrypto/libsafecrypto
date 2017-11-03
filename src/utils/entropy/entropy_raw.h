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

#pragma once

#include "safecrypto_private.h"

SINT32 encode_raw_32(sc_packer_t *packer, size_t n, const SINT32 *p, size_t bits);
SINT32 decode_raw_signed_32(sc_packer_t *packer, size_t n, SINT32 *p, size_t bits);
SINT32 decode_raw_unsigned_32(sc_packer_t *packer, size_t n, SINT32 *p, size_t bits);
SINT32 encode_raw_16(sc_packer_t *packer, size_t n, const SINT16 *p, size_t bits);
SINT32 decode_raw_signed_16(sc_packer_t *packer, size_t n, SINT16 *p, size_t bits);
SINT32 decode_raw_unsigned_16(sc_packer_t *packer, size_t n, SINT16 *p, size_t bits);
SINT32 encode_raw_8(sc_packer_t *packer, size_t n, const SINT8 *p, size_t bits);
SINT32 decode_raw_signed_8(sc_packer_t *packer, size_t n, SINT8 *p, size_t bits);
SINT32 decode_raw_unsigned_8(sc_packer_t *packer, size_t n, SINT8 *p, size_t bits);
