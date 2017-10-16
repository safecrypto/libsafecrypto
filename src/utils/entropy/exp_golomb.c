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

#include "exp_golomb.h"


static const UINT8 length_lut[256] = {
    1,  3,  3,  5,  5,  5,  5,  7,  7,  7,  7,  7,  7,  7,  7,  9,
    9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  11,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 17
};

void exp_golomb_encode(UINT8 in, UINT32 *code, SINT32 *bits)
{
    // NOTE: k = 0

    // Obtain the code length
    *bits = length_lut[in];

    // Translate the input value and sign bit into a code
    *code = in + 1;
}

void exp_golomb_sign_encode(SINT8 in, UINT32 *code, SINT32 *bits)
{
    // NOTE: k = 0
    UINT32 sign, value;
    SINT32 in1 = (SINT32) in;

    // Obtain the sign bit
    sign = (in1 <= 0)? 0 : 1;

    // Obtain the absolute value
    value = (sign)? (UINT32)(in1) : (UINT32)(-in1);
    value = (value << 1) - sign;

    exp_golomb_encode(value, code, bits);
}

UINT8 exp_golomb_decode(UINT32 code)
{
    // NOTE: k = 0
    return code - 1;
}

SINT8 exp_golomb_sign_decode(UINT32 code)
{
    // NOTE: k = 0
    SINT32 sign, value;

    if (1 == code) return 0;

    value = code;
    sign = value & 0x1;
    value >>= 1;

    return sign? -value : value;
}

