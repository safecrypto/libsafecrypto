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

#include "packer.h"


SINT32 encode_raw_32(sc_packer_t *packer, size_t n, const SINT32 *p, size_t bits)
{
	size_t i;

    // Write bits for each symbol to the stream
    for (i=0; i<n; i++) {
        if (SC_FUNC_FAILURE == packer->write(packer, p[i], bits)) {
            return SC_ERROR;
        }
    }

    return SC_OK;
}

SINT32 decode_raw_signed_32(sc_packer_t *packer, size_t n, SINT32 *p, size_t bits)
{
	size_t i;
    UINT32 sign, sign_extension, value;
    sign           = 1 << (bits - 1);
    sign_extension = ((1 << (32 - bits)) - 1) << bits;

   	for (i=0; i<n; i++) {
       	// Obtain the sign bit, create a mask for sign extension and read the raw bits
       	if (SC_FUNC_FAILURE == packer->read(packer, &value, bits)) {
            return SC_ERROR;
       	}
       	p[i] = (value & sign)? sign_extension | value : value;
    }

    return SC_OK;
}

SINT32 decode_raw_unsigned_32(sc_packer_t *packer, size_t n, SINT32 *p, size_t bits)
{
	size_t i;
    UINT32 value;

    // Iterate through each symbol
  	for (i=0; i<n; i++) {
   		if (SC_FUNC_FAILURE == packer->read(packer, &value, bits)) {
            return SC_ERROR;
       	}
       	p[i] = value;
    }

    return SC_OK;
}

SINT32 encode_raw_16(sc_packer_t *packer, size_t n, const SINT16 *p, size_t bits)
{
	size_t i;

    // Write bits for each symbol to the stream
    for (i=0; i<n; i++) {
        if (SC_FUNC_FAILURE == packer->write(packer, p[i], bits)) {
            return SC_ERROR;
        }
    }

    return SC_OK;
}

SINT32 decode_raw_signed_16(sc_packer_t *packer, size_t n, SINT16 *p, size_t bits)
{
	size_t i;
    UINT32 sign, sign_extension, value;
    sign           = 1 << (bits - 1);
    sign_extension = ((1 << (16 - bits)) - 1) << bits;

   	for (i=0; i<n; i++) {
       	// Obtain the sign bit, create a mask for sign extension and read the raw bits
       	if (SC_FUNC_FAILURE == packer->read(packer, &value, bits)) {
            return SC_ERROR;
       	}
       	p[i] = (value & sign)? sign_extension | value : value;
    }

    return SC_OK;
}

SINT32 decode_raw_unsigned_16(sc_packer_t *packer, size_t n, SINT16 *p, size_t bits)
{
	size_t i;
    UINT32 value;

    // Iterate through each symbol
  	for (i=0; i<n; i++) {
   		if (SC_FUNC_FAILURE == packer->read(packer, &value, bits)) {
            return SC_ERROR;
       	}
       	p[i] = value;
    }

    return SC_OK;
}

SINT32 encode_raw_8(sc_packer_t *packer, size_t n, const SINT8 *p, size_t bits)
{
    size_t i;

    // Write bits for each symbol to the stream
    for (i=0; i<n; i++) {
        if (SC_FUNC_FAILURE == packer->write(packer, p[i], bits)) {
            return SC_ERROR;
        }
    }

    return SC_OK;
}

SINT32 decode_raw_signed_8(sc_packer_t *packer, size_t n, SINT8 *p, size_t bits)
{
    size_t i;
    UINT32 sign, sign_extension, value;
    sign           = 1 << (bits - 1);
    sign_extension = ((1 << (8 - bits)) - 1) << bits;

    for (i=0; i<n; i++) {
        // Obtain the sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, bits)) {
            return SC_ERROR;
        }
        p[i] = (value & sign)? sign_extension | value : value;
    }

    return SC_OK;
}

SINT32 decode_raw_unsigned_8(sc_packer_t *packer, size_t n, SINT8 *p, size_t bits)
{
    size_t i;
    UINT32 value;

    // Iterate through each symbol
    for (i=0; i<n; i++) {
        if (SC_FUNC_FAILURE == packer->read(packer, &value, bits)) {
            return SC_ERROR;
        }
        p[i] = value;
    }

    return SC_OK;
}

