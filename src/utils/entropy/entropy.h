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
#include <string.h>

typedef struct sc_packer sc_packer_t;

typedef enum _entropy_sign_e {
    UNSIGNED_COEFF = 0,
    SIGNED_COEFF
} entropy_sign_e;


/// Use the given packer object to compress the signed input polynomial
/// @param packer A bit packing object also capable of entropy coding
/// @param n The length of the input polynomial
/// @param p The input polynomial
/// @param bits The maximum coefficient size in bits
/// @param signedness The signedness of the coefficients
/// @param type The type of entropy coding to be applied
/// @param dist The index of the distribution to be used
/// @param coded_bits An incrementing count of the output coded bits
SINT32 entropy_poly_encode_32(sc_packer_t *packer, size_t n, const SINT32 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits);

/// Use the given packer object to decompress and write to the signed output polynomial
/// @param packer A bit packing object also capable of entropy decoding
/// @param n The length of the output polynomial
/// @param p The output polynomial
/// @param bits The maximum coefficient size in bits
/// @param signedness The signedness of the coefficients
/// @param type The type of entropy coding to be applied
/// @param dist The index of the distribution to be used
SINT32 entropy_poly_decode_32(sc_packer_t *packer, size_t n, SINT32 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist);

/// Use the given packer object to compress the signed input polynomial
/// @param packer A bit packing object also capable of entropy coding
/// @param n The length of the input polynomial
/// @param p The input polynomial
/// @param bits The maximum coefficient size in bits
/// @param signedness The signedness of the coefficients
/// @param type The type of entropy coding to be applied
/// @param dist The index of the distribution to be used
/// @param coded_bits An incrementing count of the output coded bits
SINT32 entropy_poly_encode_16(sc_packer_t *packer, size_t n, const SINT16 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits);

/// Use the given packer object to decompress and write to the signed output polynomial
/// @param packer A bit packing object also capable of entropy decoding
/// @param n The length of the output polynomial
/// @param p The output polynomial
/// @param bits The maximum coefficient size in bits
/// @param signedness The signedness of the coefficients
/// @param type The type of entropy coding to be applied
/// @param dist The index of the distribution to be used
SINT32 entropy_poly_decode_16(sc_packer_t *packer, size_t n, SINT16 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist);

/// Use the given packer object to compress the signed input polynomial
/// @param packer A bit packing object also capable of entropy coding
/// @param n The length of the input polynomial
/// @param p The input polynomial
/// @param bits The maximum coefficient size in bits
/// @param signedness The signedness of the coefficients
/// @param type The type of entropy coding to be applied
/// @param dist The index of the distribution to be used
/// @param coded_bits An incrementing count of the output coded bits
SINT32 entropy_poly_encode_8(sc_packer_t *packer, size_t n, const SINT8 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits);

/// Use the given packer object to decompress and write to the signed output polynomial
/// @param packer A bit packing object also capable of entropy decoding
/// @param n The length of the output polynomial
/// @param p The output polynomial
/// @param bits The maximum coefficient size in bits
/// @param signedness The signedness of the coefficients
/// @param type The type of entropy coding to be applied
/// @param dist The index of the distribution to be used
SINT32 entropy_poly_decode_8(sc_packer_t *packer, size_t n, SINT8 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist);

