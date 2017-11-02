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

#include "entropy.h"
#include "packer.h"
#include "bac.h"
#include "huffman.h"



static SINT32 encode_huffman_signed_32(sc_packer_t *packer,
	size_t n, const SINT32 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 value, sign;
    SINT32 mask = (1 << beta) - 1;
    const huffman_table_t *table = (7 == bits)? huff_table_gaussian_6 :
                                   (6 == bits)? huff_table_gaussian_5 :
                                   (5 == bits)? huff_table_gaussian_4 :
                                   (4 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    for (i=0; i<n; i++) {
        // Write the least significant beta for each p symbol to the stream
        sign  = (p[i] < 0)? 1 : 0;
        value = (sign)? -p[i] : p[i];
        if (SC_FUNC_FAILURE == packer->write(packer, value & mask, beta)) {
            return SC_ERROR;
        }
        value >>= beta;

        // Huffman code the most significant bits
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }

        // If non-zero encode a sign bit
        if (0 != p[i]) {
            if (SC_FUNC_FAILURE == packer->write(packer, sign, 1)) {
                return SC_ERROR;
            }
        }
    }

    return SC_OK;
}

static SINT32 encode_huffman_unsigned_32(sc_packer_t *packer,
	size_t n, const SINT32 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 value;
    SINT32 mask = (1 << beta) - 1;
    const huffman_table_t *table = (6 == bits)? huff_table_gaussian_6 :
                                   (5 == bits)? huff_table_gaussian_5 :
                                   (4 == bits)? huff_table_gaussian_4 :
                                   (3 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    for (i=0; i<n; i++) {
        // Write the least significant beta for each p symbol to the stream
        value = p[i];
        if (SC_FUNC_FAILURE == packer->write(packer, value & mask, beta)) {
            return SC_ERROR;
        }
        value >>= beta;

        // Huffman code the most significant bits
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }
    }

    return SC_OK;
}

static SINT32 decode_huffman_signed_32(sc_packer_t *packer,
	size_t n, SINT32 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 sign, value;
    const huffman_table_t *table = (7 == bits)? huff_table_gaussian_6 :
                                   (6 == bits)? huff_table_gaussian_5 :
                                   (5 == bits)? huff_table_gaussian_4 :
                                   (4 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<n; i++) {
        // Obtain the sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, beta)) {
            return SC_ERROR;
        }

        if (SC_OK != decode_huffman(packer, table, &sign)) {
            return SC_ERROR;
        }

        value |= sign << beta;
        if (0 != value) {
            if (SC_FUNC_FAILURE == packer->read(packer, &sign, 1)) {
                return SC_ERROR;
            }
        }
        else {
            sign = 0;
        }

        p[i] = value;
        p[i] = (sign)? -p[i] : p[i];
    }

    return SC_OK;
}

static SINT32 decode_huffman_unsigned_32(sc_packer_t *packer,
	size_t n, SINT32 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 sign, value;
    const huffman_table_t *table = (6 == bits)? huff_table_gaussian_6 :
                                   (5 == bits)? huff_table_gaussian_5 :
                                   (4 == bits)? huff_table_gaussian_4 :
                                   (3 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<n; i++) {
        // Obtain the sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, beta)) {
            return SC_ERROR;
        }

        if (SC_OK != decode_huffman(packer, table, &sign)) {
            return SC_ERROR;
        }

        p[i] = value | (sign << beta);
    }

    return SC_OK;
}

static SINT32 encode_huffman_signed_16(sc_packer_t *packer,
	size_t n, const SINT16 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 value, sign;
    SINT32 mask = (1 << beta) - 1;
    const huffman_table_t *table = (7 == bits)? huff_table_gaussian_6 :
                                   (6 == bits)? huff_table_gaussian_5 :
                                   (5 == bits)? huff_table_gaussian_4 :
                                   (4 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    for (i=0; i<n; i++) {
        // Write the least significant beta for each p symbol to the stream
        sign  = (p[i] < 0)? 1 : 0;
        value = (sign)? -p[i] : p[i];
        if (SC_FUNC_FAILURE == packer->write(packer, value & mask, beta)) {
            return SC_ERROR;
        }
        value >>= beta;

        // Huffman code the most significant bits
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }

        // If non-zero encode a sign bit
        if (0 != p[i]) {
            if (SC_FUNC_FAILURE == packer->write(packer, sign, 1)) {
                return SC_ERROR;
            }
        }
    }

    return SC_OK;
}

static SINT32 encode_huffman_unsigned_16(sc_packer_t *packer,
	size_t n, const SINT16 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 value;
    SINT32 mask = (1 << beta) - 1;
    const huffman_table_t *table = (6 == bits)? huff_table_gaussian_6 :
                                   (5 == bits)? huff_table_gaussian_5 :
                                   (4 == bits)? huff_table_gaussian_4 :
                                   (3 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    for (i=0; i<n; i++) {
        // Write the least significant beta for each p symbol to the stream
        value = p[i];
        if (SC_FUNC_FAILURE == packer->write(packer, value & mask, beta)) {
            return SC_ERROR;
        }
        value >>= beta;

        // Huffman code the most significant bits
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }
    }

    return SC_OK;
}

static SINT32 decode_huffman_signed_16(sc_packer_t *packer,
	size_t n, SINT16 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 sign, value;
    const huffman_table_t *table = (7 == bits)? huff_table_gaussian_6 :
                                   (6 == bits)? huff_table_gaussian_5 :
                                   (5 == bits)? huff_table_gaussian_4 :
                                   (4 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<n; i++) {
        // Obtain the sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, beta)) {
            return SC_ERROR;
        }

        if (SC_OK != decode_huffman(packer, table, &sign)) {
            return SC_ERROR;
        }

        value |= sign << beta;
        if (0 != value) {
            if (SC_FUNC_FAILURE == packer->read(packer, &sign, 1)) {
                return SC_ERROR;
            }
        }
        else {
            sign = 0;
        }

        p[i] = value;
        p[i] = (sign)? -p[i] : p[i];
    }

    return SC_OK;
}

static SINT32 decode_huffman_unsigned_16(sc_packer_t *packer,
	size_t n, SINT16 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 sign, value;
    const huffman_table_t *table = (6 == bits)? huff_table_gaussian_6 :
                                   (5 == bits)? huff_table_gaussian_5 :
                                   (4 == bits)? huff_table_gaussian_4 :
                                   (3 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<n; i++) {
        // Obtain the sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, beta)) {
            return SC_ERROR;
        }

        if (SC_OK != decode_huffman(packer, table, &sign)) {
            return SC_ERROR;
        }

        p[i] = value | (sign << beta);
    }

    return SC_OK;
}

static SINT32 encode_huffman_signed_8(sc_packer_t *packer,
    size_t n, const SINT8 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 value, sign;
    SINT32 mask = (1 << beta) - 1;
    const huffman_table_t *table = (7 == bits)? huff_table_gaussian_6 :
                                   (6 == bits)? huff_table_gaussian_5 :
                                   (5 == bits)? huff_table_gaussian_4 :
                                   (4 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    for (i=0; i<n; i++) {
        // Write the least significant beta for each p symbol to the stream
        sign  = (p[i] < 0)? 1 : 0;
        value = (sign)? -p[i] : p[i];
        if (SC_FUNC_FAILURE == packer->write(packer, value & mask, beta)) {
            return SC_ERROR;
        }
        value >>= beta;

        // Huffman code the most significant bits
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }

        // If non-zero encode a sign bit
        if (0 != p[i]) {
            if (SC_FUNC_FAILURE == packer->write(packer, sign, 1)) {
                return SC_ERROR;
            }
        }
    }

    return SC_OK;
}

static SINT32 encode_huffman_unsigned_8(sc_packer_t *packer,
    size_t n, const SINT8 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 value;
    SINT32 mask = (1 << beta) - 1;
    const huffman_table_t *table = (6 == bits)? huff_table_gaussian_6 :
                                   (5 == bits)? huff_table_gaussian_5 :
                                   (4 == bits)? huff_table_gaussian_4 :
                                   (3 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    for (i=0; i<n; i++) {
        // Write the least significant beta for each p symbol to the stream
        value = p[i];
        if (SC_FUNC_FAILURE == packer->write(packer, value & mask, beta)) {
            return SC_ERROR;
        }
        value >>= beta;

        // Huffman code the most significant bits
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }
    }

    return SC_OK;
}

static SINT32 decode_huffman_signed_8(sc_packer_t *packer,
    size_t n, SINT8 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 sign, value;
    const huffman_table_t *table = (7 == bits)? huff_table_gaussian_6 :
                                   (6 == bits)? huff_table_gaussian_5 :
                                   (5 == bits)? huff_table_gaussian_4 :
                                   (4 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<n; i++) {
        // Obtain the sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, beta)) {
            return SC_ERROR;
        }

        if (SC_OK != decode_huffman(packer, table, &sign)) {
            return SC_ERROR;
        }

        value |= sign << beta;
        if (0 != value) {
            if (SC_FUNC_FAILURE == packer->read(packer, &sign, 1)) {
                return SC_ERROR;
            }
        }
        else {
            sign = 0;
        }

        p[i] = value;
        p[i] = (sign)? -p[i] : p[i];
    }

    return SC_OK;
}

static SINT32 decode_huffman_unsigned_8(sc_packer_t *packer,
    size_t n, SINT8 *p, size_t bits, SINT32 beta)
{
    size_t i;
    UINT32 sign, value;
    const huffman_table_t *table = (6 == bits)? huff_table_gaussian_6 :
                                   (5 == bits)? huff_table_gaussian_5 :
                                   (4 == bits)? huff_table_gaussian_4 :
                                   (3 == bits)? huff_table_gaussian_3 :
                                                huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<n; i++) {
        // Obtain the sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, beta)) {
            return SC_ERROR;
        }

        if (SC_OK != decode_huffman(packer, table, &sign)) {
            return SC_ERROR;
        }

        p[i] = value | (sign << beta);
    }

    return SC_OK;
}

static SINT32 encode_raw_32(sc_packer_t *packer, size_t n, const SINT32 *p,
	size_t bits)
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

static SINT32 decode_raw_signed_32(sc_packer_t *packer, size_t n, SINT32 *p,
	size_t bits)
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

static SINT32 decode_raw_unsigned_32(sc_packer_t *packer, size_t n, SINT32 *p,
	size_t bits)
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

static SINT32 encode_raw_16(sc_packer_t *packer, size_t n, const SINT16 *p,
	size_t bits)
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

static SINT32 decode_raw_signed_16(sc_packer_t *packer, size_t n, SINT16 *p,
	size_t bits)
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

static SINT32 decode_raw_unsigned_16(sc_packer_t *packer, size_t n, SINT16 *p,
	size_t bits)
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

static SINT32 encode_raw_8(sc_packer_t *packer, size_t n, const SINT8 *p,
    size_t bits)
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

static SINT32 decode_raw_signed_8(sc_packer_t *packer, size_t n, SINT8 *p,
    size_t bits)
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

static SINT32 decode_raw_unsigned_8(sc_packer_t *packer, size_t n, SINT8 *p,
    size_t bits)
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


SINT32 entropy_poly_encode_32(sc_packer_t *packer, size_t n, const SINT32 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits)
{
    SINT32 retval;
    if (NULL == packer) {
        return SC_ERROR;
    }

    size_t coded = utils_entropy.pack_get_bits(packer);

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
		if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
			retval = encode_huffman_unsigned_32(packer, n, p, bits - beta, beta);
		}
		else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
			retval = encode_huffman_signed_32(packer, n, p, bits - beta, beta);
		}
	}
    else if (SC_ENTROPY_BAC == type) {
        SINT32 offset = 0;
        if (SIGNED_COEFF == signedness) {
            offset = 1 << (bits - 1);
        }
        retval = bac_encode_64_32(packer, p, n, packer->coder->dist[dist], bits, offset);
        retval = (SC_FUNC_SUCCESS == retval)? SC_OK : SC_ERROR;
    }
	else {
		retval = encode_raw_32(packer, n, p, bits);
	}

    if (NULL != coded_bits) {
        *coded_bits += utils_entropy.pack_get_bits(packer) - coded;
    }
    return retval;
}

SINT32 entropy_poly_decode_32(sc_packer_t *packer, size_t n, SINT32 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist)
{
    if (NULL == packer) {
        return SC_ERROR;
    }

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
    	if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
	    	return decode_huffman_unsigned_32(packer, n, p, bits - beta, beta);
	    }
	    else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
    		return decode_huffman_signed_32(packer, n, p, bits - beta, beta);
    	}
    }
    else {
    	if (UNSIGNED_COEFF == signedness) {
	    	return decode_raw_unsigned_32(packer, n, p, bits);
	    }
	    else {
    		return decode_raw_signed_32(packer, n, p, bits);
    	}
    }
}

SINT32 entropy_poly_encode_16(sc_packer_t *packer, size_t n, const SINT16 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits)
{
    SINT32 retval;

    if (NULL == packer) {
        return SC_ERROR;
    }

    size_t coded = utils_entropy.pack_get_bits(packer);

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
		if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
			retval = encode_huffman_unsigned_16(packer, n, p, bits - beta, beta);
		}
		else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
			retval = encode_huffman_signed_16(packer, n, p, bits - beta, beta);
		}
	}
	else {
		retval = encode_raw_16(packer, n, p, bits);
	}

    if (NULL != coded_bits) {
        *coded_bits += utils_entropy.pack_get_bits(packer) - coded;
    }
    return retval;
}

SINT32 entropy_poly_decode_16(sc_packer_t *packer, size_t n, SINT16 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist)
{
    if (NULL == packer) {
        return SC_ERROR;
    }

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
    	if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
	    	return decode_huffman_unsigned_16(packer, n, p, bits - beta, beta);
	    }
	    else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
    		return decode_huffman_signed_16(packer, n, p, bits - beta, beta);
    	}
    }
    else {
		if (UNSIGNED_COEFF == signedness) {
    		return decode_raw_unsigned_16(packer, n, p, bits);
    	}
    	else {
	    	return decode_raw_signed_16(packer, n, p, bits);
	    }
	}
}

SINT32 entropy_poly_encode_8(sc_packer_t *packer, size_t n, const SINT8 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits)
{
    SINT32 retval;

    if (NULL == packer) {
        return SC_ERROR;
    }

    size_t coded = utils_entropy.pack_get_bits(packer);

    if (SC_ENTROPY_HUFFMAN_STATIC == type) {
        if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
            retval = encode_huffman_unsigned_8(packer, n, p, bits - beta, beta);
        }
        else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
            retval = encode_huffman_signed_8(packer, n, p, bits - beta, beta);
        }
    }
    else {
        retval = encode_raw_8(packer, n, p, bits);
    }

    if (NULL != coded_bits) {
        *coded_bits += utils_entropy.pack_get_bits(packer) - coded;
    }
    return retval;
}

SINT32 entropy_poly_decode_8(sc_packer_t *packer, size_t n, SINT8 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist)
{
    if (NULL == packer) {
        return SC_ERROR;
    }

    if (SC_ENTROPY_HUFFMAN_STATIC == type) {
        if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
            return decode_huffman_unsigned_8(packer, n, p, bits - beta, beta);
        }
        else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
            return decode_huffman_signed_8(packer, n, p, bits - beta, beta);
        }
    }
    else {
        if (UNSIGNED_COEFF == signedness) {
            return decode_raw_unsigned_8(packer, n, p, bits);
        }
        else {
            return decode_raw_signed_8(packer, n, p, bits);
        }
    }
}
