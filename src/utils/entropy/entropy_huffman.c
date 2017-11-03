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
#include "huffman.h"


SINT32 encode_huffman_signed_32(sc_packer_t *packer,
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

SINT32 encode_huffman_unsigned_32(sc_packer_t *packer,
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

SINT32 decode_huffman_signed_32(sc_packer_t *packer,
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

SINT32 decode_huffman_unsigned_32(sc_packer_t *packer,
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

SINT32 encode_huffman_signed_16(sc_packer_t *packer,
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

SINT32 encode_huffman_unsigned_16(sc_packer_t *packer,
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

SINT32 decode_huffman_signed_16(sc_packer_t *packer,
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

SINT32 decode_huffman_unsigned_16(sc_packer_t *packer,
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

SINT32 encode_huffman_signed_8(sc_packer_t *packer,
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

SINT32 encode_huffman_unsigned_8(sc_packer_t *packer,
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

SINT32 decode_huffman_signed_8(sc_packer_t *packer,
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

SINT32 decode_huffman_unsigned_8(sc_packer_t *packer,
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

