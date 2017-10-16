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

#include "bliss_huffman_static.h"
#include "utils/entropy/huffman.h"


#define HUFFMAN_STATIC_BETA        7
#define HUFFMAN_STATIC_TABLE       huff_table_gaussian_4

SINT32 bliss_sig_encode_huffman_static(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    (void) z1_bits;

    size_t i;
    UINT32 value, sign;
    SINT32 beta = HUFFMAN_STATIC_BETA;
    SINT32 mask = (1 << beta) - 1;
    const huffman_table_t *table_z1 = HUFFMAN_STATIC_TABLE;
    const huffman_table_t *table_z2 = (7 == z2_bits)? huff_table_gaussian_6 :
                                      (6 == z2_bits)? huff_table_gaussian_5 :
                                      (5 == z2_bits)? huff_table_gaussian_4 :
                                      (4 == z2_bits)? huff_table_gaussian_3 :
                                                      huff_table_gaussian_2;

    SINT32 coded_bits = utils_entropy.pack_get_bits(packer);
    for (i=0; i<(size_t)n; i++) {
        // Write z1_bits for each z1 symbol to the stream
        sign  = (z1[i] < 0)? 1 : 0;
        value = (sign)? -z1[i] : z1[i];
        if (SC_FUNC_FAILURE == packer->write(packer, value & mask, beta)) {
            return SC_ERROR;
        }
        value >>= beta;
        if (SC_OK != encode_huffman(packer, table_z1, value)) {
            return SC_ERROR;
        }
        if (0 != z1[i]) {
            if (SC_FUNC_FAILURE == packer->write(packer, sign, 1)) {
                return SC_ERROR;
            }
        }
    }
    packer->sc->stats.sig_bits_coded[0] += utils_entropy.pack_get_bits(packer) - coded_bits;

    coded_bits = utils_entropy.pack_get_bits(packer);
    for (i=0; i<(size_t)n; i++) {
        // Write z2_bits for each z2 symbol to the stream
        sign  = (z2[i] < 0)? 1 : 0;
        value = (sign)? -z2[i] : z2[i];
        if (SC_OK != encode_huffman(packer, table_z2, value)) {
            return SC_ERROR;
        }
        if (0 != value) {
            if (SC_FUNC_FAILURE == packer->write(packer, sign, 1)) {
                return SC_ERROR;
            }
        }
    }
    packer->sc->stats.sig_bits_coded[1] += utils_entropy.pack_get_bits(packer) - coded_bits;

    return SC_OK;
}

SINT32 bliss_sig_decode_huffman_static(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    (void) z1_bits;

    size_t i;
    UINT32 sign, value;
    SINT32 beta = HUFFMAN_STATIC_BETA;
    const huffman_table_t *table_z1 = HUFFMAN_STATIC_TABLE;
    const huffman_table_t *table_z2 = (7 == z2_bits)? huff_table_gaussian_6 :
                                      (6 == z2_bits)? huff_table_gaussian_5 :
                                      (5 == z2_bits)? huff_table_gaussian_4 :
                                      (4 == z2_bits)? huff_table_gaussian_3 :
                                                      huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<(size_t)n; i++) {
        // Obtain the z1 sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, beta)) {
            return SC_ERROR;
        }
        if (SC_OK != decode_huffman(packer, table_z1, &sign)) {
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
        z1[i] = value;
        z1[i] = (sign)? -z1[i] : z1[i];
    }

    for (i=0; i<(size_t)n; i++) {
        // Obtain the z2 sign bit, create a mask for sign extension and read the raw bits
        if (SC_OK != decode_huffman(packer, table_z2, &value))
        {
            return SC_ERROR;
        }
        if (0 != value) {
            if (SC_FUNC_FAILURE == packer->read(packer, &sign, 1)) {
                return SC_ERROR;
            }
        }
        else {
            sign = 0;
        }
        z2[i] = value;
        z2[i] = (sign)? -z2[i] : z2[i];
    }

    return SC_OK;
}


SINT32 bliss_pubkey_encode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits)
{
    (void) packer;
    (void) n;
    (void) a;
    (void) bits;

    size_t i;
    UINT32 value;
    const huffman_table_t *table = huff_table_gaussian_6;

    SINT32 coded_bits = utils_entropy.pack_get_bits(packer);
    for (i=0; i<(size_t)n; i++) {

        // Truncate and send the least significant bits
        value = a[i] & 0xFF;
        if (SC_FUNC_FAILURE == packer->write(packer, value, 8)) {
            return SC_ERROR;
        }

        // Huffman code the most significant bits
        value = a[i] >> 8;
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }
    }
    packer->sc->stats.key_bits_coded[3] += utils_entropy.pack_get_bits(packer) - coded_bits;

    return SC_OK;
}

SINT32 bliss_pubkey_decode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits)
{
    (void) packer;
    (void) n;
    (void) a;
    (void) bits;

    return SC_OK;
}


SINT32 bliss_privkey_encode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *f,
    SINT16 *g, SINT32 bits)
{
    (void) bits;

    size_t i;
    UINT32 sign, value;
    SINT16 g2;
    const huffman_table_t *table = huff_table_gaussian_2;

    for (i=0; i<(size_t)n; i++) {

        SINT32 coded_bits = utils_entropy.pack_get_bits(packer);

        // Write bits for each f symbol to the stream
        sign  = (f[i] < 0)? 1 : 0;
        value = (sign)? -f[i] : f[i];
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }

        if (0 != f[i]) {
            if (SC_FUNC_FAILURE == packer->write(packer, sign, 1)) {
                return SC_ERROR;
            }
        }

        packer->sc->stats.key_bits_coded[0] += utils_entropy.pack_get_bits(packer) - coded_bits;
        coded_bits = utils_entropy.pack_get_bits(packer);

        // Write bits for each g symbol to the stream
        g2 = g[i];
        if (0 == i) {
            g2--;
        }
        g2 >>= 1;
        sign  = (g2 < 0)? 1 : 0;
        value = (sign)? -g2 : g2;
        if (SC_OK != encode_huffman(packer, table, value)) {
            return SC_ERROR;
        }

        if (0 != g2) {
            if (SC_FUNC_FAILURE == packer->write(packer, sign, 1)) {
                return SC_ERROR;
            }
        }

        packer->sc->stats.key_bits_coded[1] += utils_entropy.pack_get_bits(packer) - coded_bits;
    }

    return SC_OK;
}

SINT32 bliss_privkey_decode_huffman_static(sc_packer_t *packer, SINT32 n, SINT16 *f,
    SINT16 *g, SINT32 bits)
{
    (void) bits;

    size_t i;
    UINT32 sign, value;
    const huffman_table_t *table = huff_table_gaussian_2;

    // Iterate through each symbol
    for (i=0; i<(size_t)n; i++) {

        // Obtain the f Huffman code, if is is non-zero then retrieve the sign bit and reconstruct
        if (SC_OK != decode_huffman(packer, table, &value)) {
            return SC_ERROR;
        }

        if (0 != value) {
            if (SC_FUNC_FAILURE == packer->read(packer, &sign, 1)) {
                return SC_ERROR;
            }
        }
        else {
            sign = 0;
        }

        f[i] = (sign)? -value : value;

        // Obtain the g Huffman code, if is is non-zero then retrieve the sign bit and reconstruct
        if (SC_OK != decode_huffman(packer, table, &value)) {
            return SC_ERROR;
        }

        if (0 != value) {
            if (SC_FUNC_FAILURE == packer->read(packer, &sign, 1)) {
                return SC_ERROR;
            }
        }
        else {
            sign = 0;
        }

        g[i] = (sign)? -value : value;

        // Perform addition coding to retrieve the g symbol
        g[i] = 2 * g[i];
        if (0 == i) {
            g[0]++;
        }
    }

    return SC_OK;
}

