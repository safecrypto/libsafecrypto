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

#include "bliss_raw.h"


SINT32 bliss_sig_encode_raw(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    size_t i;

    for (i=0; i<(size_t)n; i++) {
        // Write z1_bits for each z1 symbol to the stream
        if (SC_FUNC_FAILURE == packer->write(packer, z1[i], z1_bits))
        {
            return SC_ERROR;
        }

        // Write z2_bits for each z2 symbol to the stream
        if (SC_FUNC_FAILURE == packer->write(packer, z2[i], z2_bits))
        {
            return SC_ERROR;
        }
    }

    // Record the coded bit statistics for z1 and z2
    packer->sc->stats.sig_bits_coded[0] += n * z1_bits;
    packer->sc->stats.sig_bits_coded[1] += n * z2_bits;

    return SC_OK;
}

SINT32 bliss_sig_decode_raw(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    size_t i;
    UINT32 sign, sign_extension, value;

    // Iterate through each symbol
    for (i=0; i<(size_t)n; i++) {

        // Obtain the z1 sign bit, create a mask for sign extension and read the raw bits
        sign           = 1 << (z1_bits - 1);
        sign_extension = ((1 << (32 - z1_bits)) - 1) << z1_bits;
        if (SC_FUNC_FAILURE == packer->read(packer, &value, z1_bits))
        {
            return SC_ERROR;
        }
        z1[i] = (value & sign)? sign_extension | value : value;

        // Obtain the z2 sign bit, create a mask for sign extension and read the raw bits
        sign           = 1 << (z2_bits - 1);
        sign_extension = ((1 << (32 - z2_bits)) - 1) << z2_bits;
        if (SC_FUNC_FAILURE == packer->read(packer, &value, z2_bits))
        {
            return SC_ERROR;
        }
        z2[i] = (value & sign)? sign_extension | value : value;
    }

    return SC_OK;
}

SINT32 bliss_pubkey_encode_raw(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits)
{
    size_t i;

    for (i=0; i<(size_t)n; i++) {
        // Write bits for each a symbol to the stream
        if (SC_FUNC_FAILURE == packer->write(packer, a[i], bits))
        {
            return SC_ERROR;
        }
    }

    // Record the coded bit statistics for a
    packer->sc->stats.key_bits_coded[3] += n * bits;

    return SC_OK;
}

SINT32 bliss_pubkey_decode_raw(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits)
{
    size_t i;
    UINT32 value;

    // Iterate through each symbol
    for (i=0; i<(size_t)n; i++) {

        // Obtain the raw bits of the public key a
        if (SC_FUNC_FAILURE == packer->read(packer, &value, bits))
        {
            return SC_ERROR;
        }
        a[i] = (SINT16) value;
    }

    return SC_OK;
}

SINT32 bliss_privkey_encode_raw(sc_packer_t *packer, SINT32 n, SINT16 *f,
    SINT16 *g, SINT32 bits)
{
    size_t i;
    UINT32 value;

    for (i=0; i<(size_t)n; i++) {
        // Write bits for each f symbol to the stream
        if (SC_FUNC_FAILURE == packer->write(packer, f[i], bits))
        {
            return SC_ERROR;
        }

        // Write bits for each g symbol to the stream
        value = g[i];
        if (0 == i) {
            value--;
        }
        value >>= 1;
        if (SC_FUNC_FAILURE == packer->write(packer, value, bits))
        {
            return SC_ERROR;
        }
    }

    // Record the coded bit statistics for f and g
    packer->sc->stats.key_bits_coded[0] += n * bits;
    packer->sc->stats.key_bits_coded[1] += n * bits;

    return SC_OK;
}

SINT32 bliss_privkey_decode_raw(sc_packer_t *packer, SINT32 n, SINT16 *f,
    SINT16 *g, SINT32 bits)
{
    size_t i;
    UINT32 sign, sign_extension, value;

    // Iterate through each symbol
    for (i=0; i<(size_t)n; i++) {

        // Obtain the f sign bit, create a mask for sign extension and read the raw bits
        sign           = 1 << (bits - 1);
        sign_extension = ((1 << (32 - bits)) - 1) << bits;
        if (SC_FUNC_FAILURE == packer->read(packer, &value, bits))
        {
            return SC_ERROR;
        }
        f[i] = (value & sign)? sign_extension | value : value;

        // Obtain the g sign bit, create a mask for sign extension and read the raw bits
        if (SC_FUNC_FAILURE == packer->read(packer, &value, bits))
        {
            return SC_ERROR;
        }
        g[i] = (value & sign)? sign_extension | value : value;
        g[i] = 2 * g[i];
        if (0 == i) {
            g[0]++;
        }
    }

    return SC_OK;
}

