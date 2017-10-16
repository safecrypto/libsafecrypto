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

#include "bliss_bac.h"
#include "utils/entropy/bac.h"
#include "utils/entropy/exp_golomb.h"

#include "safecrypto_debug.h"
#include "schemes/sig/bliss_b/bliss_b.h"

#include <math.h>



SINT32 bliss_sig_create_bac(bliss_bac_code_t *bac_code)
{
    bac_code->z1_dist = SC_MALLOC((1 << bac_code->n_z1) * sizeof(UINT64));
    if (NULL == bac_code->z1_dist) {
        return SC_FUNC_FAILURE;
    }
    bac_code->z2_dist = SC_MALLOC((1 << bac_code->n_z2) * sizeof(UINT64));
    if (NULL == bac_code->z2_dist) {
        return SC_FUNC_FAILURE;
    }
    bac_code->g_dist = SC_MALLOC((1 << bac_code->n_g) * sizeof(UINT64));
    if (NULL == bac_code->g_dist) {
        return SC_FUNC_FAILURE;
    }

    gauss_freq_bac_64(bac_code->z1_dist, bac_code->z1_sig, 1 << bac_code->n_z1);
    gauss_freq_bac_64(bac_code->z2_dist, bac_code->z2_sig, 1 << bac_code->n_z2);
    gauss_freq_bac_64(bac_code->g_dist, 0.7f, 1 << bac_code->n_g);

    bac_code->initialized = 1;

    return SC_FUNC_SUCCESS;
}

SINT32 bliss_sig_destroy_bac(bliss_bac_code_t *bac_code)
{
    if (NULL != bac_code->z1_dist) {
        SC_FREE(bac_code->z1_dist, (1 << bac_code->n_z1) * sizeof(UINT64));
    }
    if (NULL != bac_code->z2_dist) {
        SC_FREE(bac_code->z2_dist, (1 << bac_code->n_z2) * sizeof(UINT64));
    }
    if (NULL != bac_code->g_dist) {
        SC_FREE(bac_code->g_dist, (1 << bac_code->n_g) * sizeof(UINT64));
    }

    bac_code->initialized = 0;

    return SC_FUNC_SUCCESS;
}

SINT32 bliss_privkey_encode_bac(sc_packer_t *packer, SINT32 n,
    SINT16 *f, SINT16 *g, SINT32 bits)
{
    size_t i;

    if (NULL == packer) {
        return SC_ERROR;
    }
    sc_entropy_t *coder = (sc_entropy_t *) packer->coder;
    if (NULL == coder) {
        return SC_ERROR;
    }
    bliss_bac_code_t *bac = (bliss_bac_code_t *) coder->entropy_coder;
    if (NULL == bac) {
        return SC_ERROR;
    }

    for (i=0; i<(size_t)n; i++) {
        if (0 == i) {
            g[0]--;
        }
        g[i] >>= 1;
    }

    SINT32 offset = 1 << (bits - 1);

    SINT32 coded_bits = utils_entropy.pack_get_bits(packer);
    if (SC_FUNC_FAILURE == bac_encode_64_16(packer, f, n, bac->g_dist, bits, offset)) {
        goto failure;
    }
    packer->sc->stats.key_bits_coded[0] += utils_entropy.pack_get_bits(packer) - coded_bits;
    coded_bits = utils_entropy.pack_get_bits(packer);
    if (SC_FUNC_FAILURE == bac_encode_64_16(packer, g, n, bac->g_dist, bits, offset)) {
        goto failure;
    }
    packer->sc->stats.key_bits_coded[1] += utils_entropy.pack_get_bits(packer) - coded_bits;

    utils_entropy.pack_flush(packer);

    for (i=0; i<(size_t)n; i++) {
        g[i] <<= 1;
        if (0 == i) {
            g[0]++;
        }
    }

    return SC_OK;

failure:
    for (i=0; i<(size_t)n; i++) {
        g[i] <<= 1;
        if (0 == i) {
            g[0]++;
        }
    }
    return SC_ERROR;
}
SINT32 bliss_privkey_decode_bac(sc_packer_t *packer, SINT32 n,
    SINT16 *f, SINT16 *g, SINT32 bits)
{
    size_t i;

    if (NULL == packer) {
        return SC_ERROR;
    }
    sc_entropy_t *coder = (sc_entropy_t *) packer->coder;
    if (NULL == coder) {
        return SC_ERROR;
    }
    bliss_bac_code_t *bac = (bliss_bac_code_t *) coder->entropy_coder;
    if (NULL == bac) {
        return SC_ERROR;
    }

    SINT32 offset = 1 << (bits - 1);

    if (SC_FUNC_FAILURE == bac_decode_64_16(packer, f, n, bac->g_dist, bits, offset)) {
        return SC_ERROR;
    }
    if (SC_FUNC_FAILURE == bac_decode_64_16(packer, g, n, bac->g_dist, bits, offset)) {
        return SC_ERROR;
    }

    for (i=0; i<(size_t)n; i++) {
        g[i] = 2 * g[i];
        if (0 == i) {
            g[0]++;
        }
    }

    SINT32 num_bits = utils_entropy.pack_get_bits(packer);
    UINT32 value;
    packer->read(packer, &value, num_bits & 0x7);

    return SC_OK;
}

SINT32 bliss_pubkey_encode_bac(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits)
{
    size_t i;
    if (NULL == packer) {
        return SC_ERROR;
    }
    sc_entropy_t *coder = (sc_entropy_t *) packer->coder;
    if (NULL == coder) {
        return SC_ERROR;
    }
    bliss_bac_code_t *bac = (bliss_bac_code_t *) coder->entropy_coder;
    if (NULL == bac) {
        return SC_ERROR;
    }

    SINT32 coded_bits = utils_entropy.pack_get_bits(packer);

    SINT32 *temp = packer->sc->bliss->temp;

    // Write each symbol to the stream as the LSBs truncated and the MSBs BAC encoded
    SINT32 trunc_bits = bits - bac->n_z2;
    SINT32 trunc_mask = (1 << trunc_bits) - 1;
    for (i=0; i<(size_t)n; i++) {
        temp[i] = a[i] >> trunc_bits;
        if (SC_FUNC_FAILURE == packer->write(packer, a[i] & trunc_mask, bits))
        {
            return SC_ERROR;
        }
    }

    // Now code the MSBs using the BAC
    if (SC_FUNC_FAILURE == bac_encode_64_32(packer, temp, n, bac->z2_dist, bac->n_z2, 0)) {
        return SC_ERROR;
    }

    packer->sc->stats.key_bits_coded[3] += utils_entropy.pack_get_bits(packer) - coded_bits;
    utils_entropy.pack_flush(packer);

    // Clear the keying data from temporary memory
    SC_MEMZERO(temp, n * sizeof(SINT32));

    return SC_OK;
}

SINT32 bliss_pubkey_decode_bac(sc_packer_t *packer, SINT32 n, SINT16 *a, SINT32 bits)
{
    (void) packer;
    (void) n;
    (void) a;
    (void) bits;
    return SC_FUNC_SUCCESS;
}

SINT32 bliss_sig_encode_bac(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    if (NULL == packer) {
        return SC_ERROR;
    }
    sc_entropy_t *coder = (sc_entropy_t *) packer->coder;
    if (NULL == coder) {
        return SC_ERROR;
    }
    bliss_bac_code_t *bac = (bliss_bac_code_t *) coder->entropy_coder;
    if (NULL == bac) {
        return SC_ERROR;
    }


    SINT32 offset = 1 << (z1_bits - 1);
    SINT32 coded_bits = utils_entropy.pack_get_bits(packer);
    if (SC_FUNC_FAILURE == bac_encode_64_32(packer, z1, n, bac->z1_dist, z1_bits, offset)) {
        return SC_ERROR;
    }
    packer->sc->stats.sig_bits_coded[0] += utils_entropy.pack_get_bits(packer) - coded_bits;

    offset = 1 << (z2_bits - 1);
    coded_bits = utils_entropy.pack_get_bits(packer);
    if (SC_FUNC_FAILURE == bac_encode_64_32(packer, z2, n, bac->z2_dist, z2_bits, offset)) {
        return SC_ERROR;
    }
    packer->sc->stats.sig_bits_coded[1] += utils_entropy.pack_get_bits(packer) - coded_bits;

    utils_entropy.pack_flush(packer);

    return SC_OK;
}

SINT32 bliss_sig_decode_bac(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    //size_t i;
    if (NULL == packer) {
        return SC_ERROR;
    }
    sc_entropy_t *coder = (sc_entropy_t *) packer->coder;
    if (NULL == coder) {
        return SC_ERROR;
    }
    bliss_bac_code_t *bac = (bliss_bac_code_t *) coder->entropy_coder;
    if (NULL == bac) {
        return SC_ERROR;
    }

    SINT32 offset = 1 << (z1_bits - 1);
    if (SC_FUNC_FAILURE == bac_decode_64_32(packer, z1, n, bac->z1_dist, z1_bits, offset)) {
        return SC_ERROR;
    }
    offset = 1 << (z2_bits - 1);
    if (SC_FUNC_FAILURE == bac_decode_64_32(packer, z2, n, bac->z2_dist, z2_bits, offset)) {
        return SC_ERROR;
    }

    SINT32 num_bits = utils_entropy.pack_get_bits(packer);
    UINT32 value;
    packer->read(packer, &value, num_bits & 0x7);

    return SC_OK;
}

SINT32 bliss_sig_encode_bac_expg(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    size_t i;
    if (NULL == packer) {
        return SC_ERROR;
    }
    sc_entropy_t *coder = (sc_entropy_t *) packer->coder;
    if (NULL == coder) {
        return SC_ERROR;
    }
    bliss_bac_code_t *bac = (bliss_bac_code_t *) coder->entropy_coder;
    if (NULL == bac) {
        return SC_ERROR;
    }

    SINT32 offset = 1 << (z1_bits - 1);
    SINT32 coded_bits = utils_entropy.pack_get_bits(packer);
    if (SC_FUNC_FAILURE == bac_encode_64_32(packer, z1, n, bac->z1_dist, z1_bits, offset)) {
        return SC_ERROR;
    }
    packer->sc->stats.sig_bits_coded[0] += utils_entropy.pack_get_bits(packer) - coded_bits;
    coded_bits = utils_entropy.pack_get_bits(packer);
    utils_entropy.pack_flush(packer);

    for (i=0; i<(size_t)n; i++) {
        // Write the symbol to the stream
        if (SC_FUNC_FAILURE == packer->write(packer, z2[i], z2_bits))
        {
            return SC_ERROR;
        }
        SC_PRINT_DEBUG(packer->sc, "%d, z2: %X [%d]", (int)i, z2[i], z2_bits);

        if (0 == z2[i]) {
            // Advance to the next symbol with a different value
            size_t j = i + 1;
            while (j < (size_t)n && z2[i] == z2[j]) {
                j++;
            }
            UINT8 runlength = j - i - 1;
            i = j - 1;

            // Send j as an Exp-Golomb code
            UINT32 code;
            SINT32 bits;
            exp_golomb_encode(runlength, &code, &bits);
            if (SC_FUNC_FAILURE == packer->write(packer, code, bits))
            {
                return SC_ERROR;
            }
            SC_PRINT_DEBUG(packer->sc, ", runlength: %d (%X [%d])\n", runlength, code, bits);
        }
        else {
            SC_PRINT_DEBUG(packer->sc, "\n");
        }
    }
    packer->sc->stats.sig_bits_coded[1] += utils_entropy.pack_get_bits(packer) - coded_bits;

    return SC_OK;
}

SINT32 bliss_sig_decode_bac_expg(sc_packer_t *packer, SINT32 n, SINT32 *z1, SINT32 z1_bits,
    SINT32 *z2, SINT32 z2_bits)
{
    size_t i;
    UINT32 sign, sign_extension, value;
    sign           = 1 << (z2_bits - 1);
    sign_extension = ((1 << (32 - z2_bits)) - 1) << z2_bits;

    if (NULL == packer) {
        return SC_ERROR;
    }
    sc_entropy_t *coder = (sc_entropy_t *) packer->coder;
    if (NULL == coder) {
        return SC_ERROR;
    }
    bliss_bac_code_t *bac = (bliss_bac_code_t *) coder->entropy_coder;
    if (NULL == bac) {
        return SC_ERROR;
    }

    SINT32 offset = 1 << (z1_bits - 1);
    if (SC_FUNC_FAILURE == bac_decode_64_32(packer, z1, n, bac->z1_dist, z1_bits, offset)) {
        return SC_ERROR;
    }

    SINT32 num_bits = utils_entropy.pack_get_bits(packer);
    packer->read(packer, &value, num_bits & 0x7);

    for (i=0; i<(size_t)n; i++) {
        // Read the symbol
        if (SC_FUNC_FAILURE == packer->read(packer, &value, z2_bits)) {
            return SC_ERROR;
        }
        z2[i] = (value & sign)? sign_extension | value : value;
        SC_PRINT_DEBUG(packer->sc, "%d, z2: %X [%d], ", (int)i, z2[i], z2_bits);

        if (0 == z2[i]) {
            // Read the run-length as an Exp-Golomb code
            UINT32 code = 0;
            SINT32 bits = 0;
            UINT8  runlength;
            while (0 == code) {
                if (SC_FUNC_FAILURE == packer->read(packer, &code, 1)) {
                    return SC_ERROR;
                }
                bits++;
            }
            if (SC_FUNC_FAILURE == packer->read(packer, &code, bits - 1)) {
                return SC_ERROR;
            }
            code |= 1 << (bits - 1);
            runlength = exp_golomb_decode(code);
    
            SC_PRINT_DEBUG(packer->sc, "runlength: %d (%X [%d])\n", runlength, code, 2*bits - 1);
    
            // Advance to the next symbol with a different value
            size_t j = i + runlength;
            while (runlength) {
                z2[i+runlength] = z2[i];
                runlength--;
            }
            i = j;
        }
    }

    return SC_OK;
}


