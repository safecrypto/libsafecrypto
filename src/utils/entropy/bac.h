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
#include "packer.h"


UINT64 mul64hi(UINT64 x, UINT64 y);

#ifdef HAVE_64BIT
SINT32 gauss_freq_bac_64(UINT64 *dist, FLOAT sig, size_t n);
#endif


/** @brief Obtain a distribution based on the frequency of occurrence (64-bit).
 *
 *  @param dist The output distribution
 *  @param freq The input frequency of occurrence
 *  @param n The length of the input and output arrays
 */
void bac_distfreq_64(UINT64 *dist, UINT64 *freq, size_t n);

/** @brief Obtain a distribution based on the frequency of occurrence (64-bit).
 *
 *  @param packer A pointer to a packer instance
 *  @param in The message to be compressed
 *  @param inlen The length of the input message
 *  @param dist The symbol distribution
 *  @param bits The number of bits per uncoded symbol
 *  @return SC_FUNC_SUCCESS indicates success, SC_FUNC_FAILURE otherwise
 */
SINT32 bac_encode_64_32(sc_packer_t *packer, const SINT32 *in, size_t inlen,
	const UINT64 *dist, SINT32 bits, SINT32 offset);

/** @brief Obtain a distribution based on the frequency of occurrence (64-bit).
 *
 *  @param packer A pointer to a packer instance
 *  @param out The message to be decompressed
 *  @param outlen The length of the output message
 *  @param dist The symbol distribution
 *  @param bits The number of bits per uncoded symbol
 *  @return SC_FUNC_SUCCESS indicates success, SC_FUNC_FAILURE otherwise
 */
SINT32 bac_decode_64_32(sc_packer_t *packer, SINT32 *out, size_t outlen,
    const UINT64 *dist, SINT32 bits, SINT32 offset);

/** @brief Obtain a distribution based on the frequency of occurrence (64-bit).
 *
 *  @param packer A pointer to a packer instance
 *  @param in The message to be compressed
 *  @param inlen The length of the input message
 *  @param dist The symbol distribution
 *  @param bits The number of bits per uncoded symbol
 *  @return SC_FUNC_SUCCESS indicates success, SC_FUNC_FAILURE otherwise
 */
SINT32 bac_encode_64_16(sc_packer_t *packer, const SINT16 *in, size_t inlen,
	const UINT64 *dist, SINT32 bits, SINT32 offset);

/** @brief Obtain a distribution based on the frequency of occurrence (64-bit).
 *
 *  @param packer A pointer to a packer instance
 *  @param out The message to be decompressed
 *  @param outlen The length of the output message
 *  @param dist The symbol distribution
 *  @param bits The number of bits per uncoded symbol
 *  @return SC_FUNC_SUCCESS indicates success, SC_FUNC_FAILURE otherwise
 */
SINT32 bac_decode_64_16(sc_packer_t *packer, SINT16 *out, size_t outlen,
    const UINT64 *dist, SINT32 bits, SINT32 offset);
