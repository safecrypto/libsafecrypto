/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file
 * Authenticate Key Exchange functions that simplify the use of such schemes
 * with the SAFEcrypto library.
 * 
 * @author n.smyth@qub.ac.uk
 * @date 20 Oct 2017
 * @brief AKE functions.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#pragma once


#include "safecrypto.h"

/** @brief Generate KEM encapsulation and decapsulation keys, sign the encapsulation key
 *  and create a message for the "B" composed of the encapsulation key and signature.
 *
 *  @param sc_sig The SAFEcrypto signature scheme
 *  @param sc_kem The SAFEcrypto KEM scheme
 *  @param kem The output KEM encapsulation key
 *  @param kem_len The length of the output KEM encapsulation key
 *  @param sig A signature of the output KEM encapsulation key
 *  @param sig_len The length of the signature
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_ake_2way_init(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    UINT8 **kem, size_t *kem_len, UINT8 **sig, size_t *sig_len);

/** @brief Verify the encapsulation key to authenticate "A" and use it to encapsulate a random
 *  secret key, sign the original message and the public/private key encapsulation fields using the
 *  specified hash. Finally create the public component of the key encapsulation, the hash and the
 *  signature to be sent to "A".
 *
 *  @param sc_sig The SAFEcrypto signature scheme
 *  @param sc_kem The SAFEcrypto KEM scheme
 *  @param hash_type The hash to be used
 *  @param kem The input KEM encapsulation key
 *  @param kem_len The length of the input KEM encapsulation key
 *  @param sig A signature of the input KEM encapsulation key
 *  @param sig_len The length of the signature
 *  @param md The output message digest associated with the hash of the random secret key, original message and KEM key
 *  @param md_len The length of the output message digest
 *  @param c The output public KEM key
 *  @param c_len The length of the output public KEM key
 *  @param resp_sig The output response signature of the hash
 *  @param resp_sig_len The length of the output response signature
 *  @param secret The shared random secret key
 *  @param secret_len The length of the shared random secret key
 *  @param secret The shared random secret key
 *  @param secret_len The length of the shared random secret key
 *  @return Returns 1 on successful authentication
 */
extern SINT32 safecrypto_ake_2way_response(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    sc_ake_e ake_type, sc_hash_e hash_type,
    const UINT8 *kem, size_t kem_len, const UINT8 *sig, size_t sig_len,
    UINT8 **md, size_t *md_len, UINT8 **c, size_t *c_len, UINT8 **resp_sig, size_t *resp_sig_len,
    UINT8 **secret, size_t *secret_len);

/** @brief Authenticate "B" and retrieve the random secret key. The response signature is first
 *  authenticated, then the encapsulation key is used to retrieve the random secret key. The hash
 *  is then re-created and compared to the received hash to authenticate "B".
 *
 *  @param sc_sig The SAFEcrypto signature scheme
 *  @param sc_kem The SAFEcrypto KEM scheme
 *  @param hash_type The hash to be used
 *  @param md The input message digest associated with the hash of the random secret key, original message and KEM key
 *  @param md_len The length of the input message digest
 *  @param c The output public KEM key
 *  @param c_len The length of the output public KEM key
 *  @param resp_sig The input response signature of the hash
 *  @param resp_sig_len The length of the input response signature
 *  @param sig A signature of the input KEM encapsulation key
 *  @param sig_len The length of the signature
 *  @param secret The shared random secret key
 *  @param secret_len The length of the shared random secret key
 *  @return Returns 1 on successful authentication
 */
extern SINT32 safecrypto_ake_2way_final(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    sc_ake_e ake_type, sc_hash_e hash_type,
    const UINT8 *md, size_t md_len, const UINT8 *c, size_t c_len, const UINT8 *resp_sig, size_t resp_sig_len,
    const UINT8 *sig, size_t sig_len,
    UINT8 **secret, size_t *secret_len);

