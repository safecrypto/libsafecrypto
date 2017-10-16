/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file SAFEcrypto.hpp
 * @author n.smyth@qub.ac.uk
 * @date 15 Dec 2016
 * @brief C++ header file for the SAFEcrypto library.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */


#pragma once

#include <cstdlib>
#include "safecrypto.h"

#include <string>


class SAFEcrypto
{
private:
	safecrypto_t *m_sc;

public:
	SAFEcrypto(sc_scheme_e Scheme, SINT32 Set, const UINT32 *Flags);
	virtual ~SAFEcrypto();

	static UINT32 GetVersion();
    static std::string GetVersionString();

    SINT32 SetDebugLevel(sc_debug_level_e level);
    sc_debug_level_e GetDebugLevel();

    void KeyGen();
    SINT32 GetPublicKey(UINT8 **key, size_t *keylen);
    SINT32 GetPrivateKey(UINT8 **key, size_t *keylen);
    SINT32 SetPublicKey(UINT8 *pubkey, size_t keylen);
    SINT32 SetPrivateKey(UINT8 *privkey, size_t keylen);

    SINT32 Encapsulation(UINT8 **Message, size_t *MessageLen,
        UINT8 **Key, size_t *KeyLen);
    SINT32 Decapsulation(UINT8 *Message, size_t MessageLen,
        UINT8 **Key, size_t *KeyLen);

    SINT32 PublicEncrypt(UINT8 *From, size_t FromLen,
        UINT8 **To, size_t *ToLen);
    SINT32 PrivateDecrypt(UINT8 *From, size_t FromLen,
        UINT8 **To, size_t *ToLen);

    SINT32 GetSignature(UINT8 *Message, size_t MessageLen,
        UINT8 **Signature, size_t *SignatureLen);
    BOOLEAN VerifySignature(UINT8 *Message, size_t MessageLen,
        UINT8 *Signature, size_t SignatureLen);
};

