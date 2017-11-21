/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file SAFEcrypto.cpp
 * @author n.smyth@qub.ac.uk
 * @date 15 Dec 2016
 * @brief C++ class wrapper for the SAFEcrypto library.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */


#include "SAFEcrypto.hpp"


SAFEcrypto::SAFEcrypto(sc_scheme_e Scheme, SINT32 Set, const UINT32 *Flags)
: m_sc(NULL)
{
	m_sc = safecrypto_create(Scheme, Set, Flags);
}

SAFEcrypto::~SAFEcrypto()
{
	if (m_sc) {
		if (SC_FUNC_SUCCESS == safecrypto_destroy(m_sc)) {
			m_sc = NULL;
		}
	}
}

UINT32 SAFEcrypto::GetVersion()
{
	return safecrypto_get_version();
}

std::string SAFEcrypto::GetVersionString()
{
	const char *version = safecrypto_get_version_string();
	std::string str(version);
	return str;
}

SINT32 SAFEcrypto::SetDebugLevel(sc_debug_level_e level)
{
	return SC_FUNC_SUCCESS;
}

sc_debug_level_e SAFEcrypto::GetDebugLevel()
{
	return SC_LEVEL_NONE;
}

void SAFEcrypto::KeyGen()
{
	safecrypto_keygen(m_sc);
}

SINT32 SAFEcrypto::GetPublicKey(UINT8 **key, size_t *keylen)
{
	return safecrypto_public_key_encode(m_sc, key, keylen);
}

SINT32 SAFEcrypto::GetPrivateKey(UINT8 **key, size_t *keylen)
{
	return safecrypto_private_key_encode(m_sc, key, keylen);
}

SINT32 SAFEcrypto::SetPublicKey(UINT8 *pubkey, size_t keylen)
{
	return safecrypto_public_key_load(m_sc, pubkey, keylen);
}

SINT32 SAFEcrypto::SetPrivateKey(UINT8 *privkey, size_t keylen)
{
	return safecrypto_private_key_load(m_sc, privkey, keylen);
}

SINT32 SAFEcrypto::Encapsulation(UINT8 **Message, size_t *MessageLen,
        UINT8 **Key, size_t *KeyLen)
{
	return safecrypto_encapsulation(m_sc, Message, MessageLen, Key, KeyLen);
}

SINT32 SAFEcrypto::Decapsulation(UINT8 *Message, size_t MessageLen,
        UINT8 **Key, size_t *KeyLen)
{
	return safecrypto_decapsulation(m_sc, Message, MessageLen, Key, KeyLen);
}

SINT32 SAFEcrypto::PublicEncrypt(UINT8 *From, size_t FromLen,
        UINT8 **To, size_t *ToLen)
{
	return safecrypto_public_encrypt(m_sc, FromLen, From, ToLen, To);
}

SINT32 SAFEcrypto::PrivateDecrypt(UINT8 *From, size_t FromLen,
        UINT8 **To, size_t *ToLen)
{
	return safecrypto_private_decrypt(m_sc, FromLen, From, ToLen, To);
}

SINT32 SAFEcrypto::GetSignature(UINT8 *Message, size_t MessageLen,
	UINT8 **Signature, size_t *SignatureLen)
{
	return safecrypto_sign(m_sc, Message, MessageLen,
		Signature, SignatureLen);
}

BOOLEAN SAFEcrypto::VerifySignature(UINT8 *Message, size_t MessageLen,
        UINT8 *Signature, size_t SignatureLen)
{
	return safecrypto_verify(m_sc, Message, MessageLen,
		Signature, SignatureLen);
}
