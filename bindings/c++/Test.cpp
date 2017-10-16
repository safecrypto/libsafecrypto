/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file Test.cpp
 * @author n.smyth@qub.ac.uk
 * @date 15 Dec 2016
 * @brief Test application for the C++ SAFEcrypto class wrapper.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */


#include "SAFEcrypto.hpp"

#include <iostream>
#include <iomanip>

int main(int argc, char *argv[])
{
	fprintf(stderr, "SAFEcrypto C++ Wrapper Class\n");

	// Obtain version numbers without creating an instance
	UINT32 Version = SAFEcrypto::GetVersion();
	std::string VersionString = SAFEcrypto::GetVersionString();
	std::cout << "Version 0x" <<
	    std::hex << std::setfill('0') << std::setw(8) << Version << "   (" <<
		std::dec << VersionString << ")" << std::endl << std::endl;

	// Create an instance for BLISS-B
	UINT32 Flags[1] = {SC_FLAG_NONE};
	SAFEcrypto SC_static(SC_SCHEME_SIG_BLISS, 4, Flags);

	// Create a dynamic instance and destroy it
	SAFEcrypto *SC = new SAFEcrypto(SC_SCHEME_SIG_BLISS, 4, Flags);

	UINT8 *pubkey = NULL, *privkey = NULL;
	size_t pubkey_len = 0, privkey_len = 0;
	SC->KeyGen();
	if (SC_FUNC_SUCCESS != SC->GetPublicKey(&pubkey, &pubkey_len)) {
		return EXIT_FAILURE;
	}
	if (SC_FUNC_SUCCESS != SC->GetPrivateKey(&privkey, &privkey_len)) {
		return EXIT_FAILURE;
	}

	std::cout << "Public Key (No entropy coding, " << pubkey_len << " bytes)" << std::endl << "    ";
	for (size_t i=0; i<pubkey_len; i++) {
		std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)pubkey[i] << " ";
		if ((i & 0x1F) == 0x1F) {
			std::cout << std::endl << "    ";
		}
	}
	std::cout << std::dec << std::endl;

	delete SC;
	if (pubkey) {
		delete pubkey;
		pubkey = NULL;
	}
	if (privkey) {
		delete privkey;
		privkey = NULL;
	}
	pubkey_len = 0;
	privkey_len = 0;

	Flags[0] = SC_FLAG_0_ENTROPY_HUFFMAN_STATIC;
	SAFEcrypto *SC2 = new SAFEcrypto(SC_SCHEME_SIG_BLISS, 4, Flags);
	SC2->KeyGen();
	if (SC_FUNC_SUCCESS != SC2->GetPublicKey(&pubkey, &pubkey_len)) {
		return EXIT_FAILURE;
	}
	if (SC_FUNC_SUCCESS != SC2->GetPrivateKey(&privkey, &privkey_len)) {
		return EXIT_FAILURE;
	}

	std::cout << "Public Key (Huffman coded, " << pubkey_len << " bytes)" << std::endl << "    ";
	for (size_t i=0; i<pubkey_len; i++) {
		std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)pubkey[i] << " ";
		if ((i & 0x1F) == 0x1F) {
			std::cout << std::endl << "    ";
		}
	}
	std::cout << std::endl;

	delete SC2;

	return EXIT_SUCCESS;
}

