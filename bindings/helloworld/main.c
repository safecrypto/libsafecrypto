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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "safecrypto.h"


#define APP_NAME   "SAFEcrypto software reference"
#define COPYRIGHT  "(C) SAFEcrypto 2016"


int helloworld_test(sc_debug_level_e level)
{
	int retcode = SC_FUNC_SUCCESS;
	safecrypto_t *sc;
	uint8_t m[4] = {0x00, 0x01, 0x02, 0x03};
	int32_t m_len = 4;
	uint8_t *sig;
	size_t siglen, c_len, k_len;
	size_t f_len = 0, o_len;
	int32_t i;
	uint8_t *c;
	uint8_t *k, *c2;

	// Create a pointer to a safecrypto struct, verifying that it is non-NULL.
	// Key generation is performed for a private-key.
	if ((sc = safecrypto_create(SC_SCHEME_SIG_HELLO_WORLD, 0, 0)) == NULL) {
		fprintf(stderr, "Cannot create a SAFEcrypto object\n");
		return SC_FUNC_FAILURE; // Cannot instantiate a SAFEcrypto object
	}

	// Set the desired debug verboseness
	if ((retcode = safecrypto_set_debug_level(sc, level)) != SC_FUNC_SUCCESS) {
		fprintf(stderr, "Setting the debug level has failed\n");
		goto finish;
	}

	// Verify that keys can be generated
	if ((retcode = safecrypto_keygen(sc)) != SC_FUNC_FAILURE) {
		fprintf(stderr, "The 'Hello World' algorithm does not support key pair generation\n");
		goto finish;
	}

	// Verify that a key encapsulation function is not available
	if ((retcode = safecrypto_encapsulation(sc, &c, &c_len, &k, &k_len)) != SC_FUNC_FAILURE) {
		fprintf(stderr, "The 'Hello World' algorithm does not support key encapsulation\n");
		goto finish;
	}

	// Verify that a key decapsulation function is not available
	if ((retcode = safecrypto_decapsulation(sc, c, c_len, &k, &k_len)) != SC_FUNC_FAILURE) {
		fprintf(stderr, "The 'Hello World' algorithm does not support key decapsulation\n");
		goto finish;
	}

	// Verify that an encryption function is not available
	if ((retcode = safecrypto_public_encrypt(sc, f_len, c, &o_len, &k)) != SC_FUNC_FAILURE) {
		fprintf(stderr, "The 'Hello World' algorithm does not support public key encryption\n");
		goto finish;
	}

	// Verify that a decryption function is not available
	if ((retcode = safecrypto_private_decrypt(sc, f_len, k, &o_len, &c2)) != SC_FUNC_FAILURE) {
		fprintf(stderr, "The 'Hello World' algorithm does not support private key decryption\n");
		goto finish;
	}

	free(k);
	free(c2);

	// Verify that a signature function is available
	if ((retcode = safecrypto_sign(sc, m, m_len, &sig, &siglen)) != SC_FUNC_SUCCESS) {
		fprintf(stderr, "Cannot create a signature using the 'Hello World' algorithm\n");
		goto finish;
	}

	// Verify that the signature verification function is available
	if ((retcode = safecrypto_verify(sc, m, m_len, sig, siglen)) != SC_FUNC_SUCCESS) {
		fprintf(stderr, "Cannot verify a signature using the 'Hello World' algorithm\n");
		goto finish;
	}

finish:
	// Five SC_INVALID_FUNCTION_CALL errors should be present in the error queue
	for (i=0; i<5; i++) {
		uint32_t errcode;
		if ((errcode = safecrypto_err_get_error(sc)) != SC_INVALID_FUNCTION_CALL) {
			fprintf(stderr, "Incorrect error logged, expected SC_INVALID_FUNCTION_CALL got CODE: %d\n", errcode);
			retcode = SC_FUNC_FAILURE;
		}
	}
	if (safecrypto_err_get_error(sc) != 0) {
		fprintf(stderr, "There where additional error messages in the error queue\n");
		retcode = SC_FUNC_FAILURE;
	}

	// Verify that destruction is successful
	if (safecrypto_destroy(sc) != SC_FUNC_SUCCESS) {
		fprintf(stderr, "SAFEcrypto object resources cannot be freed\n");
		return SC_FUNC_FAILURE;
	}

	return retcode;
}



int main( int argc, char** argv )
{
	int errval = 0;

	printf( "%s ", APP_NAME );
	printf( "[version %s]\n", safecrypto_get_version_string() );
	printf( "%s\n\n", COPYRIGHT );
	printf( "This is a test executable for the build system and API.\n" );

	// Execute the helloworld test to verify the API functionality
	printf("\nSetting the debug level to SC_LEVEL_DEBUG\n");
	errval = helloworld_test(SC_LEVEL_DEBUG);
	if (errval != SC_FUNC_SUCCESS) {
		printf("Error: %08X\n", errval);
		goto finish;
	}
	printf("\nSetting the debug level to SC_LEVEL_INFO\n");
	errval = helloworld_test(SC_LEVEL_INFO);
	if (errval != SC_FUNC_SUCCESS) {
		printf("Error: %08X\n", errval);
		goto finish;
	}
	printf("\nSetting the debug level to SC_LEVEL_WARNING\n");
	errval = helloworld_test(SC_LEVEL_WARNING);
	if (errval != SC_FUNC_SUCCESS) {
		printf("Error: %08X\n", errval);
		goto finish;
	}
	printf("\nSetting the debug level to SC_LEVEL_ERROR\n");
	errval = helloworld_test(SC_LEVEL_ERROR);
	if (errval != SC_FUNC_SUCCESS) {
		printf("Error: %08X\n", errval);
		goto finish;
	}
	printf("\nSetting the debug level to SC_LEVEL_NONE\n");
	errval = helloworld_test(SC_LEVEL_NONE);
	if (errval != SC_FUNC_SUCCESS) {
		printf("Error: %08X\n", errval);
		goto finish;
	}

	printf("\nAll tests passed\n");

finish:
	return errval;
}


