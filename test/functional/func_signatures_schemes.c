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
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/crypto/prng.h"

#include <string.h>


#define MAX_ITER      1

#define USE_FIXED_BUFFERS     1
#if USE_FIXED_BUFFERS == 1
#define FIXED_BUFFER_SIZE     8192
#else
#define FIXED_BUFFER_SIZE     0
#endif


void show_progress(char *msg, int32_t count, int32_t max)
{
    int i;
    int barWidth = 50;
    double progress = (double) count / max;

    printf("%-20s [", msg);
    int pos = barWidth * progress;
    for (i = 0; i < barWidth; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %4d/%4d (%3d %%)\r", count, max, (int)(progress * 100.0f));
    if (count == max) printf("\n");
    fflush(stdout);
}

int main(void)
{
    safecrypto_t *sc = NULL;

#ifdef DISABLE_SIGNATURES
    UINT32 flags[2] = {SC_FLAG_NONE, SC_FLAG_NONE};

    sc = safecrypto_create(SC_SCHEME_SIG_BLISS, 0, flags);
    if (NULL != sc) {
        fprintf(stderr, "ERROR! safecrypto_create() succeeded but the scheme has been disabled\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
#else
    SINT32 i, j, k;
    UINT8 message[8192];
    size_t length = 64;
    size_t siglen = 0, pubkeylen = 0, privkeylen = 0;
#if USE_FIXED_BUFFERS
    UINT8 *fixed_buffer = malloc(FIXED_BUFFER_SIZE*3);
    UINT8 *sig = fixed_buffer;
    UINT8 *pubkey = fixed_buffer + FIXED_BUFFER_SIZE;
    UINT8 *privkey = fixed_buffer + 2*FIXED_BUFFER_SIZE;
#else
    UINT8 *sig = NULL, *pubkey, *privkey;
#endif
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM,
        SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    if (NULL == prng_ctx) {
        fprintf(stderr, "ERROR! Could not create prng_ctx_t\n");
        goto error_return;
    }

    UINT32 flags[2] = {SC_FLAG_MORE, SC_FLAG_1_CSPRNG_AES_CTR_DRBG};
    sc_entropy_type_e coding = SC_ENTROPY_NONE;

    char disp_msg[128];

    for (k=0; k<6; k++) {
        size_t min_set = 0, max_set = 0;
        sc_scheme_e scheme;
        switch (k) {
#ifdef DISABLE_SIG_BLISS_B
            case 0: continue;
#else
            case 0: scheme = SC_SCHEME_SIG_BLISS; min_set = 1; max_set = 4; break;
#endif
#ifdef DISABLE_SIG_RING_TESLA
            case 1: continue;
#else
            case 1: scheme = SC_SCHEME_SIG_RING_TESLA; min_set = 0; max_set = 1; break;
#endif
#ifdef DISABLE_SIG_ENS
            case 2: continue;
#else
            case 2: scheme = SC_SCHEME_SIG_ENS; min_set = 0; max_set = 1; break;
#endif
#ifdef DISABLE_SIG_DLP
            case 3: continue;
#else
            case 3: scheme = SC_SCHEME_SIG_DLP; min_set = 0; max_set = 1; break;
#endif
#ifdef DISABLE_SIG_DILITHIUM
            case 4: continue;
#else
            case 4: scheme = SC_SCHEME_SIG_DILITHIUM; min_set = 0; max_set = 3; break;
#endif
#ifdef DISABLE_SIG_DILITHIUM_G
            case 5: continue;
#else
            case 5: scheme = SC_SCHEME_SIG_DILITHIUM_G; min_set = 0; max_set = 3; break;
#endif
        }

        for (i=min_set; i<=max_set; i++) {

            snprintf(disp_msg, 128, "%-26s", sc_scheme_names[scheme]);

            // Create a SAFEcrypto object
            sc = safecrypto_create(scheme, i, flags);
            if (NULL == sc) {
                fprintf(stderr, "WARNING! %s cannot be instantiated", sc_scheme_names[scheme]);
                continue;
            }

            // Create a key pair
            if (SC_FUNC_SUCCESS != safecrypto_keygen(sc)) {
                fprintf(stderr, "ERROR! safecrypto_keygen() failed\n");
                goto error_return;
            }

            // Encode the key pair
            safecrypto_set_key_coding(sc, coding, coding);
            pubkeylen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc, &pubkey, &pubkeylen)) {
                fprintf(stderr, "ERROR! safecrypto_public_key_encode() failed\n");
                goto error_return;
            }
            privkeylen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_private_key_encode(sc, &privkey, &privkeylen)) {
                fprintf(stderr, "ERROR! safecrypto_private_key_encode() failed\n");
                goto error_return;
            }

            // Free all resources for the given SAFEcrypto object
            if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
                return EXIT_FAILURE;
            }

            // Create a SAFEcrypto object
            sc = safecrypto_create(scheme, i, flags);

            // Load the public key
            safecrypto_set_key_coding(sc, coding, coding);
            if (SC_FUNC_SUCCESS != safecrypto_private_key_load(sc, privkey, privkeylen)) {
                fprintf(stderr, "ERROR! safecrypto_public_key_load() failed\n");
                goto error_return;
            }

            // Generate a random message
            prng_mem(prng_ctx, message, length);

            // Generate a signature for that message
            siglen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_sign(sc, message, length, &sig, &siglen)) {
                goto error_return;
            }

            // Free all resources for the given SAFEcrypto object
            if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
                return EXIT_FAILURE;
            }

            // Create a SAFEcrypto object
            sc = safecrypto_create(scheme, i, flags);

            // Load the public key
            safecrypto_set_key_coding(sc, coding, coding);
            if (SC_FUNC_SUCCESS != safecrypto_public_key_load(sc, pubkey, pubkeylen)) {
                fprintf(stderr, "ERROR! safecrypto_public_key_load() failed\n");
                goto error_return;
            }
#if USE_FIXED_BUFFERS
#else
            free(privkey);
            free(pubkey);
#endif

            // Verify the signature using the public key
            if (SC_FUNC_SUCCESS != safecrypto_verify(sc, message, length, sig, siglen)) {
                fprintf(stderr, "ERROR! Signature NOT verified\n");
                goto error_return;
            }

#if USE_FIXED_BUFFERS
#else
            free(sig);
            sig = NULL;
#endif

            // Free all resources for the given SAFEcrypto object
            if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
                return EXIT_FAILURE;
            }

            // Update the progress bar
            show_progress(disp_msg, i+1, max_set+1-min_set);
        }
    }

#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (sig) free(sig);
#endif
    prng_destroy(prng_ctx);
    return EXIT_SUCCESS;

error_return:
    if (sc) {
        UINT32 error;
        const char *file;
        SINT32 line;
        while (SC_OK != (error = safecrypto_err_get_error_line(sc, &file, &line))) {
            printf("ERROR: %08X, %s, line %d\n", error, file, line);
        }
    }
#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (sig) free(sig);
#endif
    prng_destroy(prng_ctx);
    safecrypto_destroy(sc);
    return EXIT_FAILURE;
#endif
}


