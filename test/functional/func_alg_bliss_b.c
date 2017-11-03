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
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/threading/threading.h"

#include <string.h>


#define MIN_PARAM_SET 1
#define MAX_PARAM_SET 4
#define MAX_ITER      4096

#define USE_FIXED_BUFFERS     1
#if USE_FIXED_BUFFERS == 1
#define FIXED_BUFFER_SIZE     1200
#else
#define FIXED_BUFFER_SIZE     0
#endif


static void show_progress(char *msg, int32_t count, int32_t max)
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

static void prng_entropy_source(size_t n, UINT8 *data)
{
    size_t i;
    for (i=0; i<n; i++) {
        data[i] = i;
    }
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
    SINT32 i, j;
    UINT8 message[8192];
    size_t length = 128;
    UINT8 md[64];
    size_t siglen = 0, pubkeylen = 0, privkeylen = 0;
#if USE_FIXED_BUFFERS
    UINT8 *fixed_buffer = malloc(FIXED_BUFFER_SIZE);
    UINT8 *sig = fixed_buffer, *pubkey = fixed_buffer, *privkey = fixed_buffer;
#else
    UINT8 *sig = NULL, *pubkey, *privkey;
#endif
    utils_crypto_hash_t *hash = NULL;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM,
        SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    if (NULL == prng_ctx) {
        fprintf(stderr, "ERROR! Could not create prng_ctx_t\n");
        goto error_return;
    }

    hash = utils_crypto_hash_create(SC_HASH_SHA2_512);

#ifdef USE_HUFFMAN_STATIC_ENTROPY
    UINT32 flags[2] = {SC_FLAG_0_ENTROPY_HUFFMAN_STATIC};
    sc_entropy_type_e coding = SC_ENTROPY_HUFFMAN_STATIC;
#else
#ifdef USE_STRONGSWAN_HUFFMAN_ENTROPY
    UINT32 flags[2] = {SC_FLAG_0_ENTROPY_STRONGSWAN};
    sc_entropy_type_e coding = SC_ENTROPY_STRONGSWAN;
#else
#ifdef USE_BAC_RLE_ENTROPY
    UINT32 flags[2] = {SC_FLAG_0_ENTROPY_BAC_RLE};
    sc_entropy_type_e coding = SC_ENTROPY_BAC_RLE;
#else
#ifdef USE_BAC_ENTROPY
    UINT32 flags[2] = {SC_FLAG_0_ENTROPY_BAC};
    sc_entropy_type_e coding = SC_ENTROPY_BAC;
#else
    UINT32 flags[2] = {SC_FLAG_NONE};
    sc_entropy_type_e coding = SC_ENTROPY_NONE;
#endif
#endif
#endif
#endif

    flags[0] |= SC_FLAG_MORE;
    flags[0] |= SC_FLAG_0_SAMPLE_CDF;
    flags[1] |= SC_FLAG_1_CSPRNG_AES_CTR_DRBG;
    flags[1] |= SC_FLAG_1_CSPRNG_USE_CALLBACK_RANDOM;

    SC_TIMER_INSTANCE(keygen_timer);
    SC_TIMER_INSTANCE(sign_timer);
    SC_TIMER_INSTANCE(verify_timer);
    SC_TIMER_CREATE(keygen_timer);
    SC_TIMER_CREATE(sign_timer);
    SC_TIMER_CREATE(verify_timer);

    char disp_msg[128];
    snprintf(disp_msg, 128, "%-20s", "Series Test");

    for (i=MIN_PARAM_SET; i<=MAX_PARAM_SET; i++) {

#ifdef USE_STRONGSWAN_HUFFMAN_ENTROPY
        if (2 == i) continue;
        if (0 == i) continue;
#endif

        SC_TIMER_RESET(keygen_timer);
        SC_TIMER_RESET(sign_timer);
        SC_TIMER_RESET(verify_timer);

        printf("Message length: %6d bytes\n", (int)length);

        // Create a SAFEcrypto object
        safecrypto_entropy_callback(prng_entropy_source);
        sc = safecrypto_create(SC_SCHEME_SIG_BLISS, i, flags);

        for (j=0; j<MAX_ITER; j++) {

            // Create a key pair
            SC_TIMER_START(keygen_timer);
            if (SC_FUNC_SUCCESS != safecrypto_keygen(sc)) {
                fprintf(stderr, "ERROR! safecrypto_keygen() failed\n");
                goto error_return;
            }
            SC_TIMER_STOP(keygen_timer);

            if (SC_FUNC_SUCCESS != safecrypto_set_key_coding(sc, SC_ENTROPY_NONE, coding)) {
                fprintf(stderr, "ERROR! safecrypto_set_key_coding() failed\n");
                goto error_return;
            }
            pubkeylen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc, &pubkey, &pubkeylen)) {
                fprintf(stderr, "ERROR! safecrypto_public_key_encode() failed\n");
                goto error_return;
            }
            privkeylen = FIXED_BUFFER_SIZE;
#if USE_FIXED_BUFFERS
#else
            free(pubkey);
#endif
            if (SC_FUNC_SUCCESS != safecrypto_private_key_encode(sc, &privkey, &privkeylen)) {
                fprintf(stderr, "ERROR! safecrypto_private_key_encode() failed\n");
                goto error_return;
            }
#if USE_FIXED_BUFFERS
#else
            free(privkey);
#endif

            // Generate a random message
            prng_mem(prng_ctx, message, length);

            // Generate a hash of the message to be signed
            hash_init(hash);
            hash_update(hash, message, length);
            hash_final(hash, md);

            // Generate a signature for that message
            SC_TIMER_START(sign_timer);
            siglen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_sign(sc, md, 64, &sig, &siglen)) {
                goto error_return;
            }
            SC_TIMER_STOP(sign_timer);

            SC_TIMER_START(verify_timer);
            // Invert a bit of the message digest to cause verification to fail
            if ((j & 0x3) == 3) {
                sig[j%64] ^= 1 << (j % 8);

                // Verify the signature using the public key
                if (SC_FUNC_SUCCESS == safecrypto_verify(sc, md, 64, sig, siglen)) {
                    fprintf(stderr, "ERROR! Signature verified even though it was corrupt (j=%d)\n", j);
                    for (i=0; i<siglen; i++) {
                        if ((i&0x0F) == 0) fprintf(stderr, "\n  ");
                        fprintf(stderr, "%4d ", sig[i]);
                    }
                    fprintf(stderr, "\n");
                    goto error_return;
                }
            }
            else if ((j & 0x3) == 2) {
                md[j%64] ^= 1 << (j % 8);

                // Verify the signature using the public key
                if (SC_FUNC_SUCCESS == safecrypto_verify(sc, md, 64, sig, siglen)) {
                    fprintf(stderr, "ERROR! Signature verified even though the message was corrupt\n");
                    goto error_return;
                }
            }
            else {
                // Verify the signature using the public key
                if (SC_FUNC_SUCCESS != safecrypto_verify(sc, md, 64, sig, siglen)) {
                    fprintf(stderr, "ERROR! Signature NOT verified\n");
                    goto error_return;
                }
            }
            SC_TIMER_STOP(verify_timer);

#if USE_FIXED_BUFFERS
#else
            free(sig);
            sig = NULL;
#endif

            if ((j & 0x1F) == 0x1F) show_progress(disp_msg, j, MAX_ITER);
        }

        show_progress(disp_msg, MAX_ITER, MAX_ITER);

        const char *stats = safecrypto_processing_stats(sc);
        printf("%s", stats);

        double elapsed = SC_TIMER_GET_ELAPSED(keygen_timer);
        printf("KeyGen time: %f (%f per sec)\n", elapsed, (double)MAX_ITER / elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(sign_timer);
        printf("Sign time:   %f (%f per sec)\n", elapsed, (double)MAX_ITER / elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(verify_timer);
        printf("Verify time: %f (%f per sec)\n\n", elapsed, (double)MAX_ITER / elapsed);

        // Free all resources for the given SAFEcrypto object
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
            return EXIT_FAILURE;
        }
    }

#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (sig) free(sig);
#endif
    SC_TIMER_DESTROY(keygen_timer);
    SC_TIMER_DESTROY(sign_timer);
    SC_TIMER_DESTROY(verify_timer);
    utils_crypto_hash_destroy(hash);
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
    SC_TIMER_DESTROY(keygen_timer);
    SC_TIMER_DESTROY(sign_timer);
    SC_TIMER_DESTROY(verify_timer);
    utils_crypto_hash_destroy(hash);
    prng_destroy(prng_ctx);
    safecrypto_destroy(sc);
    return EXIT_FAILURE;
#endif
}


