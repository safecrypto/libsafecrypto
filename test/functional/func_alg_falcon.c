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
 *   Author: Neil Smyth <n.smyth@qub.ac.uk>
 *   Date:   Mon Jan 8 08:09:10 2018 +0000
 *   Branch: master
 *   Id:     c0be7930945cf19e699498c85866db8b706e3a10
 */

#include <stdlib.h>
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/threading/threading.h"

#include <string.h>


#define MAX_KEYGEN_ITER   1
#define MAX_ITER          1024

#define USE_FIXED_BUFFERS     0
#if USE_FIXED_BUFFERS == 1
#define FIXED_BUFFER_SIZE     4096
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

SINT32 compare_messages(UINT8 *a, UINT8 *b, size_t length)
{
    size_t i;

    for (i=0; i<length; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr, "ERROR! Messages do NOT match at index %d: %08X vs %08X\n",
                (SINT32)i, a[i], b[i]);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int main(void)
{
    safecrypto_t *sc = NULL;

#ifdef DISABLE_SIGNATURES
    UINT32 flags[1] = {SC_FLAG_NONE};
    sc = safecrypto_create(SC_SCHEME_SIG_FALCON, 0, flags);
    if (NULL != sc) {
        fprintf(stderr, "ERROR! safecrypto_create() succeeded but the scheme has been disabled\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
#else
    int32_t i, j;
    uint8_t *message = malloc(8192);
    memset(message, 0, 8192);
    size_t length = 128;
#if USE_FIXED_BUFFERS
    UINT8 *fixed_buffer = malloc(FIXED_BUFFER_SIZE);
    UINT8 *sig = fixed_buffer;
#else
    UINT8 *sig = NULL;
#endif
    UINT8 *pubkey, *privkey;
    size_t siglen = 0, pubkeylen = 0, privkeylen = 0;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    char disp_msg[128];

    printf("FALCON Signature Scheme\n");

    SC_TIMER_INSTANCE(keygen_timer);
    SC_TIMER_INSTANCE(sig_timer);
    SC_TIMER_INSTANCE(ver_timer);
    SC_TIMER_CREATE(keygen_timer);
    SC_TIMER_CREATE(sig_timer);
    SC_TIMER_CREATE(ver_timer);

    for (i=0; i<3; i++) {
        //if (i == 0) continue; //removing para 0
        if (i == 1) continue; //removing ternary
        if (i == 2) continue; //removing para 2
        SC_TIMER_RESET(keygen_timer);

        printf("Parameter Set: %d\n", i);;
/*#ifdef USE_HUFFMAN_STATIC_ENTROPY
        UINT32 flags[2] = {SC_FLAG_0_ENTROPY_HUFFMAN, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_HUFFMAN_STATIC;
#else
#ifdef USE_BAC_ENTROPY
        UINT32 flags[2] = {SC_FLAG_0_ENTROPY_BAC, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_BAC;
#else*/
        UINT32 flags[3] = {SC_FLAG_NONE, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_NONE;
//#endif
          flags[0] = SC_FLAG_MORE;
          flags[1] = SC_FLAG_MORE;
          flags[2] = SC_FLAG_2_SAMPLE_SCA_DISCARD_LO;
          //SC_FLAG_2_SAMPLE_SCA_BLINDING;
          //SC_FLAG_2_SAMPLE_SCA_SHUFFLE | SC_FLAG_2_SAMPLE_SCA_DISCARD_LO;



        // Create a SAFEcrypto object
        sc = safecrypto_create(SC_SCHEME_SIG_FALCON, i, flags);

        // Create a key pair
        snprintf(disp_msg, 128, "%-20s", "KeyGen");
        SC_TIMER_START(keygen_timer);
        for (j=0; j<MAX_KEYGEN_ITER; j++) {
            if (SC_FUNC_SUCCESS != safecrypto_keygen(sc)) {
                fprintf(stderr, "ERROR! Key generation failed\n");
                goto error_return;
            }

            if ((j & 0x1F) == 0x1F) show_progress(disp_msg, j, MAX_KEYGEN_ITER);
        }
        SC_TIMER_STOP(keygen_timer);
        show_progress(disp_msg, MAX_KEYGEN_ITER, MAX_KEYGEN_ITER);

        safecrypto_set_key_coding(sc, coding, coding);
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

        snprintf(disp_msg, 128, "%-20s", "Sign/Verify");

        for (j=0; j<MAX_ITER; j++) {

            length = 128;

            // Generate a random message
            prng_mem(prng_ctx, message, length);

            // Generate a signature for that message
            SC_TIMER_START(sig_timer);
            siglen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_sign(sc, message, length, &sig, &siglen)) {
                //fprintf(stderr, "ERROR! safecrypto_sign() failed\n");
                //goto error_return;
            }
            SC_TIMER_STOP(sig_timer);

            // Verify the signature
           SC_TIMER_START(ver_timer);
            if ((j & 0x3) == 3) {
                // Ensure that the last byte (which is potentially partially used) is not corrupted
                size_t idx = j % siglen;
                if (idx == (siglen - 1)) {
                    idx--;
                }
                sig[idx] ^= 1 << (j % 8);

                // Verify the signature using the public key
                if (SC_FUNC_SUCCESS == safecrypto_verify(sc, message, length, sig, siglen)) {
                    fprintf(stderr, "ERROR! Signature verified even though it was corrupt (j=%d,siglen=%zu)\n", j, siglen);
                    for (i=0; i<siglen; i++) {
                        if ((i&0x0F) == 0) fprintf(stderr, "\n  ");
                        fprintf(stderr, "%4d ", sig[i]);
                    }
                    fprintf(stderr, "\n");
                    goto error_return;
                }
            }
            else if ((j & 0x3) == 2 && length > 0) {
                message[j%length] ^= 1 << (j % 8);

                // Verify the signature using the public key
                if (SC_FUNC_SUCCESS == safecrypto_verify(sc, message, length, sig, siglen)) {
                    fprintf(stderr, "ERROR! Signature verified even though the message was corrupt\n");
                    goto error_return;
                }
            }
            else {
                // Verify the signature using the public key
                if (SC_FUNC_SUCCESS != safecrypto_verify(sc, message, length, sig, siglen)) {
                    fprintf(stderr, "ERROR! Signature NOT verified\n");
                    goto error_return;
                }
            }
            SC_TIMER_STOP(ver_timer);

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

        // Free all resources for the given SAFEcrypto object
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
            return EXIT_FAILURE;
        }

        double elapsed = SC_TIMER_GET_ELAPSED(keygen_timer);
        printf("KeyGen time:        %f (%f per sec)\n", elapsed, (double)MAX_KEYGEN_ITER / elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(sig_timer);
        printf("Signature time:     %f (%f per sec)\n", elapsed, (double)MAX_ITER / elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(ver_timer);
        printf("Verification time:  %f (%f per sec)\n\n", elapsed, (double)MAX_ITER / elapsed);

        //length <<= 1;
    }

#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (sig) free(sig);
#endif

    SC_TIMER_DESTROY(keygen_timer);
    SC_TIMER_DESTROY(sig_timer);
    SC_TIMER_DESTROY(ver_timer);
    prng_destroy(prng_ctx);
    free(message);
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
    SC_TIMER_DESTROY(sig_timer);
    SC_TIMER_DESTROY(ver_timer);
    prng_destroy(prng_ctx);
    safecrypto_destroy(sc);
    free(message);
    return EXIT_FAILURE;
#endif
}