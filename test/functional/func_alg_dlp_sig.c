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
#include "utils/threading/threading.h"

#include <string.h>


#define MAX_ITER    1024

#define USE_FIXED_BUFFERS     0
#if USE_FIXED_BUFFERS == 1
#define FIXED_BUFFER_SIZE     16384
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
    sc = safecrypto_create(SC_SCHEME_SIG_DLP, 0, flags);
    if (NULL != sc) {
        fprintf(stderr, "ERROR! safecrypto_create() succeeded but the scheme has been disabled\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
#else
    int32_t i, j, k;
    uint8_t message[8192];
    size_t length;
#if USE_FIXED_BUFFERS
    UINT8 *fixed_buffer = malloc(FIXED_BUFFER_SIZE);
    UINT8 *sig = fixed_buffer;
#else
    UINT8 *sig = NULL;
#endif
    UINT8 *pubkey, *privkey;
    size_t siglen = 0, pubkeylen = 0, privkeylen = 0;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    printf("DLP Signature Scheme\n");

    SC_TIMER_INSTANCE(keygen_timer);
    SC_TIMER_INSTANCE(sig_timer);
    SC_TIMER_INSTANCE(ver_timer);
    SC_TIMER_CREATE(keygen_timer);
    SC_TIMER_CREATE(sig_timer);
    SC_TIMER_CREATE(ver_timer);

    for (i=0; i<2; i++) {
        SC_TIMER_RESET(keygen_timer);

        printf("Parameter Set: %d\n", i);

#ifdef USE_HUFFMAN_STATIC_ENTROPY
        UINT32 flags[2] = {SC_FLAG_0_ENTROPY_HUFFMAN_STATIC, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_HUFFMAN_STATIC;
#else
#ifdef USE_BAC_RLE_ENTROPY
        UINT32 flags[2] = {SC_FLAG_0_ENTROPY_BAC_RLE, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_BAC_RLE;
#else
#ifdef USE_BAC_ENTROPY
        UINT32 flags[2] = {SC_FLAG_0_ENTROPY_BAC, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_BAC;
#else
        UINT32 flags[2] = {SC_FLAG_NONE, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_NONE;
#endif
#endif
#endif
        flags[0] |= SC_FLAG_MORE;
        flags[1] |= SC_FLAG_1_CSPRNG_AES_CTR_DRBG;

        // Create a SAFEcrypto object
        sc = safecrypto_create(SC_SCHEME_SIG_DLP, i, flags);

        // Create a key pair
        SC_TIMER_START(keygen_timer);
        if (SC_FUNC_SUCCESS != safecrypto_keygen(sc)) {
            fprintf(stderr, "ERROR! Key generation failed\n");
            goto error_return;
        }
        SC_TIMER_STOP(keygen_timer);

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

        char disp_msg[128];

        double elapsed_enc[3], elapsed_dec[3];
        length = 128;
        for (k=0; k<2; k++) {
            snprintf(disp_msg, 128, "%-16s %-4zu", "Msg Length", length);

            for (j=0; j<MAX_ITER; j++) {

                // Generate a random message
                prng_mem(prng_ctx, message, length);

                // Generate a signature for that message
                SC_TIMER_START(sig_timer);
                siglen = FIXED_BUFFER_SIZE;
                if (SC_FUNC_SUCCESS != safecrypto_sign(sc, message, length, &sig, &siglen)) {
                    fprintf(stderr, "ERROR! safecrypto_sign() failed\n");
                    goto error_return;
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
                    message[j%64] ^= 1 << (j % 8);

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

            elapsed_enc[k] = SC_TIMER_GET_ELAPSED(sig_timer);
            elapsed_dec[k] = SC_TIMER_GET_ELAPSED(ver_timer);
            SC_TIMER_RESET(sig_timer);
            SC_TIMER_RESET(ver_timer);

            length <<= 3;
        }

        const char *stats = safecrypto_processing_stats(sc);
        printf("%s", stats);

        // Free all resources for the given SAFEcrypto object
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
            return EXIT_FAILURE;
        }

        double elapsed = SC_TIMER_GET_ELAPSED(keygen_timer);
        printf("KeyGen time:        %3.3f (%3.3f per sec)\n", elapsed, 1.0 / elapsed);
        printf("Signature time (128):      %3.3f (%3.3f per sec, %5.3f bytes per sec)\n", elapsed_enc[0], (double)MAX_ITER / elapsed_enc[0], ((double)MAX_ITER * 128) / elapsed_enc[0]);
        printf("Signature time (1024):    %3.3f (%3.3f per sec, %5.3f bytes per sec)\n", elapsed_enc[1], (double)MAX_ITER / elapsed_enc[1], ((double)MAX_ITER * 1024) / elapsed_enc[1]);
        printf("Verification time (128):   %3.3f (%3.3f per sec, %5.3f bytes per sec)\n", elapsed_dec[0], (double)MAX_ITER / elapsed_dec[0], ((double)MAX_ITER * 128) / elapsed_dec[0]);
        printf("Verification time (1024): %3.3f (%3.3f per sec, %5.3f bytes per sec)\n\n", elapsed_dec[1], (double)MAX_ITER / elapsed_dec[1], ((double)MAX_ITER * 1024) / elapsed_dec[1]);
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
    return EXIT_FAILURE;
#endif
}


